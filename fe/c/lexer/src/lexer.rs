//! The C preprocessing-token lexer.

use crate::alloc_prelude::*;
use crate::token::{PpToken, PpTokenKind, Punctuator};
use stratum_arena::Interner;
use stratum_diagnostics::{Diagnostic, FileId, Label, Span};

type TokenCtor = fn(stratum_arena::Symbol) -> PpTokenKind;

/// The result of lexing a source file into preprocessing tokens.
#[derive(Debug, Default)]
pub struct LexResult {
    /// The preprocessing tokens, in source order. Newlines are retained as
    /// [`PpTokenKind::Newline`].
    pub tokens: Vec<PpToken>,
    /// Diagnostics produced while lexing (e.g. unterminated literals).
    pub diagnostics: Vec<Diagnostic>,
}

impl LexResult {
    /// Returns `true` if any error-severity diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == stratum_diagnostics::Severity::Error)
    }
}

/// Lexes `source` (the text of `file`) into preprocessing tokens.
///
/// Line splicing (a backslash immediately followed by a newline) and comments are handled
/// here, in [phases 1 and 2][phases] of translation; both are treated as if they were
/// whitespace. Spans always refer to offsets in the original, unspliced source.
///
/// Identifiers, numbers, and literal spellings are interned into `interner`.
///
/// # Errors
///
/// Returns an error if string interning fails.
///
/// # Examples
///
/// ```
/// use stratum_arena::Interner;
/// use stratum_c_lexer::{lex, PpTokenKind};
/// use stratum_diagnostics::SourceMap;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut map = SourceMap::new();
/// let file = map.add_root("t.c", "int x;\n")?;
/// let mut interner = Interner::new();
/// let result = lex("int x;\n", file, &mut interner)?;
/// assert!(!result.has_errors());
/// assert!(matches!(result.tokens[0].kind, PpTokenKind::Identifier(_)));
/// # Ok(())
/// # }
/// ```
///
/// [phases]: https://en.cppreference.com/w/c/language/translation_phases
pub fn lex(source: &str, file: FileId, interner: &mut Interner) -> crate::Result<LexResult> {
    Lexer::new(source, file, interner).run()
}

struct Lexer<'a> {
    cleaned: Vec<u8>,
    map: Vec<u32>,
    file: FileId,
    interner: &'a mut Interner,
    pos: usize,
    leading_whitespace: bool,
    at_bol: bool,
    tokens: Vec<PpToken>,
    diagnostics: Vec<Diagnostic>,
}

/// Splices out backslash-newline pairs, returning the cleaned bytes and a map from each
/// cleaned byte index to its original byte offset. The map has one trailing sentinel entry
/// equal to the original length so exclusive end offsets resolve correctly.
fn splice_lines(source: &str) -> (Vec<u8>, Vec<u32>) {
    let bytes = source.as_bytes();
    let mut cleaned = Vec::with_capacity(bytes.len());
    let mut map = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'\\' {
            if bytes.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
        }
        cleaned.push(byte);
        map.push(u32::try_from(i).unwrap_or(u32::MAX));
        i += 1;
    }
    map.push(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    (cleaned, map)
}

fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_ident_continue(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

impl<'a> Lexer<'a> {
    fn new(source: &str, file: FileId, interner: &'a mut Interner) -> Self {
        let (cleaned, map) = splice_lines(source);
        Self {
            cleaned,
            map,
            file,
            interner,
            pos: 0,
            leading_whitespace: false,
            at_bol: true,
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn byte(&self, offset: usize) -> Option<u8> {
        self.cleaned.get(self.pos + offset).copied()
    }

    fn span(&self, start: usize, end: usize) -> Span {
        let start_off = self.map.get(start).copied().unwrap_or(0);
        let end_off = self.map.get(end).copied().unwrap_or(start_off);
        Span::new(self.file, start_off, end_off)
    }

    fn push(&mut self, kind: PpTokenKind, start: usize) {
        let span = self.span(start, self.pos);
        self.tokens.push(PpToken {
            kind,
            span,
            leading_whitespace: self.leading_whitespace,
            at_bol: self.at_bol,
        });
        self.leading_whitespace = false;
        self.at_bol = false;
    }

    fn run(mut self) -> crate::Result<LexResult> {
        while let Some(b) = self.byte(0) {
            match b {
                b' ' | b'\t' | b'\r' | 0x0b | 0x0c => {
                    self.pos += 1;
                    self.leading_whitespace = true;
                }
                b'\n' => self.lex_newline(),
                b'/' if self.byte(1) == Some(b'*') => self.skip_block_comment(),
                b'/' if self.byte(1) == Some(b'/') => self.skip_line_comment(),
                b'"' => self.lex_string_or_char(b'"', PpTokenKind::StringLit)?,
                b'\'' => self.lex_string_or_char(b'\'', PpTokenKind::CharConst)?,
                _ if is_ident_start(b) => self.lex_identifier_or_prefixed()?,
                b'.' if self.byte(1).is_some_and(|n| n.is_ascii_digit()) => self.lex_number()?,
                _ if b.is_ascii_digit() => self.lex_number()?,
                _ => self.lex_punct_or_other(),
            }
        }
        Ok(LexResult {
            tokens: self.tokens,
            diagnostics: self.diagnostics,
        })
    }

    fn lex_newline(&mut self) {
        let start = self.pos;
        self.pos += 1;
        let span = self.span(start, self.pos);
        self.tokens.push(PpToken {
            kind: PpTokenKind::Newline,
            span,
            leading_whitespace: self.leading_whitespace,
            at_bol: self.at_bol,
        });
        self.leading_whitespace = false;
        self.at_bol = true;
    }

    fn skip_block_comment(&mut self) {
        let start = self.pos;
        self.pos += 2;
        while self.pos < self.cleaned.len() {
            if self.byte(0) == Some(b'*') && self.byte(1) == Some(b'/') {
                self.pos += 2;
                self.leading_whitespace = true;
                return;
            }
            self.pos += 1;
        }
        let span = self.span(start, self.pos);
        self.diagnostics.push(
            Diagnostic::error("unterminated block comment")
                .with_label(Label::new(span, "comment starts here")),
        );
        self.leading_whitespace = true;
    }

    fn skip_line_comment(&mut self) {
        self.pos += 2;
        while self.byte(0).is_some_and(|byte| byte != b'\n') {
            self.pos += 1;
        }
        self.leading_whitespace = true;
    }

    fn lex_identifier_or_prefixed(&mut self) -> crate::Result<()> {
        // Recognize encoding-prefixed literals such as `L"..."` and `u8'...'`.
        if let Some((len, quote, kind)) = self.literal_prefix() {
            return self.lex_string_or_char_with_offset(len, quote, kind);
        }
        let start = self.pos;
        self.pos += 1;
        while self.byte(0).is_some_and(is_ident_continue) {
            self.pos += 1;
        }
        let symbol = self.intern(start, self.pos)?;
        self.push(PpTokenKind::Identifier(symbol), start);
        Ok(())
    }

    /// If the current position begins an encoding prefix directly followed by a quote,
    /// returns the prefix length, quote byte, and token constructor.
    fn literal_prefix(&self) -> Option<(usize, u8, TokenCtor)> {
        let candidates: [&[u8]; 4] = [b"u8", b"L", b"u", b"U"];
        for prefix in candidates {
            let after = self.pos + prefix.len();
            let matches_prefix = self
                .cleaned
                .get(self.pos..after)
                .is_some_and(|slice| slice == prefix);
            if !matches_prefix {
                continue;
            }
            let Some(&quote) = self.cleaned.get(after) else {
                continue;
            };
            let kind = match quote {
                b'"' => PpTokenKind::StringLit,
                b'\'' => PpTokenKind::CharConst,
                _ => continue,
            };
            return Some((prefix.len(), quote, kind));
        }
        None
    }

    fn lex_string_or_char(
        &mut self,
        quote: u8,
        kind: fn(stratum_arena::Symbol) -> PpTokenKind,
    ) -> crate::Result<()> {
        self.lex_string_or_char_with_offset(0, quote, kind)
    }

    fn lex_string_or_char_with_offset(
        &mut self,
        prefix_len: usize,
        quote: u8,
        kind: fn(stratum_arena::Symbol) -> PpTokenKind,
    ) -> crate::Result<()> {
        let start = self.pos;
        self.pos += prefix_len + 1;
        let mut terminated = false;
        while let Some(c) = self.byte(0) {
            if c == b'\n' {
                break;
            }
            if c == b'\\' {
                self.pos += 2;
                continue;
            }
            if c == quote {
                self.pos += 1;
                terminated = true;
                break;
            }
            self.pos += 1;
        }
        if !terminated {
            let span = self.span(start, self.pos);
            let what = if quote == b'"' {
                "string literal"
            } else {
                "character constant"
            };
            self.diagnostics.push(
                Diagnostic::error(format!("unterminated {what}"))
                    .with_label(Label::new(span, "literal starts here")),
            );
        }
        let symbol = self.intern(start, self.pos)?;
        self.push(kind(symbol), start);
        Ok(())
    }

    fn lex_number(&mut self) -> crate::Result<()> {
        let start = self.pos;
        self.pos += 1;
        while let Some(c) = self.byte(0) {
            if matches!(c, b'e' | b'E' | b'p' | b'P') && matches!(self.byte(1), Some(b'+' | b'-')) {
                self.pos += 2;
            } else if is_ident_continue(c) || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let symbol = self.intern(start, self.pos)?;
        self.push(PpTokenKind::Number(symbol), start);
        Ok(())
    }

    fn lex_punct_or_other(&mut self) {
        if let Some((punct, len)) = self.match_punctuator() {
            let start = self.pos;
            self.pos += len;
            self.push(PpTokenKind::Punct(punct), start);
            return;
        }
        let start = self.pos;
        let ch = self.decode_char();
        self.push(PpTokenKind::Other(ch), start);
    }

    fn decode_char(&mut self) -> char {
        // `cleaned` is always valid UTF-8 (only ASCII bytes are removed during splicing),
        // so the first `char` is well defined; the fallback only guards an empty slice.
        let rest = self.cleaned.get(self.pos..).unwrap_or_default();
        let ch = core::str::from_utf8(rest)
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}');
        self.pos += ch.len_utf8().max(1);
        ch
    }

    fn intern(&mut self, start: usize, end: usize) -> crate::Result<stratum_arena::Symbol> {
        let text = self
            .cleaned
            .get(start..end)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("");
        self.interner.intern(text).map_err(Into::into)
    }

    fn match_punctuator(&self) -> Option<(Punctuator, usize)> {
        let b0 = self.byte(0)?;
        let b1 = self.byte(1);
        let b2 = self.byte(2);
        let b3 = self.byte(3);
        // Four-character punctuator: the `%:%:` digraph for `##`.
        if b0 == b'%' && b1 == Some(b':') && b2 == Some(b'%') && b3 == Some(b':') {
            return Some((Punctuator::HashHash, 4));
        }
        if let Some(found) = match_three(b0, b1, b2) {
            return Some(found);
        }
        if let Some(found) = match_two(b0, b1) {
            return Some(found);
        }
        match_one(b0).map(|p| (p, 1))
    }
}

fn match_three(b0: u8, b1: Option<u8>, b2: Option<u8>) -> Option<(Punctuator, usize)> {
    let punct = match (b0, b1, b2) {
        (b'.', Some(b'.'), Some(b'.')) => Punctuator::Ellipsis,
        (b'<', Some(b'<'), Some(b'=')) => Punctuator::ShlAssign,
        (b'>', Some(b'>'), Some(b'=')) => Punctuator::ShrAssign,
        _ => return None,
    };
    Some((punct, 3))
}

fn match_two(b0: u8, b1: Option<u8>) -> Option<(Punctuator, usize)> {
    let b1 = b1?;
    let punct = match (b0, b1) {
        (b'-', b'>') => Punctuator::Arrow,
        (b'+', b'+') => Punctuator::PlusPlus,
        (b'-', b'-') => Punctuator::MinusMinus,
        (b'<', b'<') => Punctuator::Shl,
        (b'>', b'>') => Punctuator::Shr,
        (b'<', b'=') => Punctuator::Le,
        (b'>', b'=') => Punctuator::Ge,
        (b'=', b'=') => Punctuator::EqEq,
        (b'!', b'=') => Punctuator::Ne,
        (b'&', b'&') => Punctuator::AmpAmp,
        (b'|', b'|') => Punctuator::PipePipe,
        (b'*', b'=') => Punctuator::StarAssign,
        (b'/', b'=') => Punctuator::SlashAssign,
        (b'%', b'=') => Punctuator::PercentAssign,
        (b'+', b'=') => Punctuator::PlusAssign,
        (b'-', b'=') => Punctuator::MinusAssign,
        (b'&', b'=') => Punctuator::AmpAssign,
        (b'^', b'=') => Punctuator::CaretAssign,
        (b'|', b'=') => Punctuator::PipeAssign,
        (b'#', b'#') => Punctuator::HashHash,
        (b'<', b':') => Punctuator::LBracket,
        (b':', b'>') => Punctuator::RBracket,
        (b'<', b'%') => Punctuator::LBrace,
        (b'%', b'>') => Punctuator::RBrace,
        (b'%', b':') => Punctuator::Hash,
        _ => return None,
    };
    Some((punct, 2))
}

fn match_one(b0: u8) -> Option<Punctuator> {
    let punct = match b0 {
        b'[' => Punctuator::LBracket,
        b']' => Punctuator::RBracket,
        b'(' => Punctuator::LParen,
        b')' => Punctuator::RParen,
        b'{' => Punctuator::LBrace,
        b'}' => Punctuator::RBrace,
        b'.' => Punctuator::Dot,
        b'&' => Punctuator::Amp,
        b'*' => Punctuator::Star,
        b'+' => Punctuator::Plus,
        b'-' => Punctuator::Minus,
        b'~' => Punctuator::Tilde,
        b'!' => Punctuator::Bang,
        b'/' => Punctuator::Slash,
        b'%' => Punctuator::Percent,
        b'<' => Punctuator::Lt,
        b'>' => Punctuator::Gt,
        b'^' => Punctuator::Caret,
        b'|' => Punctuator::Pipe,
        b'?' => Punctuator::Question,
        b':' => Punctuator::Colon,
        b';' => Punctuator::Semicolon,
        b'=' => Punctuator::Assign,
        b',' => Punctuator::Comma,
        b'#' => Punctuator::Hash,
        _ => return None,
    };
    Some(punct)
}
