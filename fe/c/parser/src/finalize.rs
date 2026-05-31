//! Token finalisation: converting preprocessing tokens into parser tokens.
//!
//! This is C translation phase 7's preamble: keywords are distinguished from identifiers,
//! numeric spellings are parsed into values, character constants are decoded, and adjacent
//! string literals are concatenated. Newline markers are dropped and a trailing
//! [`TokenKind::Eof`] is appended.

use crate::alloc_prelude::*;
use stratum_arena::Interner;
use stratum_c_lexer::{Dialect, Keyword, PpToken, PpTokenKind, Token, TokenKind};
use stratum_diagnostics::{Diagnostic, FileId, Label, Span};

/// The outcome of finalising a preprocessing-token stream.
#[derive(Debug, Default)]
pub struct FinalizeResult {
    /// The finalized tokens, terminated by [`TokenKind::Eof`].
    pub tokens: Vec<Token>,
    /// Diagnostics produced during finalisation.
    pub diagnostics: Vec<Diagnostic>,
}

/// finalizes `tokens`, interning any decoded string contents into `interner`.
#[must_use]
pub fn finalize(tokens: &[PpToken], interner: &mut Interner) -> FinalizeResult {
    finalize_with_dialect(tokens, interner, Dialect::DEFAULT)
}

/// finalizes `tokens` using the keyword set from `dialect`.
#[must_use]
pub fn finalize_with_dialect(
    tokens: &[PpToken],
    interner: &mut Interner,
    dialect: Dialect,
) -> FinalizeResult {
    let mut out = Vec::new();
    let mut diagnostics = Vec::new();
    let mut i = 0;
    while let Some(&token) = tokens.get(i) {
        match token.kind {
            PpTokenKind::Newline => {}
            PpTokenKind::Identifier(sym) => {
                out.push(finalize_identifier(sym, token, interner, dialect));
            }
            PpTokenKind::Number(sym) => {
                out.push(finalize_number(sym, token, interner, &mut diagnostics));
            }
            PpTokenKind::CharConst(sym) => {
                out.push(finalize_char(sym, token, interner, &mut diagnostics));
            }
            PpTokenKind::StringLit(_) => {
                let (tok, consumed) =
                    finalize_strings(tokens.get(i..).unwrap_or_default(), interner);
                out.push(tok);
                i += consumed;
                continue;
            }
            PpTokenKind::Punct(p) => out.push(Token {
                kind: TokenKind::Punct(p),
                span: token.span,
            }),
            PpTokenKind::Other(_) => diagnostics.push(
                Diagnostic::error("stray token in program")
                    .with_label(Label::new(token.span, "unexpected character")),
            ),
        }
        i += 1;
    }
    out.push(Token {
        kind: TokenKind::Eof,
        span: eof_span(tokens),
    });
    FinalizeResult {
        tokens: out,
        diagnostics,
    }
}

fn eof_span(tokens: &[PpToken]) -> Span {
    tokens
        .last()
        .map_or_else(|| Span::point(FileId::from_raw(0), 0), |t| t.span)
}

fn finalize_identifier(
    sym: stratum_arena::Symbol,
    token: PpToken,
    interner: &Interner,
    dialect: Dialect,
) -> Token {
    let kind = Keyword::from_identifier_in(interner.resolve(sym).unwrap_or(""), dialect)
        .map_or(TokenKind::Identifier(sym), TokenKind::Keyword);
    Token {
        kind,
        span: token.span,
    }
}

fn finalize_number(
    sym: stratum_arena::Symbol,
    token: PpToken,
    interner: &mut Interner,
    diagnostics: &mut Vec<Diagnostic>,
) -> Token {
    let text = interner.resolve(sym).unwrap_or("").to_string();
    let kind = if is_float_spelling(&text) {
        let float_sym = interner.intern(&text).unwrap_or_default();
        TokenKind::Float(float_sym)
    } else if let Some((value, unsigned)) = parse_integer(&text) {
        TokenKind::Integer { value, unsigned }
    } else {
        diagnostics.push(
            Diagnostic::error(format!("invalid integer constant `{text}`"))
                .with_label(Label::new(token.span, "not an integer")),
        );
        TokenKind::Integer {
            value: 0,
            unsigned: false,
        }
    };
    Token {
        kind,
        span: token.span,
    }
}

/// Returns `true` if a preprocessing number spells a floating-point constant.
fn is_float_spelling(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        // Hex floats require a binary exponent `p`.
        return hex.contains('p') || hex.contains('.');
    }
    lower.contains('.') || lower.contains('e')
}

/// Parses an integer constant, returning its value and whether it is unsigned.
fn parse_integer(text: &str) -> Option<(i128, bool)> {
    let trimmed = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let unsigned = text.contains('u') || text.contains('U');
    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        i128::from_str_radix(hex, 16).ok()?
    } else if trimmed.len() > 1 && trimmed.starts_with('0') {
        i128::from_str_radix(trimmed.strip_prefix('0')?, 8).ok()?
    } else {
        trimmed.parse::<i128>().ok()?
    };
    Some((value, unsigned))
}

fn finalize_char(
    sym: stratum_arena::Symbol,
    token: PpToken,
    interner: &Interner,
    diagnostics: &mut Vec<Diagnostic>,
) -> Token {
    let text = interner.resolve(sym).unwrap_or("");
    let value = decode_char(text).unwrap_or_else(|| {
        diagnostics.push(
            Diagnostic::error("invalid character constant")
                .with_label(Label::new(token.span, "here")),
        );
        0
    });
    Token {
        kind: TokenKind::Char(value),
        span: token.span,
    }
}

/// Decodes a character constant such as `'A'` or `L'\n'` to its value.
fn decode_char(text: &str) -> Option<u32> {
    let inner = text.trim_start_matches(['L', 'u', 'U']);
    let inner = inner.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = inner.chars();
    let first = chars.next()?;
    if first == '\\' {
        decode_escape(&mut chars)
    } else {
        Some(first as u32)
    }
}

fn decode_escape(chars: &mut core::str::Chars<'_>) -> Option<u32> {
    let escape = chars.next()?;
    let value = match escape {
        'n' => 10,
        't' => 9,
        'r' => 13,
        '0' => 0,
        '\\' => u32::from(b'\\'),
        '\'' => u32::from(b'\''),
        '"' => u32::from(b'"'),
        'a' => 7,
        'b' => 8,
        'f' => 12,
        'v' => 11,
        'x' => {
            let hex: String = chars.by_ref().collect();
            u32::from_str_radix(&hex, 16).ok()?
        }
        other => other as u32,
    };
    Some(value)
}

/// finalizes a run of adjacent string literals, concatenating their decoded contents.
fn finalize_strings(tokens: &[PpToken], interner: &mut Interner) -> (Token, usize) {
    let mut contents = String::new();
    let mut span = tokens
        .first()
        .map_or_else(|| Span::point(FileId::from_raw(0), 0), |token| token.span);
    let mut consumed = 0;
    for token in tokens {
        let PpTokenKind::StringLit(sym) = token.kind else {
            break;
        };
        let raw = interner.resolve(sym).unwrap_or("").to_string();
        contents.push_str(&decode_string(&raw));
        span = span.to(token.span);
        consumed += 1;
    }
    let sym = interner.intern(&contents).unwrap_or_default();
    (
        Token {
            kind: TokenKind::String(sym),
            span,
        },
        consumed,
    )
}

/// Decodes a string literal's contents, stripping the prefix/quotes and resolving escapes.
fn decode_string(raw: &str) -> String {
    let body = raw.trim_start_matches(['L', 'u', 'U', '8']);
    let body = body
        .strip_prefix('"')
        .and_then(|b| b.strip_suffix('"'))
        .unwrap_or(body);
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(value) = decode_escape(&mut chars)
                && let Some(decoded) = char::from_u32(value)
            {
                out.push(decoded);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        decode_char, decode_string, finalize, finalize_strings, finalize_with_dialect,
        parse_integer,
    };
    use crate::alloc_prelude::*;
    use stratum_arena::Interner;
    use stratum_c_lexer::{Dialect, PpToken, PpTokenKind, TokenKind, lex};
    use stratum_diagnostics::{FileId, Span};

    fn finalize_src(src: &str) -> (Vec<TokenKind>, Interner) {
        let mut interner = Interner::new();
        let lexed = lex(src, FileId::from_raw(0), &mut interner).unwrap();
        let result = finalize(&lexed.tokens, &mut interner);
        assert!(result.diagnostics.is_empty(), "unexpected diagnostics");
        (
            result.tokens.into_iter().map(|t| t.kind).collect(),
            interner,
        )
    }

    fn kind(kinds: &[TokenKind], index: usize) -> Option<TokenKind> {
        kinds.get(index).copied()
    }

    fn finalize_with_diagnostics(src: &str) -> super::FinalizeResult {
        let mut interner = Interner::new();
        let lexed = lex(src, FileId::from_raw(0), &mut interner).unwrap();
        finalize(&lexed.tokens, &mut interner)
    }

    #[test]
    fn keywords_are_classified() {
        let (kinds, _) = finalize_src("int while");
        assert!(matches!(kind(&kinds, 0), Some(TokenKind::Keyword(_))));
        assert!(matches!(kind(&kinds, 1), Some(TokenKind::Keyword(_))));
    }

    #[test]
    fn keyword_classification_respects_dialect() {
        let mut interner = Interner::new();
        let lexed = lex("inline _Generic true", FileId::from_raw(0), &mut interner).unwrap();
        let c89 = finalize_with_dialect(&lexed.tokens, &mut interner, Dialect::C89);
        assert!(matches!(
            kind(&c89.tokens.iter().map(|t| t.kind).collect::<Vec<_>>(), 0),
            Some(TokenKind::Identifier(_))
        ));

        let c23 = finalize_with_dialect(&lexed.tokens, &mut interner, Dialect::C23);
        assert!(matches!(
            c23.tokens.first().map(|t| t.kind),
            Some(TokenKind::Keyword(_))
        ));
        assert!(matches!(
            c23.tokens.get(1).map(|t| t.kind),
            Some(TokenKind::Keyword(_))
        ));
        assert!(matches!(
            c23.tokens.get(2).map(|t| t.kind),
            Some(TokenKind::Keyword(_))
        ));
    }

    #[test]
    fn integers_are_parsed() {
        let (kinds, _) = finalize_src("42 0x10 075 7u");
        assert_eq!(
            kind(&kinds, 0),
            Some(TokenKind::Integer {
                value: 42,
                unsigned: false
            })
        );
        assert_eq!(
            kind(&kinds, 1),
            Some(TokenKind::Integer {
                value: 16,
                unsigned: false
            })
        );
        assert_eq!(
            kind(&kinds, 2),
            Some(TokenKind::Integer {
                value: 61,
                unsigned: false
            })
        );
        assert_eq!(
            kind(&kinds, 3),
            Some(TokenKind::Integer {
                value: 7,
                unsigned: true
            })
        );
    }

    #[test]
    fn floats_are_detected() {
        let (kinds, _) = finalize_src("3.14 1e9");
        assert!(matches!(kind(&kinds, 0), Some(TokenKind::Float(_))));
        assert!(matches!(kind(&kinds, 1), Some(TokenKind::Float(_))));
    }

    #[test]
    fn char_constants_decode() {
        let (kinds, _) = finalize_src("'A' '\\n'");
        assert_eq!(kind(&kinds, 0), Some(TokenKind::Char(65)));
        assert_eq!(kind(&kinds, 1), Some(TokenKind::Char(10)));
    }

    #[test]
    fn adjacent_strings_concatenate() {
        let (kinds, interner) = finalize_src("\"ab\" \"cd\"");
        assert!(
            matches!(kind(&kinds, 0), Some(TokenKind::String(sym)) if interner.resolve(sym).unwrap_or("") == "abcd")
        );
        assert_eq!(kind(&kinds, 1), Some(TokenKind::Eof));
    }

    #[test]
    fn invalid_tokens_and_literals_report_diagnostics() {
        let result = finalize_with_diagnostics("@ 09 '\\x'");
        assert_eq!(result.diagnostics.len(), 3);
        assert!(matches!(
            result.tokens.first().map(|token| token.kind),
            Some(TokenKind::Integer {
                value: 0,
                unsigned: false
            })
        ));
    }

    #[test]
    fn integer_and_character_helpers_cover_edge_cases() {
        assert_eq!(parse_integer("0XfU"), Some((15, true)));
        assert_eq!(parse_integer("077"), Some((63, false)));
        assert_eq!(parse_integer("09"), None);
        assert_eq!(decode_char("bad"), None);
        assert_eq!(decode_char("''"), None);
        assert_eq!(decode_char("'\\'"), None);
        assert_eq!(decode_char("'\\t'"), Some(9));
        assert_eq!(decode_char("'\\r'"), Some(13));
        assert_eq!(decode_char("'\\0'"), Some(0));
        assert_eq!(decode_char("'\\\\'"), Some(u32::from(b'\\')));
        assert_eq!(decode_char("'\\''"), Some(u32::from(b'\'')));
        assert_eq!(decode_char("'\\\"'"), Some(u32::from(b'"')));
        assert_eq!(decode_char("'\\a'"), Some(7));
        assert_eq!(decode_char("'\\b'"), Some(8));
        assert_eq!(decode_char("'\\f'"), Some(12));
        assert_eq!(decode_char("'\\v'"), Some(11));
        assert_eq!(decode_char("'\\x41'"), Some(65));
        assert_eq!(decode_char("'\\z'"), Some(u32::from('z')));
    }

    #[test]
    fn string_helpers_decode_escapes_and_empty_runs() {
        assert_eq!(decode_string("plain"), "plain");
        assert_eq!(decode_string("\"a\\n\\x21\""), "a\n!");

        let mut interner = Interner::new();
        let (token, consumed) = finalize_strings(&[], &mut interner);
        assert_eq!(consumed, 0);
        assert!(matches!(token.kind, TokenKind::String(_)));

        let sym = interner.intern("\"x\"").unwrap();
        let non_string = PpToken {
            kind: PpTokenKind::Other('@'),
            span: Span::point(FileId::from_raw(0), 0),
            leading_whitespace: false,
            at_bol: false,
        };
        let string = PpToken {
            kind: PpTokenKind::StringLit(sym),
            span: Span::point(FileId::from_raw(0), 1),
            leading_whitespace: false,
            at_bol: false,
        };
        let (_token, consumed) = finalize_strings(&[string, non_string], &mut interner);
        assert_eq!(consumed, 1);
    }
}
