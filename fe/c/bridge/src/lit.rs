//! Parsing of C literal spellings into HIR literal values.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_arena::Symbol as CSymbol;
use stratum_c_ast::{CNode, CNodeId};
use stratum_diagnostics::{Diagnostic, Label, Span};

impl CLowering<'_> {
    /// Parses a C integer-constant spelling (e.g. `0x1Fu`, `010`, `42L`) into an `i128`.
    ///
    /// On failure a diagnostic is emitted and `0` is returned.
    pub(crate) fn parse_int_literal(
        &mut self,
        sym: CSymbol,
        span: Span,
    ) -> crate::error::Result<i128> {
        let raw = self.ast.resolve(sym)?;
        if let Some(value) = parse_c_integer(raw) {
            return Ok(value);
        }
        self.diagnostics.push(
            Diagnostic::error(format!("invalid integer constant `{raw}`"))
                .with_label(Label::new(span, "here")),
        );
        Ok(0)
    }

    /// Parses a C character-constant spelling (e.g. `'A'`, `'\n'`, `'\x41'`) into a code point.
    ///
    /// On failure a diagnostic is emitted and `0` is returned.
    pub(crate) fn parse_char_literal(
        &mut self,
        sym: CSymbol,
        span: Span,
    ) -> crate::error::Result<u32> {
        let raw = self.ast.resolve(sym)?;
        if let Some(value) = parse_c_char(raw) {
            return Ok(value);
        }
        self.diagnostics.push(
            Diagnostic::error(format!("invalid character constant `{raw}`"))
                .with_label(Label::new(span, "here")),
        );
        Ok(0)
    }

    /// Best-effort evaluation of an array-length expression (integer literals only, for now).
    pub(crate) fn const_array_len(&self, id: CNodeId) -> crate::error::Result<Option<u64>> {
        match self.ast.node(id) {
            CNode::IntLiteral(sym) => {
                Ok(parse_c_integer(self.ast.resolve(*sym)?).and_then(|v| u64::try_from(v).ok()))
            }
            _ => Ok(None),
        }
    }
}

/// Parses a C integer constant, ignoring any `u`/`l` suffixes.
fn parse_c_integer(raw: &str) -> Option<i128> {
    let digits = raw.trim_end_matches(['u', 'U', 'l', 'L']);
    if digits.is_empty() {
        return None;
    }
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        return i128::from_str_radix(hex, 16).ok();
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return i128::from_str_radix(&digits[1..], 8).ok();
    }
    digits.parse::<i128>().ok()
}

/// Parses a C character constant including its surrounding quotes.
fn parse_c_char(raw: &str) -> Option<u32> {
    if let Ok(value) = raw.parse::<u32>() {
        return Some(value);
    }
    let inner = raw.strip_prefix('\'')?.strip_suffix('\'')?;
    let mut chars = inner.chars();
    let first = chars.next()?;
    if first != '\\' {
        return Some(first as u32);
    }
    let escape = chars.next()?;
    let value = match escape {
        'n' => u32::from(b'\n'),
        't' => u32::from(b'\t'),
        'r' => u32::from(b'\r'),
        '0' => 0,
        '\\' => u32::from(b'\\'),
        '\'' => u32::from(b'\''),
        '"' => u32::from(b'"'),
        'a' => 0x07,
        'b' => 0x08,
        'f' => 0x0C,
        'v' => 0x0B,
        'x' => return u32::from_str_radix(chars.as_str(), 16).ok(),
        _ => return None,
    };
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::{CLowering, parse_c_char, parse_c_integer};
    use stratum_c_ast::{CAst, CNode};
    use stratum_diagnostics::{FileId, Span};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn integer_parser_covers_bases_suffixes_and_invalid_digits() {
        assert_eq!(parse_c_integer(""), None);
        assert_eq!(parse_c_integer("0x10ul"), Some(16));
        assert_eq!(parse_c_integer("010"), Some(8));
        assert_eq!(parse_c_integer("42"), Some(42));
        assert_eq!(parse_c_integer("09"), None);
        assert_eq!(parse_c_integer("bad"), None);
    }

    #[test]
    fn character_parser_covers_numeric_plain_and_escape_spellings() {
        assert_eq!(parse_c_char("65"), Some(65));
        assert_eq!(parse_c_char("'A'"), Some(65));
        assert_eq!(parse_c_char("'\\n'"), Some(u32::from(b'\n')));
        assert_eq!(parse_c_char("'\\t'"), Some(u32::from(b'\t')));
        assert_eq!(parse_c_char("'\\r'"), Some(u32::from(b'\r')));
        assert_eq!(parse_c_char("'\\0'"), Some(0));
        assert_eq!(parse_c_char("'\\\\'"), Some(u32::from(b'\\')));
        assert_eq!(parse_c_char("'\\''"), Some(u32::from(b'\'')));
        assert_eq!(parse_c_char("'\\\"'"), Some(u32::from(b'"')));
        assert_eq!(parse_c_char("'\\a'"), Some(0x07));
        assert_eq!(parse_c_char("'\\b'"), Some(0x08));
        assert_eq!(parse_c_char("'\\f'"), Some(0x0c));
        assert_eq!(parse_c_char("'\\v'"), Some(0x0b));
        assert_eq!(parse_c_char("'\\x41'"), Some(65));
        assert_eq!(parse_c_char("'\\z'"), None);
        assert_eq!(parse_c_char("''"), None);
        assert_eq!(parse_c_char("'"), None);
    }

    #[test]
    fn invalid_literals_record_diagnostics_and_default_values() {
        let mut ast = CAst::new();
        let int = ast.intern("09").unwrap();
        let ch = ast.intern("'\\z'").unwrap();
        let mut lowering = CLowering::new(&ast);

        assert_eq!(lowering.parse_int_literal(int, span()).unwrap(), 0);
        assert_eq!(lowering.parse_char_literal(ch, span()).unwrap(), 0);
        assert_eq!(lowering.diagnostics.len(), 2);
    }

    #[test]
    fn valid_literal_helpers_return_parsed_values() {
        let mut ast = CAst::new();
        let int = ast.intern("0x2a").unwrap();
        let ch = ast.intern("'\\x41'").unwrap();
        let len_sym = ast.intern("12").unwrap();
        let len = ast.alloc(CNode::IntLiteral(len_sym), span()).unwrap();
        let lowering = CLowering::new(&ast);
        let mut lowering = lowering;

        assert_eq!(lowering.parse_int_literal(int, span()).unwrap(), 42);
        assert_eq!(lowering.parse_char_literal(ch, span()).unwrap(), 65);
        assert_eq!(lowering.const_array_len(len).unwrap(), Some(12));
        assert!(lowering.diagnostics.is_empty());
    }

    #[test]
    fn const_array_len_ignores_non_integer_nodes() {
        let mut ast = CAst::new();
        let name = ast.intern("n").unwrap();
        let node = ast.alloc(CNode::Ident(name), span()).unwrap();
        let lowering = CLowering::new(&ast);

        assert_eq!(lowering.const_array_len(node).unwrap(), None);
    }
}
