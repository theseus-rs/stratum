//! Parsing of C literal spellings into HIR literal values.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_arena::Symbol as CSymbol;
use stratum_c_ast::{CNode, CNodeId, decode_char_literal, parse_integer};
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
        if let Some((value, _)) = parse_integer(raw) {
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
        if let Some(value) = decode_char_literal(raw) {
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
            CNode::IntLiteral(sym) => Ok(parse_integer(self.ast.resolve(*sym)?)
                .map(|(value, _)| value)
                .and_then(|v| u64::try_from(v).ok())),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CLowering;
    use stratum_c_ast::{CAst, CNode};
    use stratum_c_ast::{decode_char_literal, parse_integer};
    use stratum_diagnostics::{FileId, Span};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn integer_parser_covers_bases_suffixes_and_invalid_digits() {
        assert_eq!(parse_integer(""), None);
        assert_eq!(parse_integer("0x10ul"), Some((16, true)));
        assert_eq!(parse_integer("0xzz"), None);
        assert_eq!(parse_integer("010"), Some((8, false)));
        assert_eq!(parse_integer("42"), Some((42, false)));
        assert_eq!(parse_integer("09"), None);
        assert_eq!(parse_integer("bad"), None);
    }

    #[test]
    fn character_parser_covers_numeric_plain_and_escape_spellings() {
        assert_eq!(decode_char_literal("65"), Some(65));
        assert_eq!(decode_char_literal("'A'"), Some(65));
        assert_eq!(decode_char_literal("'\\n'"), Some(u32::from(b'\n')));
        assert_eq!(decode_char_literal("'\\t'"), Some(u32::from(b'\t')));
        assert_eq!(decode_char_literal("'\\r'"), Some(u32::from(b'\r')));
        assert_eq!(decode_char_literal("'\\0'"), Some(0));
        assert_eq!(decode_char_literal("'\\\\'"), Some(u32::from(b'\\')));
        assert_eq!(decode_char_literal("'\\''"), Some(u32::from(b'\'')));
        assert_eq!(decode_char_literal("'\\\"'"), Some(u32::from(b'"')));
        assert_eq!(decode_char_literal("'\\?'"), Some(u32::from(b'?')));
        assert_eq!(decode_char_literal("'\\a'"), Some(0x07));
        assert_eq!(decode_char_literal("'\\b'"), Some(0x08));
        assert_eq!(decode_char_literal("'\\f'"), Some(0x0c));
        assert_eq!(decode_char_literal("'\\v'"), Some(0x0b));
        assert_eq!(decode_char_literal("'\\x41'"), Some(65));
        assert_eq!(decode_char_literal("'\\101'"), Some(65));
        assert_eq!(decode_char_literal("'\\12x'"), Some(u32::from(b'\n')));
        assert_eq!(decode_char_literal("'\\z'"), None);
        assert_eq!(decode_char_literal("''"), None);
        assert_eq!(decode_char_literal("'"), None);
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
