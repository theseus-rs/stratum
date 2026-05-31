//! Rendering of preprocessing tokens for `--emit pptokens`.

use crate::alloc_prelude::*;
use core::fmt::Write as _;
use stratum_arena::Interner;
use stratum_c_lexer::{PpToken, PpTokenKind, Punctuator};

/// Renders a preprocessing-token stream to a stable, line-oriented form.
///
/// Newline markers are omitted; their effect is reflected in the `at_bol` of the following
/// token, which is not shown here to keep the output stable across expansion.
///
/// # Errors
///
/// Returns an error if a token symbol cannot be resolved.
pub fn pp_tokens(tokens: &[PpToken], interner: &Interner) -> crate::Result<String> {
    let mut out = String::new();
    for token in tokens {
        let line = match token.kind {
            PpTokenKind::Identifier(sym) => format!("ident {}", interner.resolve(sym)?),
            PpTokenKind::Number(sym) => format!("number {}", interner.resolve(sym)?),
            PpTokenKind::CharConst(sym) => format!("char {}", interner.resolve(sym)?),
            PpTokenKind::StringLit(sym) => format!("string {}", interner.resolve(sym)?),
            PpTokenKind::Punct(p) => format!("punct {}", Punctuator::spelling(p)),
            PpTokenKind::Newline => continue,
            PpTokenKind::Other(c) => format!("other {c}"),
        };
        let _ = writeln!(out, "{line}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::pp_tokens;
    use stratum_arena::Interner;
    use stratum_c_lexer::{PpToken, PpTokenKind};
    use stratum_diagnostics::{FileId, Span};

    #[test]
    fn renders_every_preprocessing_token_kind() {
        let mut interner = Interner::new();
        let ident = interner.intern("name").unwrap();
        let number = interner.intern("1").unwrap();
        let ch = interner.intern("'c'").unwrap();
        let string = interner.intern("\"s\"").unwrap();
        let span = Span::point(FileId::from_raw(0), 0);
        let base = PpToken {
            kind: PpTokenKind::Newline,
            span,
            leading_whitespace: false,
            at_bol: false,
        };
        let tokens = [
            PpToken {
                kind: PpTokenKind::Identifier(ident),
                ..base
            },
            PpToken {
                kind: PpTokenKind::Number(number),
                ..base
            },
            PpToken {
                kind: PpTokenKind::CharConst(ch),
                ..base
            },
            PpToken {
                kind: PpTokenKind::StringLit(string),
                ..base
            },
            PpToken {
                kind: PpTokenKind::Newline,
                ..base
            },
            PpToken {
                kind: PpTokenKind::Other('@'),
                ..base
            },
        ];
        let rendered = pp_tokens(&tokens, &interner).unwrap();
        assert_eq!(
            rendered,
            "ident name\nnumber 1\nchar 'c'\nstring \"s\"\nother @\n"
        );
    }
}
