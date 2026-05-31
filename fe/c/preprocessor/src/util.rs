#![allow(clippy::unwrap_used)]
//! Helpers for inspecting and synthesising preprocessing tokens.

use crate::alloc_prelude::*;
use stratum_arena::Interner;
use stratum_c_lexer::{PpToken, PpTokenKind};

/// Returns the source spelling of a preprocessing token.
#[must_use]
pub fn spelling(token: &PpToken, interner: &Interner) -> String {
    match token.kind {
        PpTokenKind::Identifier(sym)
        | PpTokenKind::Number(sym)
        | PpTokenKind::CharConst(sym)
        | PpTokenKind::StringLit(sym) => interner.resolve(sym).unwrap_or("<invalid>").to_string(),
        PpTokenKind::Punct(punct) => punct.spelling().to_string(),
        PpTokenKind::Newline => "\n".to_string(),
        PpTokenKind::Other(ch) => ch.to_string(),
    }
}

/// Returns `true` if `token` is the named identifier.
#[must_use]
pub fn is_identifier(token: &PpToken, interner: &Interner, name: &str) -> bool {
    matches!(token.kind, PpTokenKind::Identifier(sym) if interner.resolve(sym).unwrap_or("<invalid>") == name)
}

/// Renders a string literal spelling for the stringize (`#`) operator, escaping `"` and `\`.
#[must_use]
pub fn stringize(tokens: &[PpToken], interner: &Interner) -> String {
    let mut inner = String::new();
    let mut first = true;
    for token in tokens {
        if token.kind == PpTokenKind::Newline {
            continue;
        }
        if !first && token.leading_whitespace {
            inner.push(' ');
        }
        first = false;
        for ch in spelling(token, interner).chars() {
            if ch == '"' || ch == '\\' {
                inner.push('\\');
            }
            inner.push(ch);
        }
    }
    format!("\"{inner}\"")
}

#[cfg(test)]
mod tests {
    use super::{is_identifier, spelling, stringize};
    use crate::alloc_prelude::*;
    use stratum_arena::Interner;
    use stratum_c_lexer::{PpTokenKind, lex};
    use stratum_diagnostics::FileId;

    #[test]
    fn spelling_round_trips_identifier() {
        let mut interner = Interner::new();
        let result = lex("foo", FileId::from_raw(0), &mut interner).unwrap();
        assert_eq!(
            result
                .tokens
                .first()
                .map(|token| spelling(token, &interner)),
            Some("foo".to_string())
        );
    }

    #[test]
    fn stringize_escapes_quotes() {
        let mut interner = Interner::new();
        let result = lex("a \"b\"", FileId::from_raw(0), &mut interner).unwrap();
        let text = stringize(&result.tokens, &interner);
        assert_eq!(text, "\"a \\\"b\\\"\"");
    }

    #[test]
    fn spelling_covers_non_identifier_tokens() {
        let mut interner = Interner::new();
        let result = lex("1 'c' \"s\" +\n@", FileId::from_raw(0), &mut interner).unwrap();
        let rendered: Vec<_> = result
            .tokens
            .iter()
            .map(|token| spelling(token, &interner))
            .collect();
        assert_eq!(rendered, ["1", "'c'", "\"s\"", "+", "\n", "@"]);
    }

    #[test]
    fn identifier_matching_uses_interner_text() {
        let mut interner = Interner::new();
        let result = lex("name 1", FileId::from_raw(0), &mut interner).unwrap();
        let first = result.tokens.first().unwrap();
        let second = result.tokens.get(1).unwrap();
        assert!(is_identifier(first, &interner, "name"));
        assert!(!is_identifier(first, &interner, "other"));
        assert!(!matches!(second.kind, PpTokenKind::Identifier(_)));
        assert!(!is_identifier(second, &interner, "name"));
    }

    #[test]
    fn stringize_skips_newlines_and_preserves_other_tokens() {
        let mut interner = Interner::new();
        let result = lex("a\n@", FileId::from_raw(0), &mut interner).unwrap();
        assert_eq!(stringize(&result.tokens, &interner), "\"a@\"");
    }
}
