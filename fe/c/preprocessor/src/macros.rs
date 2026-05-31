//! Macro definitions and the macro table.

use crate::alloc_prelude::*;
use crate::util::is_identifier;
use stratum_arena::{Interner, Symbol};
use stratum_c_lexer::{PpToken, PpTokenKind, Punctuator};
use stratum_diagnostics::{Diagnostic, Label, Span};

/// A preprocessor macro definition (`#define`).
#[derive(Debug, Clone)]
pub struct MacroDef {
    /// The macro's name.
    pub name: Symbol,
    /// Parameter names for a function-like macro, or `None` for an object-like macro.
    pub params: Option<Vec<Symbol>>,
    /// Whether the function-like macro ends with `...` (collects `__VA_ARGS__`).
    pub variadic: bool,
    /// The replacement list (with no trailing newline).
    pub body: Vec<PpToken>,
    /// The span of the macro name in the `#define` directive.
    pub span: Span,
}

impl MacroDef {
    /// Returns `true` if this is a function-like macro.
    #[must_use]
    pub fn is_function_like(&self) -> bool {
        self.params.is_some()
    }
}

/// Parses the tokens of a `#define` directive (everything after `#define`).
///
/// `line` is the directive's token list excluding the leading `#` and `define`. Returns the
/// parsed [`MacroDef`], or an error diagnostic if the directive is malformed.
/// # Errors
/// Returns an error if the macro definition is invalid.
pub fn parse_define(line: &[PpToken], directive: Span) -> Result<MacroDef, Diagnostic> {
    let Some((name_tok, rest)) = line.split_first() else {
        return Err(Diagnostic::error("`#define` requires a macro name")
            .with_label(Label::new(directive, "expected a name here")));
    };
    let PpTokenKind::Identifier(name) = name_tok.kind else {
        return Err(Diagnostic::error("macro name must be an identifier")
            .with_label(Label::new(name_tok.span, "not an identifier")));
    };

    // A function-like macro has a `(` immediately after the name with no intervening space.
    let function_like = rest
        .first()
        .is_some_and(|t| t.kind == PpTokenKind::Punct(Punctuator::LParen) && !t.leading_whitespace);

    if !function_like {
        return Ok(MacroDef {
            name,
            params: None,
            variadic: false,
            body: rest.to_vec(),
            span: name_tok.span,
        });
    }

    let (params, variadic, body) = parse_params(rest.get(1..).unwrap_or_default(), name_tok.span)?;
    Ok(MacroDef {
        name,
        params: Some(params),
        variadic,
        body,
        span: name_tok.span,
    })
}

type ParsedParams = (Vec<Symbol>, bool, Vec<PpToken>);

fn parse_params(tokens: &[PpToken], name_span: Span) -> Result<ParsedParams, Diagnostic> {
    let mut params = Vec::new();
    let mut variadic = false;
    let mut i = 0;
    let mut expect_param = true;

    loop {
        let Some(tok) = tokens.get(i) else {
            return Err(Diagnostic::error("unterminated macro parameter list")
                .with_label(Label::new(name_span, "in this macro")));
        };
        match tok.kind {
            PpTokenKind::Punct(Punctuator::RParen) => {
                i += 1;
                break;
            }
            PpTokenKind::Punct(Punctuator::Comma) if !expect_param => {
                expect_param = true;
                i += 1;
            }
            PpTokenKind::Punct(Punctuator::Ellipsis) if expect_param => {
                variadic = true;
                i += 1;
                expect_param = false;
            }
            PpTokenKind::Identifier(sym) if expect_param => {
                params.push(sym);
                expect_param = false;
                i += 1;
            }
            _ => {
                return Err(Diagnostic::error("malformed macro parameter list")
                    .with_label(Label::new(tok.span, "unexpected token")));
            }
        }
    }
    let body = tokens.get(i..).unwrap_or_default().to_vec();
    Ok((params, variadic, body))
}

/// Returns `true` if `token` spells `__VA_ARGS__`.
#[must_use]
pub fn is_va_args(token: &PpToken, interner: &Interner) -> bool {
    is_identifier(token, interner, "__VA_ARGS__")
}

#[cfg(test)]
mod tests {
    use super::{is_va_args, parse_define};
    use crate::alloc_prelude::*;
    use stratum_arena::Interner;
    use stratum_c_lexer::{PpTokenKind, lex};
    use stratum_diagnostics::{FileId, Span};

    fn tokens(src: &str, interner: &mut Interner) -> Vec<stratum_c_lexer::PpToken> {
        lex(src, FileId::from_raw(0), interner)
            .unwrap()
            .tokens
            .into_iter()
            .filter(|tok| !matches!(tok.kind, PpTokenKind::Newline))
            .collect()
    }

    #[test]
    fn object_like_define_with_space_before_paren_is_not_function_like() {
        let mut interner = Interner::new();
        let toks = tokens("NAME ( x )", &mut interner);
        let def = parse_define(&toks, Span::point(FileId::from_raw(0), 0)).unwrap();
        assert!(!def.is_function_like());
        assert_eq!(def.body.len(), 3);
    }

    #[test]
    fn malformed_defines_report_diagnostics() {
        let mut interner = Interner::new();
        assert!(parse_define(&[], Span::point(FileId::from_raw(0), 0)).is_err());
        let non_ident = tokens("123", &mut interner);
        assert!(parse_define(&non_ident, Span::point(FileId::from_raw(0), 0)).is_err());
        let unterminated = tokens("F(x", &mut interner);
        assert!(parse_define(&unterminated, Span::point(FileId::from_raw(0), 0)).is_err());
        let malformed = tokens("F(,)", &mut interner);
        assert!(parse_define(&malformed, Span::point(FileId::from_raw(0), 0)).is_err());
    }

    #[test]
    fn va_args_identifier_is_detected() {
        let mut interner = Interner::new();
        let toks = tokens("__VA_ARGS__ other", &mut interner);
        assert!(is_va_args(toks.first().unwrap(), &interner));
        assert!(!is_va_args(toks.get(1).unwrap(), &interner));
    }
}
