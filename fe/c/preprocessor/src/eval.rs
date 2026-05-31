//! A constant-expression evaluator for `#if` / `#elif` directives.
//!
//! The evaluator operates on a list of preprocessing tokens in which `defined` has already
//! been resolved and macros have been expanded. Per the C standard, any identifier that
//! survives to this point evaluates to `0`. All arithmetic is performed with `i64`.

use crate::alloc_prelude::*;
use crate::util::spelling;
use stratum_arena::Interner;
use stratum_c_lexer::{PpToken, PpTokenKind, Punctuator};
use stratum_diagnostics::{Diagnostic, Label, Span};

/// Evaluates a preprocessor constant expression.
///
/// Returns the integer value of the expression (where non-zero is "true"), or an error
/// diagnostic for malformed input.
///
/// # Errors
///
/// Returns a [`Diagnostic`] if the expression is empty, has trailing tokens, or contains a
/// syntactic error such as an unbalanced parenthesis.
pub fn eval(tokens: &[PpToken], interner: &Interner, directive: Span) -> Result<i64, Diagnostic> {
    let mut parser = Eval {
        tokens,
        interner,
        pos: 0,
        directive,
    };
    if parser.tokens.is_empty() {
        return Err(Diagnostic::error("`#if` expression is empty")
            .with_label(Label::new(directive, "expected an expression")));
    }
    let value = parser.ternary()?;
    if parser.pos != parser.tokens.len() {
        let span = parser
            .tokens
            .get(parser.pos)
            .map_or(parser.directive, |token| token.span);
        return Err(Diagnostic::error("trailing tokens after `#if` expression")
            .with_label(Label::new(span, "unexpected token")));
    }
    Ok(value)
}

struct Eval<'a> {
    tokens: &'a [PpToken],
    interner: &'a Interner,
    pos: usize,
    directive: Span,
}

impl Eval<'_> {
    fn peek(&self) -> Option<Punctuator> {
        match self.tokens.get(self.pos).map(|t| t.kind) {
            Some(PpTokenKind::Punct(p)) => Some(p),
            _ => None,
        }
    }

    fn eat(&mut self, punct: Punctuator) -> bool {
        if self.peek() == Some(punct) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn error_here(&self, message: &str) -> Diagnostic {
        let span = self.tokens.get(self.pos).map_or(self.directive, |t| t.span);
        Diagnostic::error(message).with_label(Label::new(span, "here"))
    }

    fn ternary(&mut self) -> Result<i64, Diagnostic> {
        let cond = self.binary(0)?;
        if self.eat(Punctuator::Question) {
            let then_val = self.ternary()?;
            if !self.eat(Punctuator::Colon) {
                return Err(self.error_here("expected `:` in conditional expression"));
            }
            let else_val = self.ternary()?;
            Ok(if cond != 0 { then_val } else { else_val })
        } else {
            Ok(cond)
        }
    }

    fn binary(&mut self, min_prec: u8) -> Result<i64, Diagnostic> {
        let mut lhs = self.unary()?;
        while let Some(op) = self.peek() {
            let Some(prec) = precedence(op) else { break };
            if prec < min_prec {
                break;
            }
            self.pos += 1;
            let rhs = self.binary(prec + 1)?;
            lhs = self.apply(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn apply(&self, op: Punctuator, lhs: i64, rhs: i64) -> Result<i64, Diagnostic> {
        let value = match op {
            Punctuator::PipePipe => i64::from((lhs != 0) || (rhs != 0)),
            Punctuator::AmpAmp => i64::from((lhs != 0) && (rhs != 0)),
            Punctuator::Pipe => lhs | rhs,
            Punctuator::Caret => lhs ^ rhs,
            Punctuator::Amp => lhs & rhs,
            Punctuator::EqEq => i64::from(lhs == rhs),
            Punctuator::Ne => i64::from(lhs != rhs),
            Punctuator::Lt => i64::from(lhs < rhs),
            Punctuator::Le => i64::from(lhs <= rhs),
            Punctuator::Gt => i64::from(lhs > rhs),
            Punctuator::Ge => i64::from(lhs >= rhs),
            Punctuator::Shl => lhs.wrapping_shl(u32::try_from(rhs).unwrap_or(0)),
            Punctuator::Shr => lhs.wrapping_shr(u32::try_from(rhs).unwrap_or(0)),
            Punctuator::Plus => lhs.wrapping_add(rhs),
            Punctuator::Minus => lhs.wrapping_sub(rhs),
            Punctuator::Star => lhs.wrapping_mul(rhs),
            Punctuator::Slash | Punctuator::Percent => return self.apply_div(op, lhs, rhs),
            _ => return Err(self.error_here("unsupported operator")),
        };
        Ok(value)
    }

    fn apply_div(&self, op: Punctuator, lhs: i64, rhs: i64) -> Result<i64, Diagnostic> {
        if rhs == 0 {
            return Err(self.error_here("division by zero in `#if` expression"));
        }
        Ok(if op == Punctuator::Slash {
            lhs.wrapping_div(rhs)
        } else {
            lhs.wrapping_rem(rhs)
        })
    }

    fn unary(&mut self) -> Result<i64, Diagnostic> {
        match self.peek() {
            Some(Punctuator::Plus) => {
                self.pos += 1;
                self.unary()
            }
            Some(Punctuator::Minus) => {
                self.pos += 1;
                Ok(self.unary()?.wrapping_neg())
            }
            Some(Punctuator::Bang) => {
                self.pos += 1;
                Ok(i64::from(self.unary()? == 0))
            }
            Some(Punctuator::Tilde) => {
                self.pos += 1;
                Ok(!self.unary()?)
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Result<i64, Diagnostic> {
        if self.eat(Punctuator::LParen) {
            let value = self.ternary()?;
            if !self.eat(Punctuator::RParen) {
                return Err(self.error_here("expected `)`"));
            }
            return Ok(value);
        }
        let Some(token) = self.tokens.get(self.pos) else {
            return Err(self.error_here("expected a value"));
        };
        self.pos += 1;
        match token.kind {
            PpTokenKind::Number(_) => parse_pp_number(&spelling(token, self.interner), token.span),
            PpTokenKind::CharConst(_) => Ok(char_value(&spelling(token, self.interner))),
            PpTokenKind::Identifier(_) => Ok(0),
            _ => Err(Diagnostic::error("unexpected token in `#if` expression")
                .with_label(Label::new(token.span, "not a constant"))),
        }
    }
}

fn precedence(op: Punctuator) -> Option<u8> {
    let prec = match op {
        Punctuator::PipePipe => 1,
        Punctuator::AmpAmp => 2,
        Punctuator::Pipe => 3,
        Punctuator::Caret => 4,
        Punctuator::Amp => 5,
        Punctuator::EqEq | Punctuator::Ne => 6,
        Punctuator::Lt | Punctuator::Le | Punctuator::Gt | Punctuator::Ge => 7,
        Punctuator::Shl | Punctuator::Shr => 8,
        Punctuator::Plus | Punctuator::Minus => 9,
        Punctuator::Star | Punctuator::Slash | Punctuator::Percent => 10,
        _ => return None,
    };
    Some(prec)
}

/// Parses an integer preprocessing number, ignoring any `u`/`l` suffixes.
fn parse_pp_number(text: &str, span: Span) -> Result<i64, Diagnostic> {
    let digits: &str = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<i64>()
    };
    parsed.map_err(|_| {
        Diagnostic::error(format!("invalid integer constant `{text}` in `#if`"))
            .with_label(Label::new(span, "not an integer"))
    })
}

/// Returns the value of a character constant such as `'A'`, using only the first character.
fn char_value(text: &str) -> i64 {
    let inner = text.trim_start_matches(['L', 'u', 'U']).trim_matches('\'');
    let mut chars = inner.chars();
    match chars.next() {
        Some('\\') => match chars.next() {
            Some('n') => 10,
            Some('t') => 9,
            Some('r') => 13,
            Some('\\') => i64::from(b'\\'),
            Some('\'') => i64::from(b'\''),
            Some('0') | None => 0,
            Some(other) => i64::from(other as u32),
        },
        Some(c) => i64::from(c as u32),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{Eval, char_value, eval, parse_pp_number};
    use crate::alloc_prelude::*;
    use stratum_arena::Interner;
    use stratum_c_lexer::{Punctuator, lex};
    use stratum_diagnostics::{FileId, Span};

    fn run(expr: &str) -> i64 {
        let mut interner = Interner::new();
        let result = lex(expr, FileId::from_raw(0), &mut interner).unwrap();
        let tokens: Vec<_> = result
            .tokens
            .into_iter()
            .filter(|t| !matches!(t.kind, stratum_c_lexer::PpTokenKind::Newline))
            .collect();
        eval(&tokens, &interner, Span::new(FileId::from_raw(0), 0, 0)).expect("evaluates")
    }

    fn fails(expr: &str) {
        let mut interner = Interner::new();
        let result = lex(expr, FileId::from_raw(0), &mut interner).unwrap();
        let tokens: Vec<_> = result
            .tokens
            .into_iter()
            .filter(|t| !matches!(t.kind, stratum_c_lexer::PpTokenKind::Newline))
            .collect();
        assert!(eval(&tokens, &interner, Span::new(FileId::from_raw(0), 0, 0)).is_err());
    }

    #[test]
    fn arithmetic_precedence() {
        assert_eq!(run("1 + 2 * 3"), 7);
        assert_eq!(run("(1 + 2) * 3"), 9);
    }

    #[test]
    fn logical_and_ternary() {
        assert_eq!(run("1 && 0"), 0);
        assert_eq!(run("1 ? 42 : 7"), 42);
        assert_eq!(run("0 ? 42 : 7"), 7);
    }

    #[test]
    fn hex_and_octal() {
        assert_eq!(run("0x10 + 010"), 24);
    }

    #[test]
    fn unknown_identifier_is_zero() {
        assert_eq!(run("FOO + 1"), 1);
    }

    #[test]
    fn bitwise_comparison_shift_and_unary_operators() {
        assert_eq!(run("1 | 2"), 3);
        assert_eq!(run("3 ^ 1"), 2);
        assert_eq!(run("3 & 1"), 1);
        assert_eq!(run("1 != 2"), 1);
        assert_eq!(run("1 < 2"), 1);
        assert_eq!(run("1 <= 1"), 1);
        assert_eq!(run("2 >= 1"), 1);
        assert_eq!(run("8 >> 1"), 4);
        assert_eq!(run("5 - 3"), 2);
        assert_eq!(run("+5"), 5);
        assert_eq!(run("-5"), -5);
    }

    #[test]
    fn malformed_expressions_report_diagnostics() {
        fails("");
        fails("1 2");
        fails("1 ? 2");
        fails("(1");
        fails("1 / 0");
        fails("1 +");
        fails("?");
        fails("09");
    }

    #[test]
    fn private_apply_rejects_non_binary_operator() {
        let interner = Interner::new();
        let parser = Eval {
            tokens: &[],
            interner: &interner,
            pos: 0,
            directive: Span::point(FileId::from_raw(0), 0),
        };
        assert!(parser.apply(Punctuator::Assign, 1, 2).is_err());
    }

    #[test]
    fn private_number_and_char_helpers_cover_edge_spellings() {
        let span = Span::point(FileId::from_raw(0), 0);
        assert_eq!(parse_pp_number("123ul", span).unwrap(), 123);
        assert!(parse_pp_number("bad", span).is_err());

        assert_eq!(char_value("'\\n'"), 10);
        assert_eq!(char_value("'\\t'"), 9);
        assert_eq!(char_value("'\\r'"), 13);
        assert_eq!(char_value("'\\\\'"), i64::from(b'\\'));
        assert_eq!(char_value("'\\'x"), i64::from(b'\''));
        assert_eq!(char_value("'\\0'"), 0);
        assert_eq!(char_value("'\\z'"), i64::from('z' as u32));
        assert_eq!(char_value("''"), 0);
    }
}
