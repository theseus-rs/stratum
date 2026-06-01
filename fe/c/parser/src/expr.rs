//! Parsing of expressions, using precedence climbing for binary operators.

use crate::alloc_prelude::*;
use crate::decl::{is_alignof_keyword, is_type_keyword};
use crate::parser::{PResult, Parser};
use stratum_c_ast::{AssignOp, BinaryOp, CNode, CNodeId, GenericAssociation, PostfixOp, UnaryOp};
use stratum_c_lexer::{Dialect, Keyword, Punctuator, TokenKind};

impl Parser<'_> {
    /// Parses a full expression, including the comma operator.
    pub(crate) fn parse_expr(&mut self) -> PResult<CNodeId> {
        let mut lhs = self.parse_assignment()?;
        loop {
            if !self.is_punct(Punctuator::Comma) {
                break;
            }
            self.bump();
            let rhs = self.parse_assignment()?;
            let span = self.ast.span(lhs).to(self.ast.span(rhs));
            lhs = self.alloc_node(CNode::Comma { lhs, rhs }, span)?;
        }
        Ok(lhs)
    }

    /// Parses an assignment expression.
    pub(crate) fn parse_assignment(&mut self) -> PResult<CNodeId> {
        let lhs = self.parse_conditional()?;
        let Some(op) = assign_op(self.peek_kind()) else {
            return Ok(lhs);
        };
        self.bump();
        let value = self.parse_assignment()?;
        let span = self.ast.span(lhs).to(self.ast.span(value));
        self.alloc_node(
            CNode::Assign {
                op,
                target: lhs,
                value,
            },
            span,
        )
    }

    /// Parses a conditional (`a ? b : c`) expression.
    pub(crate) fn parse_conditional(&mut self) -> PResult<CNodeId> {
        let cond = self.parse_binary(0)?;
        if !self.eat_punct(Punctuator::Question) {
            return Ok(cond);
        }
        let then_expr = self.parse_expr()?;
        self.expect_punct(Punctuator::Colon)?;
        let else_expr = self.parse_conditional()?;
        let span = self.ast.span(cond).to(self.ast.span(else_expr));
        self.alloc_node(
            CNode::Conditional {
                cond,
                then_expr,
                else_expr,
            },
            span,
        )
    }

    /// Parses binary operators at or above `min_prec` using precedence climbing.
    fn parse_binary(&mut self, min_prec: u8) -> PResult<CNodeId> {
        let mut lhs = self.parse_cast()?;
        while let Some((op, prec)) = binary_op(self.peek_kind()) {
            if prec < min_prec {
                break;
            }
            self.bump();
            let rhs = self.parse_binary(prec + 1)?;
            let span = self.ast.span(lhs).to(self.ast.span(rhs));
            lhs = self.alloc_node(CNode::Binary { op, lhs, rhs }, span)?;
        }
        Ok(lhs)
    }

    /// Parses a cast expression, or falls through to a unary expression.
    fn parse_cast(&mut self) -> PResult<CNodeId> {
        if self.is_punct(Punctuator::LParen) && self.lparen_starts_type() {
            let start = self.bump().span; // `(`
            let type_name = self.parse_type_name()?;
            self.expect_punct(Punctuator::RParen)?;
            // `(T){ ... }` is a C99 compound literal, not a cast.
            if self.is_punct(Punctuator::LBrace) {
                self.require(Dialect::C99, "compound literal")?;
                let init = self.parse_brace_initializer()?;
                let span = start.to(self.ast.span(init));
                let literal = self.alloc_node(CNode::CompoundLiteral { type_name, init }, span)?;
                return self.parse_postfix_continuation(literal);
            }
            let expr = self.parse_cast()?;
            let span = start.to(self.ast.span(expr));
            return self.alloc_node(CNode::Cast { type_name, expr }, span);
        }
        self.parse_unary()
    }

    /// Returns `true` if the token after `(` begins a type name.
    fn lparen_starts_type(&self) -> bool {
        match self.peek2_kind() {
            TokenKind::Keyword(kw) => is_type_keyword(kw),
            TokenKind::Identifier(sym) => self.is_typedef_name(sym),
            _ => false,
        }
    }

    fn parse_unary(&mut self) -> PResult<CNodeId> {
        if let Some(op) = prefix_op(self.peek_kind()) {
            let start = self.bump().span;
            let operand = self.parse_cast()?;
            let span = start.to(self.ast.span(operand));
            return self.alloc_node(CNode::Unary { op, operand }, span);
        }
        match self.peek_kind() {
            TokenKind::Punct(Punctuator::PlusPlus) => self.parse_prefix_incr(UnaryOp::PreInc),
            TokenKind::Punct(Punctuator::MinusMinus) => self.parse_prefix_incr(UnaryOp::PreDec),
            TokenKind::Keyword(Keyword::Sizeof) => self.parse_sizeof(),
            TokenKind::Keyword(kw) if is_alignof_keyword(kw) => self.parse_alignof(),
            _ => self.parse_postfix(),
        }
    }

    fn parse_prefix_incr(&mut self, op: UnaryOp) -> PResult<CNodeId> {
        let start = self.bump().span;
        let operand = self.parse_unary()?;
        let span = start.to(self.ast.span(operand));
        self.alloc_node(CNode::Unary { op, operand }, span)
    }

    fn parse_sizeof(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `sizeof`
        if self.is_punct(Punctuator::LParen) && self.lparen_starts_type() {
            self.bump();
            let type_name = self.parse_type_name()?;
            let end = self.expect_punct(Punctuator::RParen)?;
            return self.alloc_node(CNode::SizeofType(type_name), start.to(end));
        }
        let operand = self.parse_unary()?;
        let span = start.to(self.ast.span(operand));
        self.alloc_node(CNode::SizeofExpr(operand), span)
    }

    fn parse_alignof(&mut self) -> PResult<CNodeId> {
        let kw = match self.peek_kind() {
            TokenKind::Keyword(kw) if is_alignof_keyword(kw) => kw,
            _ => return Err(self.error("expected `alignof`")),
        };
        if kw == Keyword::C23Alignof {
            self.require(Dialect::C23, "`alignof`")?;
        } else {
            self.require(Dialect::C11, "`_Alignof`")?;
        }
        let start = self.bump().span;
        if self.is_punct(Punctuator::LParen) && self.lparen_starts_type() {
            self.bump();
            let type_name = self.parse_type_name()?;
            let end = self.expect_punct(Punctuator::RParen)?;
            return self.alloc_node(CNode::AlignofType(type_name), start.to(end));
        }
        self.require(Dialect::C23, "`alignof` expression operand")?;
        let operand = self.parse_unary()?;
        let span = start.to(self.ast.span(operand));
        self.alloc_node(CNode::AlignofExpr(operand), span)
    }

    fn parse_postfix(&mut self) -> PResult<CNodeId> {
        let expr = self.parse_primary()?;
        self.parse_postfix_continuation(expr)
    }

    /// Applies any trailing postfix operators (`[]`, `()`, `.`, `->`, `++`, `--`) to an
    /// already-parsed primary or compound-literal expression.
    pub(crate) fn parse_postfix_continuation(&mut self, mut expr: CNodeId) -> PResult<CNodeId> {
        loop {
            expr = match self.peek_kind() {
                TokenKind::Punct(Punctuator::LBracket) => self.parse_index(expr)?,
                TokenKind::Punct(Punctuator::LParen) => self.parse_call(expr)?,
                TokenKind::Punct(Punctuator::Dot) => self.parse_member(expr, false)?,
                TokenKind::Punct(Punctuator::Arrow) => self.parse_member(expr, true)?,
                TokenKind::Punct(Punctuator::PlusPlus) => {
                    self.parse_postfix_incr(expr, PostfixOp::PostInc)?
                }
                TokenKind::Punct(Punctuator::MinusMinus) => {
                    self.parse_postfix_incr(expr, PostfixOp::PostDec)?
                }
                _ => break,
            };
        }
        Ok(expr)
    }

    fn parse_index(&mut self, base: CNodeId) -> PResult<CNodeId> {
        self.bump(); // `[`
        let index = self.parse_expr()?;
        let end = self.expect_punct(Punctuator::RBracket)?;
        let span = self.ast.span(base).to(end);
        self.alloc_node(CNode::Index { base, index }, span)
    }

    fn parse_call(&mut self, callee: CNodeId) -> PResult<CNodeId> {
        self.bump(); // `(`
        let mut args = Vec::new();
        if !self.is_punct(Punctuator::RParen) {
            loop {
                args.push(self.parse_assignment()?);
                if !self.eat_punct(Punctuator::Comma) {
                    break;
                }
            }
        }
        let end = self.expect_punct(Punctuator::RParen)?;
        let span = self.ast.span(callee).to(end);
        self.alloc_node(CNode::Call { callee, args }, span)
    }

    fn parse_member(&mut self, base: CNodeId, arrow: bool) -> PResult<CNodeId> {
        self.bump(); // `.` or `->`
        let Some(field) = self.eat_identifier() else {
            return Err(self.error("expected a member name"));
        };
        let span = self.ast.span(base).to(self.peek().span);
        self.alloc_node(CNode::Member { base, field, arrow }, span)
    }

    fn parse_postfix_incr(&mut self, operand: CNodeId, op: PostfixOp) -> PResult<CNodeId> {
        let end = self.bump().span;
        let span = self.ast.span(operand).to(end);
        self.alloc_node(CNode::Postfix { op, operand }, span)
    }

    fn parse_primary(&mut self) -> PResult<CNodeId> {
        let token = self.peek();
        match token.kind {
            TokenKind::Identifier(sym) => {
                self.bump();
                self.alloc_node(CNode::Ident(sym), token.span)
            }
            TokenKind::Integer { .. } | TokenKind::Char(_) => self.parse_int_like(),
            TokenKind::Float(sym) => {
                self.bump();
                self.alloc_node(CNode::FloatLiteral(sym), token.span)
            }
            TokenKind::String(sym) => {
                self.bump();
                self.alloc_node(CNode::StringLiteral(sym), token.span)
            }
            TokenKind::Keyword(Keyword::True) => {
                self.bump();
                self.alloc_node(CNode::BoolLiteral(true), token.span)
            }
            TokenKind::Keyword(Keyword::False) => {
                self.bump();
                self.alloc_node(CNode::BoolLiteral(false), token.span)
            }
            TokenKind::Keyword(Keyword::Nullptr) => {
                self.bump();
                self.alloc_node(CNode::Nullptr, token.span)
            }
            TokenKind::Keyword(Keyword::Generic) => self.parse_generic_selection(),
            TokenKind::Punct(Punctuator::LParen) => {
                self.bump();
                let expr = self.parse_expr()?;
                self.expect_punct(Punctuator::RParen)?;
                Ok(expr)
            }
            _ => Err(self.error("expected an expression")),
        }
    }

    /// Parses an integer or character literal, recording its spelling for later evaluation.
    fn parse_int_like(&mut self) -> PResult<CNodeId> {
        let token = self.bump();
        let text = match token.kind {
            TokenKind::Integer { value, .. } => value.to_string(),
            TokenKind::Char(value) => value.to_string(),
            _ => return Err(self.error_at(token.span, "expected an integer or character literal")),
        };
        let sym = self.intern_ast(&text)?;
        let node = match token.kind {
            TokenKind::Char(_) => CNode::CharLiteral(sym),
            _ => CNode::IntLiteral(sym),
        };
        self.alloc_node(node, token.span)
    }

    fn parse_generic_selection(&mut self) -> PResult<CNodeId> {
        self.require(Dialect::C11, "`_Generic`")?;
        let start = self.bump().span;
        self.expect_punct(Punctuator::LParen)?;
        let controlling = self.parse_assignment()?;
        self.expect_punct(Punctuator::Comma)?;
        let mut associations = Vec::new();
        loop {
            associations.push(self.parse_generic_association()?);
            if !self.eat_punct(Punctuator::Comma) {
                break;
            }
        }
        let end = self.expect_punct(Punctuator::RParen)?;
        let node = CNode::GenericSelection {
            controlling,
            associations,
        };
        self.alloc_node(node, start.to(end))
    }

    fn parse_generic_association(&mut self) -> PResult<GenericAssociation> {
        let type_name = if self.eat_keyword(Keyword::Default) {
            None
        } else {
            Some(self.parse_type_name()?)
        };
        self.expect_punct(Punctuator::Colon)?;
        let expr = self.parse_assignment()?;
        Ok(GenericAssociation { type_name, expr })
    }
}

fn assign_op(kind: TokenKind) -> Option<AssignOp> {
    let TokenKind::Punct(p) = kind else {
        return None;
    };
    Some(match p {
        Punctuator::Assign => AssignOp::Assign,
        Punctuator::StarAssign => AssignOp::Mul,
        Punctuator::SlashAssign => AssignOp::Div,
        Punctuator::PercentAssign => AssignOp::Rem,
        Punctuator::PlusAssign => AssignOp::Add,
        Punctuator::MinusAssign => AssignOp::Sub,
        Punctuator::ShlAssign => AssignOp::Shl,
        Punctuator::ShrAssign => AssignOp::Shr,
        Punctuator::AmpAssign => AssignOp::And,
        Punctuator::CaretAssign => AssignOp::Xor,
        Punctuator::PipeAssign => AssignOp::Or,
        _ => return None,
    })
}

fn prefix_op(kind: TokenKind) -> Option<UnaryOp> {
    let TokenKind::Punct(p) = kind else {
        return None;
    };
    Some(match p {
        Punctuator::Amp => UnaryOp::AddressOf,
        Punctuator::Star => UnaryOp::Deref,
        Punctuator::Plus => UnaryOp::Plus,
        Punctuator::Minus => UnaryOp::Neg,
        Punctuator::Tilde => UnaryOp::BitNot,
        Punctuator::Bang => UnaryOp::Not,
        _ => return None,
    })
}

/// Returns the operator and its binding precedence for a binary operator token.
fn binary_op(kind: TokenKind) -> Option<(BinaryOp, u8)> {
    let TokenKind::Punct(p) = kind else {
        return None;
    };
    let result = match p {
        Punctuator::Star => (BinaryOp::Mul, 10),
        Punctuator::Slash => (BinaryOp::Div, 10),
        Punctuator::Percent => (BinaryOp::Rem, 10),
        Punctuator::Plus => (BinaryOp::Add, 9),
        Punctuator::Minus => (BinaryOp::Sub, 9),
        Punctuator::Shl => (BinaryOp::Shl, 8),
        Punctuator::Shr => (BinaryOp::Shr, 8),
        Punctuator::Lt => (BinaryOp::Lt, 7),
        Punctuator::Gt => (BinaryOp::Gt, 7),
        Punctuator::Le => (BinaryOp::Le, 7),
        Punctuator::Ge => (BinaryOp::Ge, 7),
        Punctuator::EqEq => (BinaryOp::Eq, 6),
        Punctuator::Ne => (BinaryOp::Ne, 6),
        Punctuator::Amp => (BinaryOp::BitAnd, 5),
        Punctuator::Caret => (BinaryOp::BitXor, 4),
        Punctuator::Pipe => (BinaryOp::BitOr, 3),
        Punctuator::AmpAmp => (BinaryOp::LogicalAnd, 2),
        Punctuator::PipePipe => (BinaryOp::LogicalOr, 1),
        _ => return None,
    };
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::{assign_op, binary_op, prefix_op};
    use crate::alloc_prelude::*;
    use crate::decl::is_type_keyword;
    use crate::parser::Parser;
    use stratum_arena::{Interner, Symbol};
    use stratum_c_ast::{AssignOp, BinaryOp, CAst, UnaryOp};
    use stratum_c_lexer::{Dialect, Keyword, Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};
    use stratum_utils::HashSet;

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn operator_helpers_cover_all_fallbacks_and_assignment_variants() {
        assert_eq!(assign_op(TokenKind::Identifier(Symbol::default())), None);
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::StarAssign)),
            Some(AssignOp::Mul)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::SlashAssign)),
            Some(AssignOp::Div)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::PercentAssign)),
            Some(AssignOp::Rem)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::MinusAssign)),
            Some(AssignOp::Sub)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::ShlAssign)),
            Some(AssignOp::Shl)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::ShrAssign)),
            Some(AssignOp::Shr)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::AmpAssign)),
            Some(AssignOp::And)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::CaretAssign)),
            Some(AssignOp::Xor)
        );
        assert_eq!(
            assign_op(TokenKind::Punct(Punctuator::PipeAssign)),
            Some(AssignOp::Or)
        );
        assert_eq!(assign_op(TokenKind::Punct(Punctuator::Plus)), None);

        assert_eq!(prefix_op(TokenKind::Identifier(Symbol::default())), None);
        assert_eq!(
            prefix_op(TokenKind::Punct(Punctuator::Amp)),
            Some(UnaryOp::AddressOf)
        );
        assert_eq!(
            prefix_op(TokenKind::Punct(Punctuator::Star)),
            Some(UnaryOp::Deref)
        );
        assert_eq!(
            prefix_op(TokenKind::Punct(Punctuator::Bang)),
            Some(UnaryOp::Not)
        );
        assert_eq!(prefix_op(TokenKind::Punct(Punctuator::Comma)), None);

        assert_eq!(binary_op(TokenKind::Identifier(Symbol::default())), None);
        assert_eq!(
            binary_op(TokenKind::Punct(Punctuator::Shr)),
            Some((BinaryOp::Shr, 8))
        );
        assert_eq!(binary_op(TokenKind::Punct(Punctuator::Comma)), None);

        assert!(is_type_keyword(Keyword::Struct));
        assert!(!is_type_keyword(Keyword::Return));
    }

    #[test]
    fn parse_int_like_rejects_non_integer_token_when_called_directly() {
        let interner = Interner::new();
        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::Semicolon),
            span: span(),
        }];
        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
            ast: CAst::with_interner(interner),
            diagnostics: Vec::new(),
            typedefs: vec![HashSet::default()],
            dialect: Dialect::DEFAULT,
        };
        assert!(parser.parse_int_like().is_err());
    }

    #[test]
    fn parse_alignof_rejects_wrong_entry_token_when_called_directly() {
        let interner = Interner::new();
        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::Semicolon),
            span: span(),
        }];
        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
            ast: CAst::with_interner(interner),
            diagnostics: Vec::new(),
            typedefs: vec![HashSet::default()],
            dialect: Dialect::DEFAULT,
        };
        assert!(parser.parse_alignof().is_err());
    }
}
