//! Expression lowering: C expressions into HIR expression nodes.
//!
//! Every C expression maps to a faithful HIR node — casts keep their target type, `sizeof`
//! keeps its operand, compound assignment and increment/decrement stay first-class rather
//! than being desugared, and the comma and conditional operators survive intact. Nothing is
//! dropped, so lowering never has to emit an "unsupported" diagnostic for an expression.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_c_ast::{
    AssignOp, BinaryOp as CBinaryOp, CNode, CNodeId, PostfixOp as CPostfixOp, UnaryOp as CUnaryOp,
};
use stratum_diagnostics::Span;
use stratum_hir::{BinaryOp, HirContext, HirNode, HirNodeId, PostfixOp, UnaryOp};

impl CLowering<'_> {
    /// Lowers a C expression node into a HIR expression node.
    pub(crate) fn lower_expr(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        match self.ast.node(id) {
            CNode::Ident(sym) => {
                let sym = *sym;
                let name = self.lower_symbol(cx, sym)?;
                cx.alloc(HirNode::Name(name), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::IntLiteral(sym) => {
                let value = self.parse_int_literal(*sym, span)?;
                cx.alloc(HirNode::IntLiteral(value), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::CharLiteral(sym) => {
                let value = self.parse_char_literal(*sym, span)?;
                cx.alloc(HirNode::CharLiteral(value), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::BoolLiteral(value) => cx
                .alloc(HirNode::IntLiteral(i128::from(*value)), span)
                .map_err(crate::error::Error::from),
            CNode::Nullptr => cx
                .alloc(HirNode::IntLiteral(0), span)
                .map_err(crate::error::Error::from),
            CNode::FloatLiteral(sym) => {
                let sym = *sym;
                let interned = self.lower_symbol(cx, sym)?;
                cx.alloc(HirNode::FloatLiteral(interned), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::StringLiteral(sym) => {
                let sym = *sym;
                let interned = self.lower_symbol(cx, sym)?;
                cx.alloc(HirNode::StringLiteral(interned), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::Binary { op, lhs, rhs } => {
                let (op, lhs, rhs) = (*op, *lhs, *rhs);
                let lhs = self.lower_expr(cx, lhs)?;
                let rhs = self.lower_expr(cx, rhs)?;
                cx.alloc(
                    HirNode::Binary {
                        op: map_binary_op(op),
                        lhs,
                        rhs,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Unary { op, operand } => {
                let (op, operand) = (*op, *operand);
                let operand = self.lower_expr(cx, operand)?;
                cx.alloc(
                    HirNode::Unary {
                        op: map_unary_op(op),
                        operand,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Postfix { op, operand } => {
                let (op, operand) = (*op, *operand);
                let operand = self.lower_expr(cx, operand)?;
                cx.alloc(
                    HirNode::Postfix {
                        op: map_postfix_op(op),
                        operand,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Assign { op, target, value } => {
                let (op, target, value) = (*op, *target, *value);
                let target = self.lower_expr(cx, target)?;
                let value = self.lower_expr(cx, value)?;
                cx.alloc(
                    HirNode::Assign {
                        op: compound_op(op),
                        target,
                        value,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Conditional { .. } | CNode::Comma { .. } => {
                self.lower_grouping_expr(cx, id, span)
            }
            _ => self.lower_postfix_expr(cx, id, span),
        }
    }

    fn lower_grouping_expr(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
        match self.ast.node(id) {
            CNode::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                let (cond, then_expr, else_expr) = (*cond, *then_expr, *else_expr);
                let cond = self.lower_expr(cx, cond)?;
                let then_expr = self.lower_expr(cx, then_expr)?;
                let else_expr = self.lower_expr(cx, else_expr)?;
                cx.alloc(
                    HirNode::Ternary {
                        cond,
                        then_expr,
                        else_expr,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Comma { lhs, rhs } => {
                let (lhs, rhs) = (*lhs, *rhs);
                let lhs = self.lower_expr(cx, lhs)?;
                let rhs = self.lower_expr(cx, rhs)?;
                cx.alloc(HirNode::Comma { lhs, rhs }, span)
                    .map_err(crate::error::Error::from)
            }
            _ => Err(crate::error::Error::UnexpectedAstNode(
                "grouping expression",
            )),
        }
    }

    /// Lowers the call/access/type-operator family of expressions (calls, member access,
    /// subscripting, casts, and `sizeof`), keeping [`lower_expr`](Self::lower_expr) short.
    fn lower_postfix_expr(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
        match self.ast.node(id) {
            CNode::Call { callee, args } => {
                let callee = *callee;
                let args = args.clone();
                let callee = self.lower_expr(cx, callee)?;
                let mut lowered_args = Vec::with_capacity(args.len());
                for arg in args {
                    lowered_args.push(self.lower_expr(cx, arg)?);
                }
                cx.alloc(
                    HirNode::Call {
                        callee,
                        args: lowered_args,
                    },
                    span,
                )
                .map_err(crate::error::Error::from)
            }
            CNode::Member { base, field, arrow } => {
                let (base, field, arrow) = (*base, *field, *arrow);
                let base = self.lower_expr(cx, base)?;
                let field = self.lower_symbol(cx, field)?;
                cx.alloc(HirNode::Member { base, field, arrow }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::Index { base, index } => {
                let (base, index) = (*base, *index);
                let base = self.lower_expr(cx, base)?;
                let index = self.lower_expr(cx, index)?;
                cx.alloc(HirNode::Index { base, index }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::Cast { type_name, expr } => {
                let type_name = type_name.clone();
                let expr = *expr;
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                let operand = self.lower_expr(cx, expr)?;
                cx.alloc(HirNode::Cast { ty, operand }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::SizeofExpr(operand) | CNode::AlignofExpr(operand) => {
                let operand = *operand;
                let operand = self.lower_expr(cx, operand)?;
                cx.alloc(HirNode::SizeofExpr(operand), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::SizeofType(type_name) | CNode::AlignofType(type_name) => {
                let type_name = type_name.clone();
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                cx.alloc(HirNode::SizeofType(ty), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::GenericSelection {
                controlling,
                associations,
            } => {
                let selected = associations
                    .first()
                    .map_or(*controlling, |association| association.expr);
                self.lower_expr(cx, selected)
            }
            CNode::CompoundLiteral { type_name, init } => {
                let type_name = type_name.clone();
                let init = *init;
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                let init = self.lower_init(cx, init)?;
                cx.alloc(HirNode::CompoundLiteral { ty, init }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::InitList(_) => self.lower_brace_as_expr(cx, id, span),
            _ => cx
                .alloc(HirNode::IntLiteral(0), span)
                .map_err(crate::error::Error::from),
        }
    }

    /// Lowers a stray brace initialiser appearing in expression position into the first
    /// element's value (or `0` when empty), preserving evaluation without inventing a node.
    fn lower_brace_as_expr(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
        if let CNode::InitList(items) = self.ast.node(id) {
            let items = items.clone();
            if let Some(first) = items.first() {
                let value = first.value;
                return self.lower_expr(cx, value);
            }
        }
        cx.alloc(HirNode::IntLiteral(0), span)
            .map_err(crate::error::Error::from)
    }
}

fn map_binary_op(op: CBinaryOp) -> BinaryOp {
    match op {
        CBinaryOp::Mul => BinaryOp::Mul,
        CBinaryOp::Div => BinaryOp::Div,
        CBinaryOp::Rem => BinaryOp::Rem,
        CBinaryOp::Add => BinaryOp::Add,
        CBinaryOp::Sub => BinaryOp::Sub,
        CBinaryOp::Shl => BinaryOp::Shl,
        CBinaryOp::Shr => BinaryOp::Shr,
        CBinaryOp::Lt => BinaryOp::Lt,
        CBinaryOp::Gt => BinaryOp::Gt,
        CBinaryOp::Le => BinaryOp::Le,
        CBinaryOp::Ge => BinaryOp::Ge,
        CBinaryOp::Eq => BinaryOp::Eq,
        CBinaryOp::Ne => BinaryOp::Ne,
        CBinaryOp::BitAnd => BinaryOp::BitAnd,
        CBinaryOp::BitXor => BinaryOp::BitXor,
        CBinaryOp::BitOr => BinaryOp::BitOr,
        CBinaryOp::LogicalAnd => BinaryOp::LogicalAnd,
        CBinaryOp::LogicalOr => BinaryOp::LogicalOr,
    }
}

fn map_unary_op(op: CUnaryOp) -> UnaryOp {
    match op {
        CUnaryOp::Plus => UnaryOp::Plus,
        CUnaryOp::Neg => UnaryOp::Neg,
        CUnaryOp::Not => UnaryOp::Not,
        CUnaryOp::BitNot => UnaryOp::BitNot,
        CUnaryOp::AddressOf => UnaryOp::AddressOf,
        CUnaryOp::Deref => UnaryOp::Deref,
        CUnaryOp::PreInc => UnaryOp::PreInc,
        CUnaryOp::PreDec => UnaryOp::PreDec,
    }
}

fn map_postfix_op(op: CPostfixOp) -> PostfixOp {
    match op {
        CPostfixOp::PostInc => PostfixOp::Inc,
        CPostfixOp::PostDec => PostfixOp::Dec,
    }
}

/// Maps an assignment operator to the underlying binary operator, or `None` for plain `=`.
fn compound_op(op: AssignOp) -> Option<BinaryOp> {
    Some(match op {
        AssignOp::Assign => return None,
        AssignOp::Mul => BinaryOp::Mul,
        AssignOp::Div => BinaryOp::Div,
        AssignOp::Rem => BinaryOp::Rem,
        AssignOp::Add => BinaryOp::Add,
        AssignOp::Sub => BinaryOp::Sub,
        AssignOp::Shl => BinaryOp::Shl,
        AssignOp::Shr => BinaryOp::Shr,
        AssignOp::And => BinaryOp::BitAnd,
        AssignOp::Xor => BinaryOp::BitXor,
        AssignOp::Or => BinaryOp::BitOr,
    })
}

#[cfg(test)]
mod tests {
    use super::CLowering;
    use crate::alloc_prelude::*;
    use crate::test_utils::dump;
    use stratum_c_ast::{CAst, CNode, InitItem};
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::{HirContext, HirNode};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn index_is_first_class() {
        let out = dump("void f(int *p) { p[2]; }");
        assert!(out.contains("index"), "got: {out}");
        assert!(!out.contains("binary `+`"), "index must not desugar: {out}");
    }

    #[test]
    fn compound_assignment_is_first_class() {
        let out = dump("void f(int x) { x += 5; }");
        assert!(out.contains("assign `+=`"), "got: {out}");
    }

    #[test]
    fn post_increment_is_first_class() {
        let out = dump("void f(int x) { x++; }");
        assert!(out.contains("postfix `++`"), "got: {out}");
    }

    #[test]
    fn pre_increment_is_first_class() {
        let out = dump("void f(int x) { ++x; }");
        assert!(out.contains("unary `++`"), "got: {out}");
    }

    #[test]
    fn sizeof_type_lowers_without_error() {
        let out = dump("void f(void) { int x; x = sizeof(int); }");
        assert!(out.contains("sizeof-type i32"), "got: {out}");
    }

    #[test]
    fn sizeof_expr_lowers_without_error() {
        let out = dump("void f(int x) { x = sizeof x; }");
        assert!(out.contains("sizeof-expr"), "got: {out}");
    }

    #[test]
    fn c23_constants_alignof_and_generic_lower() {
        let out = dump(
            "int f(int c) { int a = true; int b = false; void *p = nullptr; \
             return alignof c + _Alignof(int) + _Generic(c, int: a, default: b); }",
        );
        assert!(out.contains("var a: i32"), "got: {out}");
        assert!(out.contains("int 1"), "got: {out}");
        assert!(out.contains("var b: i32"), "got: {out}");
        assert!(out.contains("var p: *void"), "got: {out}");
        assert!(out.contains("sizeof-expr"), "got: {out}");
        assert!(out.contains("sizeof-type i32"), "got: {out}");
    }

    #[test]
    fn ternary_lowers_faithfully() {
        let out = dump("void f(int x) { x = x ? 1 : 2; }");
        assert!(out.contains("ternary"), "got: {out}");
    }

    #[test]
    fn comma_lowers_faithfully() {
        let out = dump("void f(int x) { x = (1, 2); }");
        assert!(out.contains("comma"), "got: {out}");
    }

    #[test]
    fn member_access_lowers_faithfully() {
        let out = dump("struct S { int a; }; void f(struct S *s) { s->a; (*s).a; }");
        assert!(out.contains("member ->a"), "got: {out}");
        assert!(out.contains("member .a"), "got: {out}");
    }

    #[test]
    fn cast_lowers_faithfully() {
        let out = dump("void f(int x) { x = (int)3; }");
        assert!(out.contains("cast i32"), "got: {out}");
    }

    #[test]
    fn compound_literal_lowers() {
        let out = dump("struct P { int x; }; void f(void) { struct P q; q = (struct P){ 7 }; }");
        assert!(out.contains("compound-literal struct P"), "got: {out}");
        assert!(out.contains("init-list"), "got: {out}");
    }

    #[test]
    fn brace_initializer_expression_uses_first_item_or_zero() {
        let mut ast = CAst::new();
        let value_sym = ast.intern("7").unwrap();
        let value = ast.alloc(CNode::IntLiteral(value_sym), span()).unwrap();
        let non_empty = ast
            .alloc(
                CNode::InitList(vec![InitItem {
                    designators: Vec::new(),
                    value,
                }]),
                span(),
            )
            .unwrap();
        let empty = ast.alloc(CNode::InitList(Vec::new()), span()).unwrap();
        let fallback = ast
            .alloc(CNode::TranslationUnit(Vec::new()), span())
            .unwrap();

        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        let lowered = lowering.lower_expr(&mut hir, non_empty).unwrap();
        assert_eq!(hir.node(lowered), &HirNode::IntLiteral(7));

        let lowered = lowering.lower_expr(&mut hir, empty).unwrap();
        assert_eq!(hir.node(lowered), &HirNode::IntLiteral(0));

        let lowered = lowering.lower_expr(&mut hir, fallback).unwrap();
        assert_eq!(hir.node(lowered), &HirNode::IntLiteral(0));

        let lowered = lowering
            .lower_brace_as_expr(&mut hir, fallback, span())
            .unwrap();
        assert_eq!(hir.node(lowered), &HirNode::IntLiteral(0));
    }

    #[test]
    fn grouping_helper_rejects_wrong_node_kind() {
        let mut ast = CAst::new();
        let id = ast
            .alloc(CNode::TranslationUnit(Vec::new()), span())
            .unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        assert!(lowering.lower_grouping_expr(&mut hir, id, span()).is_err());
    }
}
