//! Expression lowering: C expressions into HIR expression nodes.
//!
//! Core C expressions map to structured HIR nodes; casts keep their target type, `sizeof` and
//! `alignof` keep their original operator, compound assignment and increment/decrement stay
//! first-class rather than being desugared, and the comma, conditional, and generic-selection
//! operators survive intact.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_c_ast::{
    AssignOp, BinaryOp as CBinaryOp, CNode, CNodeId, GenericAssociation as CGenericAssociation,
    PostfixOp as CPostfixOp, UnaryOp as CUnaryOp,
};
use stratum_diagnostics::Span;
use stratum_hir::{
    BinaryOp, GenericAssociation as HirGenericAssociation, HirContext, HirNode, HirNodeId,
    PostfixOp, UnaryOp,
};

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
                .alloc(HirNode::BoolLiteral(*value), span)
                .map_err(crate::error::Error::from),
            CNode::Nullptr => cx
                .alloc(HirNode::Nullptr, span)
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
            CNode::Conditional {
                cond,
                then_expr,
                else_expr,
            } => self.lower_conditional_expr(cx, *cond, *then_expr, *else_expr, span),
            CNode::Comma { lhs, rhs } => self.lower_comma_expr(cx, *lhs, *rhs, span),
            _ => self.lower_postfix_expr(cx, id, span),
        }
    }

    fn lower_conditional_expr(
        &mut self,
        cx: &mut HirContext,
        cond: CNodeId,
        then_expr: CNodeId,
        else_expr: CNodeId,
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
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

    fn lower_comma_expr(
        &mut self,
        cx: &mut HirContext,
        lhs: CNodeId,
        rhs: CNodeId,
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
        let lhs = self.lower_expr(cx, lhs)?;
        let rhs = self.lower_expr(cx, rhs)?;
        cx.alloc(HirNode::Comma { lhs, rhs }, span)
            .map_err(crate::error::Error::from)
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
            CNode::SizeofExpr(operand) => {
                let operand = *operand;
                let operand = self.lower_expr(cx, operand)?;
                cx.alloc(HirNode::SizeofExpr(operand), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::SizeofType(type_name) => {
                let type_name = type_name.clone();
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                cx.alloc(HirNode::SizeofType(ty), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::AlignofExpr(operand) => {
                let operand = *operand;
                let operand = self.lower_expr(cx, operand)?;
                cx.alloc(HirNode::AlignofExpr(operand), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::AlignofType(type_name) => {
                let type_name = type_name.clone();
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                cx.alloc(HirNode::AlignofType(ty), span)
                    .map_err(crate::error::Error::from)
            }
            CNode::GenericSelection {
                controlling,
                associations,
            } => self.lower_generic_selection(cx, *controlling, associations, span),
            CNode::CompoundLiteral { type_name, init } => {
                let type_name = type_name.clone();
                let init = *init;
                let ty =
                    self.lower_type(cx, &type_name.specifiers, &type_name.declarator.derivations)?;
                let init = self.lower_init(cx, init)?;
                cx.alloc(HirNode::CompoundLiteral { ty, init }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::InitList(_) => Err(crate::error::Error::UnexpectedAstNode(
                "initializer list expression",
            )),
            _ => Err(crate::error::Error::UnexpectedAstNode("expression")),
        }
    }

    fn lower_generic_selection(
        &mut self,
        cx: &mut HirContext,
        controlling: CNodeId,
        associations: &[CGenericAssociation],
        span: Span,
    ) -> crate::error::Result<HirNodeId> {
        let selected = self.select_generic_association_index(controlling, associations, span);
        let controlling = self.lower_expr(cx, controlling)?;
        let mut lowered = Vec::with_capacity(associations.len());
        for association in associations {
            let ty = match &association.type_name {
                Some(type_name) => {
                    let derivations = &type_name.declarator.derivations;
                    Some(self.lower_type(cx, &type_name.specifiers, derivations)?)
                }
                None => None,
            };
            let expr = self.lower_expr(cx, association.expr)?;
            lowered.push(HirGenericAssociation { ty, expr });
        }
        cx.alloc(
            HirNode::GenericSelection {
                controlling,
                associations: lowered,
                selected,
            },
            span,
        )
        .map_err(crate::error::Error::from)
    }

    fn select_generic_association_index(
        &mut self,
        controlling: CNodeId,
        associations: &[CGenericAssociation],
        span: Span,
    ) -> Option<usize> {
        let default = associations
            .iter()
            .position(|association| association.type_name.is_none());
        if let Some(controlling_ty) = self.generic_expr_type(controlling) {
            for (index, association) in associations.iter().enumerate() {
                let Some(type_name) = &association.type_name else {
                    continue;
                };
                let association_ty = Self::generic_type_from_declaration(
                    &type_name.specifiers,
                    &type_name.declarator.derivations,
                );
                if self.generic_types_compatible(&association_ty, &controlling_ty) {
                    return Some(index);
                }
            }
            if let Some(default) = default {
                return Some(default);
            }
            self.error(span, "no matching `_Generic` association");
            return None;
        }
        if let Some(default) = default {
            return Some(default);
        }
        self.error(
            span,
            "cannot determine `_Generic` controlling expression type",
        );
        associations.first().map(|_| 0)
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
    use super::{CLowering, compound_op, map_binary_op, map_unary_op};
    use crate::alloc_prelude::*;
    use crate::test_utils::dump;
    use stratum_arena::Symbol;
    use stratum_c_ast::{
        AssignOp, BinaryOp as CBinaryOp, CAst, CNode, CNodeId, DeclSpecifiers, Declarator,
        GenericAssociation, InitItem, PostfixOp as CPostfixOp, TypeName, TypeSpecifier,
        UnaryOp as CUnaryOp,
    };
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::{BinaryOp, HirContext, UnaryOp};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn valid_expr(ast: &mut CAst) -> CNodeId {
        ast.alloc(CNode::BoolLiteral(true), span()).unwrap()
    }

    fn invalid_expr(ast: &mut CAst) -> CNodeId {
        ast.alloc(CNode::Ident(Symbol::default()), span()).unwrap()
    }

    fn int_type_name() -> TypeName {
        TypeName {
            specifiers: DeclSpecifiers {
                type_specifiers: vec![TypeSpecifier::Int],
                ..DeclSpecifiers::default()
            },
            declarator: Declarator::default(),
        }
    }

    fn invalid_type_name() -> TypeName {
        TypeName {
            specifiers: DeclSpecifiers {
                type_specifiers: vec![TypeSpecifier::TypedefName(Symbol::default())],
                ..DeclSpecifiers::default()
            },
            declarator: Declarator::default(),
        }
    }

    fn assert_lower_expr_err(build: impl FnOnce(&mut CAst) -> CNodeId) {
        let mut ast = CAst::new();
        let id = build(&mut ast);
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        assert!(lowering.lower_expr(&mut hir, id).is_err());
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
    fn operator_mapping_tables_cover_every_arm() {
        for (c, hir) in [
            (CBinaryOp::Mul, BinaryOp::Mul),
            (CBinaryOp::Div, BinaryOp::Div),
            (CBinaryOp::Rem, BinaryOp::Rem),
            (CBinaryOp::Add, BinaryOp::Add),
            (CBinaryOp::Sub, BinaryOp::Sub),
            (CBinaryOp::Shl, BinaryOp::Shl),
            (CBinaryOp::Shr, BinaryOp::Shr),
            (CBinaryOp::Lt, BinaryOp::Lt),
            (CBinaryOp::Gt, BinaryOp::Gt),
            (CBinaryOp::Le, BinaryOp::Le),
            (CBinaryOp::Ge, BinaryOp::Ge),
            (CBinaryOp::Eq, BinaryOp::Eq),
            (CBinaryOp::Ne, BinaryOp::Ne),
            (CBinaryOp::BitAnd, BinaryOp::BitAnd),
            (CBinaryOp::BitXor, BinaryOp::BitXor),
            (CBinaryOp::BitOr, BinaryOp::BitOr),
            (CBinaryOp::LogicalAnd, BinaryOp::LogicalAnd),
            (CBinaryOp::LogicalOr, BinaryOp::LogicalOr),
        ] {
            assert_eq!(map_binary_op(c), hir);
        }

        for (c, hir) in [
            (CUnaryOp::Plus, UnaryOp::Plus),
            (CUnaryOp::Neg, UnaryOp::Neg),
            (CUnaryOp::Not, UnaryOp::Not),
            (CUnaryOp::BitNot, UnaryOp::BitNot),
            (CUnaryOp::AddressOf, UnaryOp::AddressOf),
            (CUnaryOp::Deref, UnaryOp::Deref),
            (CUnaryOp::PreInc, UnaryOp::PreInc),
            (CUnaryOp::PreDec, UnaryOp::PreDec),
        ] {
            assert_eq!(map_unary_op(c), hir);
        }

        assert_eq!(compound_op(AssignOp::Assign), None);
        for (c, hir) in [
            (AssignOp::Mul, BinaryOp::Mul),
            (AssignOp::Div, BinaryOp::Div),
            (AssignOp::Rem, BinaryOp::Rem),
            (AssignOp::Add, BinaryOp::Add),
            (AssignOp::Sub, BinaryOp::Sub),
            (AssignOp::Shl, BinaryOp::Shl),
            (AssignOp::Shr, BinaryOp::Shr),
            (AssignOp::And, BinaryOp::BitAnd),
            (AssignOp::Xor, BinaryOp::BitXor),
            (AssignOp::Or, BinaryOp::BitOr),
        ] {
            assert_eq!(compound_op(c), Some(hir));
        }
    }

    #[test]
    fn post_increment_is_first_class() {
        let out = dump("void f(int x) { x++; }");
        assert!(out.contains("postfix `++`"), "got: {out}");
    }

    #[test]
    fn char_float_and_string_literals_lower_as_first_class_nodes() {
        let out = dump("void f(void) { char c = 'x'; double d = 1.5; char *s = \"hi\"; }");
        assert!(out.contains("char 120"), "got: {out}");
        assert!(out.contains("float 1.5"), "got: {out}");
        assert!(out.contains("string \"hi\""), "got: {out}");
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
        assert!(out.contains("bool true"), "got: {out}");
        assert!(out.contains("var b: i32"), "got: {out}");
        assert!(out.contains("bool false"), "got: {out}");
        assert!(out.contains("var p: *void"), "got: {out}");
        assert!(out.contains("nullptr"), "got: {out}");
        assert!(out.contains("alignof-expr"), "got: {out}");
        assert!(out.contains("alignof-type i32"), "got: {out}");
        assert!(out.contains("generic-selection selected 0"), "got: {out}");
    }

    #[test]
    fn generic_selection_uses_controlling_expression_type() {
        let out = dump("int x = _Generic(0, default: 2, int: 1);");
        assert!(out.contains("generic-selection selected 1"), "got: {out}");
        assert!(out.contains("association 0 default"), "got: {out}");
        assert!(out.contains("association 1 i32"), "got: {out}");
    }

    #[test]
    fn generic_selection_uses_parameter_type_context() {
        let out =
            dump("int f(int c) { int a = 1; int b = 2; return _Generic(c, int: a, default: b); }");
        assert!(out.contains("name `a`"), "got: {out}");
    }

    #[test]
    fn generic_selection_distinguishes_pointer_targets() {
        let out = dump(
            "int f(int *ip, float *fp) { return _Generic(fp, int *: 1, float *: 2, default: 3); }",
        );
        assert!(out.contains("generic-selection selected 1"), "got: {out}");
        assert!(out.contains("association 0 *i32"), "got: {out}");
        assert!(out.contains("association 1 *f32"), "got: {out}");
    }

    #[test]
    fn generic_selection_preserves_address_of_array_type() {
        let out = dump(
            "int f(void) { int a[3]; return _Generic(&a, int (*)[3]: 1, int **: 2, default: 3); }",
        );
        assert!(out.contains("generic-selection selected 0"), "got: {out}");
        assert!(out.contains("association 0 *[i32; 3]"), "got: {out}");
        assert!(out.contains("association 1 **i32"), "got: {out}");
    }

    #[test]
    fn generic_selection_preserves_address_of_function_type() {
        let out =
            dump("int g(void); int f(void) { return _Generic(&g, int (*)(void): 1, default: 2); }");
        assert!(out.contains("generic-selection selected 0"), "got: {out}");
        assert!(out.contains("association 0 *fn() -> i32"), "got: {out}");
    }

    #[test]
    fn generic_selection_uses_arithmetic_conversions_and_typedef_compatibility() {
        let out = dump(
            "typedef int I; int f(I x) { return _Generic(1.0 + 2.0, double: 1, int: 2, default: 3) + _Generic(x, int: 4, default: 5); }",
        );
        assert_eq!(
            out.matches("generic-selection selected 0").count(),
            2,
            "got: {out}"
        );
        assert!(out.contains("association 0 f64"), "got: {out}");
        assert!(out.contains("association 0 i32"), "got: {out}");
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single synthetic fixture covers all `_Generic` diagnostic-selection paths"
    )]
    fn generic_selection_reports_unmatched_and_unknown_controlling_types() {
        fn float_type_name() -> TypeName {
            TypeName {
                specifiers: DeclSpecifiers {
                    type_specifiers: vec![TypeSpecifier::Float],
                    ..DeclSpecifiers::default()
                },
                declarator: Declarator::default(),
            }
        }

        let mut ast = CAst::new();
        let zero = ast.intern("0").unwrap();
        let one = ast.intern("1").unwrap();
        let two = ast.intern("2").unwrap();
        let controlling = ast.alloc(CNode::IntLiteral(zero), span()).unwrap();
        let selected = ast.alloc(CNode::IntLiteral(one), span()).unwrap();
        let default = ast.alloc(CNode::IntLiteral(two), span()).unwrap();
        let empty_init = ast.alloc(CNode::InitList(Vec::new()), span()).unwrap();
        let unknown = ast
            .alloc(
                CNode::CompoundLiteral {
                    type_name: int_type_name(),
                    init: empty_init,
                },
                span(),
            )
            .unwrap();

        let known_default = ast
            .alloc(
                CNode::GenericSelection {
                    controlling,
                    associations: vec![
                        GenericAssociation {
                            type_name: Some(float_type_name()),
                            expr: selected,
                        },
                        GenericAssociation {
                            type_name: None,
                            expr: default,
                        },
                    ],
                },
                span(),
            )
            .unwrap();
        let known_missing = ast
            .alloc(
                CNode::GenericSelection {
                    controlling,
                    associations: vec![GenericAssociation {
                        type_name: Some(float_type_name()),
                        expr: selected,
                    }],
                },
                span(),
            )
            .unwrap();
        let unknown_default = ast
            .alloc(
                CNode::GenericSelection {
                    controlling: unknown,
                    associations: vec![GenericAssociation {
                        type_name: None,
                        expr: default,
                    }],
                },
                span(),
            )
            .unwrap();
        let unknown_missing = ast
            .alloc(
                CNode::GenericSelection {
                    controlling: unknown,
                    associations: vec![GenericAssociation {
                        type_name: Some(float_type_name()),
                        expr: selected,
                    }],
                },
                span(),
            )
            .unwrap();

        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        let lowered = lowering.lower_expr(&mut hir, known_default).unwrap();
        assert_eq!(
            hir.dump(lowered).lines().next(),
            Some("generic-selection selected 1")
        );

        let lowered = lowering.lower_expr(&mut hir, known_missing).unwrap();
        assert_eq!(hir.dump(lowered).lines().next(), Some("generic-selection"));
        assert_eq!(lowering.diagnostics.len(), 1);

        let lowered = lowering.lower_expr(&mut hir, unknown_default).unwrap();
        assert_eq!(
            hir.dump(lowered).lines().next(),
            Some("generic-selection selected 0")
        );

        let lowered = lowering.lower_expr(&mut hir, unknown_missing).unwrap();
        assert_eq!(
            hir.dump(lowered).lines().next(),
            Some("generic-selection selected 0")
        );
        assert_eq!(lowering.diagnostics.len(), 2);
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
    fn brace_initializer_expression_is_rejected() {
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
        assert!(lowering.lower_expr(&mut hir, non_empty).is_err());
        assert!(lowering.lower_expr(&mut hir, empty).is_err());
        assert!(lowering.lower_expr(&mut hir, fallback).is_err());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single table covers expression lowering error propagation arms"
    )]
    fn expression_lowering_propagates_child_errors() {
        assert_lower_expr_err(|ast| ast.alloc(CNode::Ident(Symbol::default()), span()).unwrap());
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::IntLiteral(Symbol::default()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::CharLiteral(Symbol::default()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::FloatLiteral(Symbol::default()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::StringLiteral(Symbol::default()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let lhs = invalid_expr(ast);
            let rhs = valid_expr(ast);
            ast.alloc(
                CNode::Binary {
                    op: CBinaryOp::Add,
                    lhs,
                    rhs,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let lhs = valid_expr(ast);
            let rhs = invalid_expr(ast);
            ast.alloc(
                CNode::Binary {
                    op: CBinaryOp::Add,
                    lhs,
                    rhs,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let operand = invalid_expr(ast);
            ast.alloc(
                CNode::Unary {
                    op: CUnaryOp::Neg,
                    operand,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let operand = invalid_expr(ast);
            ast.alloc(
                CNode::Postfix {
                    op: CPostfixOp::PostInc,
                    operand,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let target = invalid_expr(ast);
            let value = valid_expr(ast);
            ast.alloc(
                CNode::Assign {
                    op: AssignOp::Assign,
                    target,
                    value,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let target = valid_expr(ast);
            let value = invalid_expr(ast);
            ast.alloc(
                CNode::Assign {
                    op: AssignOp::Assign,
                    target,
                    value,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let cond = invalid_expr(ast);
            let then_expr = valid_expr(ast);
            let else_expr = valid_expr(ast);
            ast.alloc(
                CNode::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let cond = valid_expr(ast);
            let then_expr = invalid_expr(ast);
            let else_expr = valid_expr(ast);
            ast.alloc(
                CNode::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let cond = valid_expr(ast);
            let then_expr = valid_expr(ast);
            let else_expr = invalid_expr(ast);
            ast.alloc(
                CNode::Conditional {
                    cond,
                    then_expr,
                    else_expr,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let lhs = invalid_expr(ast);
            let rhs = valid_expr(ast);
            ast.alloc(CNode::Comma { lhs, rhs }, span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            let lhs = valid_expr(ast);
            let rhs = invalid_expr(ast);
            ast.alloc(CNode::Comma { lhs, rhs }, span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            let callee = invalid_expr(ast);
            ast.alloc(
                CNode::Call {
                    callee,
                    args: Vec::new(),
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let callee = valid_expr(ast);
            let arg = invalid_expr(ast);
            ast.alloc(
                CNode::Call {
                    callee,
                    args: vec![arg],
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let base = invalid_expr(ast);
            ast.alloc(
                CNode::Member {
                    base,
                    field: Symbol::default(),
                    arrow: false,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let base = valid_expr(ast);
            ast.alloc(
                CNode::Member {
                    base,
                    field: Symbol::default(),
                    arrow: false,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let base = invalid_expr(ast);
            let index = valid_expr(ast);
            ast.alloc(CNode::Index { base, index }, span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            let base = valid_expr(ast);
            let index = invalid_expr(ast);
            ast.alloc(CNode::Index { base, index }, span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            let expr = valid_expr(ast);
            ast.alloc(
                CNode::Cast {
                    type_name: invalid_type_name(),
                    expr,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let expr = invalid_expr(ast);
            ast.alloc(
                CNode::Cast {
                    type_name: int_type_name(),
                    expr,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let operand = invalid_expr(ast);
            ast.alloc(CNode::SizeofExpr(operand), span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::SizeofType(invalid_type_name()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let operand = invalid_expr(ast);
            ast.alloc(CNode::AlignofExpr(operand), span()).unwrap()
        });
        assert_lower_expr_err(|ast| {
            ast.alloc(CNode::AlignofType(invalid_type_name()), span())
                .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let controlling = invalid_expr(ast);
            let expr = valid_expr(ast);
            ast.alloc(
                CNode::GenericSelection {
                    controlling,
                    associations: vec![GenericAssociation {
                        type_name: None,
                        expr,
                    }],
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let controlling = valid_expr(ast);
            let expr = valid_expr(ast);
            ast.alloc(
                CNode::GenericSelection {
                    controlling,
                    associations: vec![GenericAssociation {
                        type_name: Some(invalid_type_name()),
                        expr,
                    }],
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let controlling = valid_expr(ast);
            let expr = invalid_expr(ast);
            ast.alloc(
                CNode::GenericSelection {
                    controlling,
                    associations: vec![GenericAssociation {
                        type_name: None,
                        expr,
                    }],
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let init = valid_expr(ast);
            ast.alloc(
                CNode::CompoundLiteral {
                    type_name: invalid_type_name(),
                    init,
                },
                span(),
            )
            .unwrap()
        });
        assert_lower_expr_err(|ast| {
            let init = invalid_expr(ast);
            ast.alloc(
                CNode::CompoundLiteral {
                    type_name: int_type_name(),
                    init,
                },
                span(),
            )
            .unwrap()
        });
    }
}
