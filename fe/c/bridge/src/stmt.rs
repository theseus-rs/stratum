//! Statement lowering: C statements into faithful HIR control flow.
//!
//! Control flow keeps its original shapes — `while`, `do`/`while`, and `for` each lower to
//! the matching HIR loop, and `switch`/`case`/`default`, labels, and `goto` are preserved —
//! so the lowering is structure-preserving rather than normalising for the currently modeled
//! statement surface.

use crate::alloc_prelude::*;
use crate::lower::CLowering;
use stratum_c_ast::{CNode, CNodeId};
use stratum_hir::{HirContext, HirNode, HirNodeId};

impl CLowering<'_> {
    /// Lowers a compound statement (or any single statement) into a HIR [`Block`](HirNode::Block).
    pub(crate) fn lower_block(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        let mut items = Vec::new();
        if let CNode::Compound(stmts) = self.ast.node(id) {
            let stmts = stmts.clone();
            for stmt in stmts {
                self.lower_stmt_into(cx, stmt, &mut items)?;
            }
        } else {
            self.lower_stmt_into(cx, id, &mut items)?;
        }
        cx.alloc(HirNode::Block(items), span)
            .map_err(crate::error::Error::from)
    }

    /// Lowers a single statement, pushing one or more HIR nodes into `out`.
    ///
    /// Most statements yield exactly one node; declarations may yield several
    /// [`Var`](HirNode::Var)s (and aggregate definitions), and empty declarations yield none.
    fn lower_stmt_into(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let span = self.ast.span(id);
        match self.ast.node(id) {
            CNode::Compound(_) => out.push(self.lower_block(cx, id)?),
            CNode::Declaration {
                specifiers,
                declarators,
            } => {
                let specifiers = specifiers.clone();
                let declarators = declarators.clone();
                self.lower_declaration(cx, &specifiers, &declarators, id, out)?;
            }
            CNode::ExprStmt(None) => out.push(cx.alloc(HirNode::ExprStmt(None), span)?),
            CNode::ExprStmt(Some(expr)) => {
                let expr = *expr;
                let lowered = self.lower_expr(cx, expr)?;
                out.push(cx.alloc(HirNode::ExprStmt(Some(lowered)), span)?);
            }
            CNode::Return(value) => {
                let value = match value {
                    Some(v) => Some(self.lower_expr(cx, *v)?),
                    None => None,
                };
                out.push(cx.alloc(HirNode::Return(value), span)?);
            }
            CNode::Break => out.push(cx.alloc(HirNode::Break, span)?),
            CNode::Continue => out.push(cx.alloc(HirNode::Continue, span)?),
            CNode::Goto(label) => {
                let label = *label;
                let label = self.lower_symbol(cx, label)?;
                out.push(cx.alloc(HirNode::Goto(label), span)?);
            }
            CNode::If { .. } => out.push(self.lower_if(cx, id)?),
            CNode::While { .. } | CNode::DoWhile { .. } => out.push(self.lower_while(cx, id)?),
            CNode::For { .. } => out.push(self.lower_for(cx, id)?),
            CNode::Switch { .. } => out.push(self.lower_switch(cx, id)?),
            CNode::Case { .. } | CNode::Default { .. } | CNode::Label { .. } => {
                out.push(self.lower_labelled(cx, id)?);
            }
            _ => {
                // A bare expression node used in statement position.
                let lowered = self.lower_expr(cx, id)?;
                out.push(cx.alloc(HirNode::ExprStmt(Some(lowered)), span)?);
            }
        }
        Ok(())
    }

    /// Lowers a single statement to exactly one HIR node, wrapping multiple results (e.g. a
    /// multi-declarator declaration) in a [`Block`](HirNode::Block).
    fn lower_single_stmt(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        let mut items = Vec::new();
        self.lower_stmt_into(cx, id, &mut items)?;
        match items.as_slice() {
            [item] => Ok(*item),
            _ => cx
                .alloc(HirNode::Block(items), span)
                .map_err(crate::error::Error::from),
        }
    }

    fn lower_if(&mut self, cx: &mut HirContext, id: CNodeId) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        let CNode::If {
            cond,
            then_branch,
            else_branch,
        } = self.ast.node(id)
        else {
            return Err(crate::error::Error::UnexpectedAstNode("if statement"));
        };
        let (cond, then_branch, else_branch) = (*cond, *then_branch, *else_branch);
        let cond = self.lower_expr(cx, cond)?;
        let then_block = self.lower_block(cx, then_branch)?;
        let else_block = match else_branch {
            Some(e) => Some(self.lower_block(cx, e)?),
            None => None,
        };
        cx.alloc(
            HirNode::Conditional {
                cond,
                then_block,
                else_block,
            },
            span,
        )
        .map_err(crate::error::Error::from)
    }

    /// Lowers `while` and `do`/`while` into the matching faithful HIR loop.
    fn lower_while(&mut self, cx: &mut HirContext, id: CNodeId) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        match self.ast.node(id) {
            CNode::While { cond, body } => {
                let (cond, body) = (*cond, *body);
                let cond = self.lower_expr(cx, cond)?;
                let body = self.lower_block(cx, body)?;
                cx.alloc(HirNode::While { cond, body }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::DoWhile { body, cond } => {
                let (body, cond) = (*body, *cond);
                let body = self.lower_block(cx, body)?;
                let cond = self.lower_expr(cx, cond)?;
                cx.alloc(HirNode::DoWhile { body, cond }, span)
                    .map_err(crate::error::Error::from)
            }
            _ => Err(crate::error::Error::UnexpectedAstNode("loop statement")),
        }
    }

    /// Lowers a `for` loop, preserving each of its (optional) clauses.
    fn lower_for(&mut self, cx: &mut HirContext, id: CNodeId) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        let CNode::For {
            init,
            cond,
            step,
            body,
        } = self.ast.node(id)
        else {
            return Err(crate::error::Error::UnexpectedAstNode("for statement"));
        };
        let (init, cond, step, body) = (*init, *cond, *step, *body);
        let init = match init {
            Some(i) => Some(self.lower_for_init(cx, i)?),
            None => None,
        };
        let cond = match cond {
            Some(c) => Some(self.lower_expr(cx, c)?),
            None => None,
        };
        let step = match step {
            Some(s) => Some(self.lower_expr(cx, s)?),
            None => None,
        };
        let body = self.lower_block(cx, body)?;
        cx.alloc(
            HirNode::For {
                init,
                cond,
                step,
                body,
            },
            span,
        )
        .map_err(crate::error::Error::from)
    }

    /// Lowers a `for` initialisation clause (an expression statement or a declaration) to a
    /// single HIR node.
    fn lower_for_init(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        self.lower_single_stmt(cx, id)
    }

    fn lower_switch(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        let CNode::Switch { cond, body } = self.ast.node(id) else {
            return Err(crate::error::Error::UnexpectedAstNode("switch statement"));
        };
        let (cond, body) = (*cond, *body);
        let scrutinee = self.lower_expr(cx, cond)?;
        let body = self.lower_block(cx, body)?;
        cx.alloc(HirNode::Switch { scrutinee, body }, span)
            .map_err(crate::error::Error::from)
    }

    /// Lowers a `case`, `default`, or named label, preserving the labelled statement.
    fn lower_labelled(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(id);
        match self.ast.node(id) {
            CNode::Case { value, body } => {
                let (value, body) = (*value, *body);
                let value = self.lower_expr(cx, value)?;
                let body = self.lower_single_stmt(cx, body)?;
                cx.alloc(HirNode::Case { value, body }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::Default { body } => {
                let body = *body;
                let body = self.lower_single_stmt(cx, body)?;
                cx.alloc(HirNode::Default { body }, span)
                    .map_err(crate::error::Error::from)
            }
            CNode::Label { name, body } => {
                let (name, body) = (*name, *body);
                let name = self.lower_symbol(cx, name)?;
                let body = self.lower_single_stmt(cx, body)?;
                cx.alloc(HirNode::Label { name, body }, span)
                    .map_err(crate::error::Error::from)
            }
            _ => Err(crate::error::Error::UnexpectedAstNode("labelled statement")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CLowering;
    use crate::lower::lower;
    use crate::test_utils::{build, dump};
    use stratum_c_ast::{CAst, CNode};
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::HirContext;

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn while_lowers_faithfully() {
        let out = dump("void f(void) { while (1) { } }");
        assert!(out.contains("while"), "got: {out}");
        assert!(
            !out.contains("break"),
            "loop must not synthesise a break: {out}"
        );
    }

    #[test]
    fn do_while_lowers_faithfully() {
        let out = dump("void f(void) { do { } while (1); }");
        assert!(out.contains("do-while"), "got: {out}");
    }

    #[test]
    fn for_lowers_with_all_clauses() {
        let out = dump("void f(void) { for (int i = 0; i < 10; i = i + 1) { } }");
        assert!(out.contains("for"), "got: {out}");
        assert!(out.contains("init"), "got: {out}");
        assert!(out.contains("cond"), "got: {out}");
        assert!(out.contains("step"), "got: {out}");
        assert!(out.contains("body"), "got: {out}");
    }

    #[test]
    fn for_without_optional_clauses_lowers() {
        let out = dump("void f(void) { for (;;) { break; } }");
        assert!(out.contains("for"), "got: {out}");
        assert!(out.contains("body"), "got: {out}");
        assert!(out.contains("break"), "got: {out}");
    }

    #[test]
    fn for_init_with_multiple_declarators_wraps_in_block() {
        let out = dump("void f(void) { for (int i = 0, j = 1; ; ) { } }");
        assert!(out.contains("init\n          block"), "got: {out}");
    }

    #[test]
    fn if_else_lowers_to_conditional() {
        let out = dump("void f(int x) { if (x) { return; } else { return; } }");
        assert!(out.contains("if"));
        assert!(out.contains("then"));
        assert!(out.contains("else"));
    }

    #[test]
    fn if_without_else_and_void_return_lower() {
        let out = dump("void f(int x) { if (x) return; }");
        assert!(out.contains("if"), "got: {out}");
        assert!(out.contains("return"), "got: {out}");
        assert!(!out.contains("else"), "got: {out}");
    }

    #[test]
    fn local_declaration_lowers_to_var() {
        let out = dump("void f(void) { int x; }");
        assert!(out.contains("var x: i32"), "got: {out}");
    }

    #[test]
    fn nested_compound_statement_lowers_to_nested_block() {
        let out = dump("void f(void) { { ; } }");
        assert!(out.contains("block\n      block"), "got: {out}");
    }

    #[test]
    fn switch_case_default_lower_faithfully() {
        let out = dump("void f(int x) { switch (x) { case 1: break; default: break; } }");
        assert!(out.contains("switch"), "got: {out}");
        assert!(out.contains("case"), "got: {out}");
        assert!(out.contains("default"), "got: {out}");
    }

    #[test]
    fn label_and_goto_lower_faithfully() {
        let out = dump("void f(void) { goto end; end: return; }");
        assert!(out.contains("goto end"), "got: {out}");
        assert!(out.contains("label end"), "got: {out}");
    }

    #[test]
    fn continue_in_for_does_not_warn() {
        let ast = build("void f(void) { for (int i = 0; i < 3; i = i + 1) { continue; } }");
        let result = lower(&ast).unwrap();
        assert!(
            result.diagnostics.is_empty(),
            "got: {:?}",
            result.diagnostics
        );
    }

    #[test]
    fn empty_statement_is_preserved() {
        let out = dump("void f(void) { ; }");
        assert!(out.contains("empty-stmt"), "got: {out}");
    }

    #[test]
    fn specialized_statement_lowerers_reject_wrong_node_kind() {
        let mut ast = CAst::new();
        let sym = ast.intern("1").unwrap();
        let literal = ast.alloc(CNode::IntLiteral(sym), span()).unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        assert!(lowering.lower_if(&mut hir, literal).is_err());
        assert!(lowering.lower_while(&mut hir, literal).is_err());
        assert!(lowering.lower_for(&mut hir, literal).is_err());
        assert!(lowering.lower_switch(&mut hir, literal).is_err());
        assert!(lowering.lower_labelled(&mut hir, literal).is_err());
    }

    #[test]
    fn non_statement_node_in_block_lowers_as_expression_statement() {
        let mut ast = CAst::new();
        let sym = ast.intern("1").unwrap();
        let literal = ast.alloc(CNode::IntLiteral(sym), span()).unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        let block = lowering.lower_block(&mut hir, literal).unwrap();
        assert!(hir.dump(block).contains("expr-stmt"));
    }
}
