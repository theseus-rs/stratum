//! A deterministic S-expression dumper for the C AST.
//!
//! The output is intentionally compact and stable so it can be compared against committed
//! snapshot files in integration tests.

use crate::CNodeId;
use crate::alloc_prelude::*;
use crate::node::{CNode, Designator, InitItem};
use crate::tree::CAst;

impl CAst {
    /// Renders the translation-unit root to a stable S-expression string.
    ///
    /// Returns `"<empty>"` when no root has been set.
    #[must_use]
    pub fn dump_root(&self) -> String {
        match self.root() {
            Some(root) => self.dump(root),
            None => "<empty>".to_string(),
        }
    }

    /// Renders the subtree rooted at `id` to a compact S-expression.
    #[must_use]
    pub fn dump(&self, id: CNodeId) -> String {
        match self.node(id) {
            CNode::TranslationUnit(items) => self.sexpr("tu", items),
            CNode::FunctionDef {
                declarator, body, ..
            } => {
                let name = declarator
                    .name
                    .map_or("?", |s| self.resolve(s).unwrap_or("<invalid>"));
                format!("(fn {} {})", name, self.dump(*body))
            }
            CNode::Declaration { declarators, .. } => {
                let mut names = Vec::new();
                for declarator in declarators {
                    let name = declarator
                        .declarator
                        .name
                        .map_or("?", |symbol| self.resolve(symbol).unwrap_or("<invalid>"))
                        .to_string();
                    names.push(match declarator.init {
                        Some(init) => format!("{name}={}", self.dump(init)),
                        None => name,
                    });
                }
                format!("(decl {})", names.join(" "))
            }
            CNode::StaticAssert { cond, message } => {
                let message = message
                    .map(|m| format!(" {:?}", self.resolve(m).unwrap_or("<invalid>")))
                    .unwrap_or_default();
                format!("(static-assert {}{})", self.dump(*cond), message)
            }
            CNode::Compound(items) => self.sexpr("block", items),
            CNode::ExprStmt(Some(e)) => format!("(expr {})", self.dump(*e)),
            CNode::ExprStmt(None) => "(expr)".to_string(),
            CNode::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let els = else_branch.map_or(String::new(), |e| format!(" {}", self.dump(e)));
                format!(
                    "(if {} {}{})",
                    self.dump(*cond),
                    self.dump(*then_branch),
                    els
                )
            }
            CNode::While { cond, body } => {
                format!("(while {} {})", self.dump(*cond), self.dump(*body))
            }
            CNode::DoWhile { body, cond } => {
                format!("(do {} {})", self.dump(*body), self.dump(*cond))
            }
            CNode::For {
                init,
                cond,
                step,
                body,
            } => format!(
                "(for {} {} {} {})",
                self.opt(*init),
                self.opt(*cond),
                self.opt(*step),
                self.dump(*body)
            ),
            CNode::Return(v) => format!("(return {})", self.opt(*v)),
            CNode::Break => "(break)".to_string(),
            CNode::Continue => "(continue)".to_string(),
            CNode::Goto(s) => format!("(goto {})", self.resolve(*s).unwrap_or("<invalid>")),
            CNode::Label { name, body } => {
                format!(
                    "(label {} {})",
                    self.resolve(*name).unwrap_or("<invalid>"),
                    self.dump(*body)
                )
            }
            CNode::Switch { cond, body } => {
                format!("(switch {} {})", self.dump(*cond), self.dump(*body))
            }
            CNode::Case { value, body } => {
                format!("(case {} {})", self.dump(*value), self.dump(*body))
            }
            CNode::Default { body } => format!("(default {})", self.dump(*body)),
            _ => self.dump_expr(id),
        }
    }

    /// Renders an expression node to a compact S-expression.
    ///
    /// If `id` is not an expression node, this returns `"<stmt>"`.
    #[must_use]
    pub fn dump_expr(&self, id: CNodeId) -> String {
        match self.node(id) {
            CNode::Ident(s)
            | CNode::IntLiteral(s)
            | CNode::CharLiteral(s)
            | CNode::FloatLiteral(s) => self.resolve(*s).unwrap_or("<invalid>").to_string(),
            CNode::BoolLiteral(value) => value.to_string(),
            CNode::Nullptr => "nullptr".to_string(),
            CNode::StringLiteral(s) => format!("{:?}", self.resolve(*s).unwrap_or("<invalid>")),
            CNode::Unary { op, operand } => format!("({op:?} {})", self.dump(*operand)),
            CNode::Postfix { op, operand } => format!("({op:?} {})", self.dump(*operand)),
            CNode::Binary { op, lhs, rhs } => {
                format!("({op:?} {} {})", self.dump(*lhs), self.dump(*rhs))
            }
            CNode::Assign { op, target, value } => {
                format!("({op:?} {} {})", self.dump(*target), self.dump(*value))
            }
            CNode::Conditional {
                cond,
                then_expr,
                else_expr,
            } => format!(
                "(?: {} {} {})",
                self.dump(*cond),
                self.dump(*then_expr),
                self.dump(*else_expr)
            ),
            CNode::Comma { lhs, rhs } => {
                format!("(comma {} {})", self.dump(*lhs), self.dump(*rhs))
            }
            CNode::Call { callee, args } => {
                let mut rendered = Vec::new();
                for arg in args {
                    rendered.push(self.dump(*arg));
                }
                format!("(call {} {})", self.dump(*callee), rendered.join(" "))
            }
            CNode::Member { base, field, arrow } => {
                let op = if *arrow { "->" } else { "." };
                format!(
                    "(mem{} {} {})",
                    op,
                    self.dump(*base),
                    self.resolve(*field).unwrap_or("<invalid>")
                )
            }
            CNode::Index { base, index } => {
                format!("(idx {} {})", self.dump(*base), self.dump(*index))
            }
            CNode::Cast { expr, .. } => format!("(cast {})", self.dump(*expr)),
            CNode::SizeofExpr(e) => format!("(sizeof {})", self.dump(*e)),
            CNode::SizeofType(_) => "(sizeof-type)".to_string(),
            CNode::AlignofExpr(e) => format!("(alignof {})", self.dump(*e)),
            CNode::AlignofType(_) => "(alignof-type)".to_string(),
            CNode::GenericSelection {
                controlling,
                associations,
            } => {
                let mut parts = Vec::new();
                for assoc in associations {
                    let key = if assoc.type_name.is_some() {
                        "type"
                    } else {
                        "default"
                    };
                    parts.push(format!("({key} {})", self.dump(assoc.expr)));
                }
                format!("(generic {} {})", self.dump(*controlling), parts.join(" "))
            }
            CNode::InitList(items) => self.dump_init_list(items),
            CNode::CompoundLiteral { init, .. } => format!("(compound-lit {})", self.dump(*init)),
            _ => "<stmt>".to_string(),
        }
    }

    /// Renders a braced initialiser list, including any C99 designators.
    fn dump_init_list(&self, items: &[InitItem]) -> String {
        let mut parts = Vec::new();
        for item in items {
            parts.push(self.dump_init_item(item));
        }
        format!("(init {})", parts.join(" "))
    }

    fn dump_init_item(&self, item: &InitItem) -> String {
        let value = self.dump(item.value);
        if item.designators.is_empty() {
            return value;
        }
        let mut designators = String::new();
        for designator in &item.designators {
            match designator {
                Designator::Field(name) => {
                    let name = self.resolve(*name).unwrap_or("<invalid>");
                    designators.push('.');
                    designators.push_str(name);
                }
                Designator::Index(expr) => {
                    let expr = self.dump(*expr);
                    designators.push('[');
                    designators.push_str(&expr);
                    designators.push(']');
                }
            }
        }
        format!("{designators}={value}")
    }

    fn opt(&self, id: Option<CNodeId>) -> String {
        match id {
            Some(id) => self.dump(id),
            None => "_".to_string(),
        }
    }

    fn sexpr(&self, head: &str, items: &[CNodeId]) -> String {
        let mut parts = Vec::new();
        for item in items {
            parts.push(self.dump(*item));
        }
        format!("({} {})", head, parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use crate::alloc_prelude::*;
    use crate::{CAst, CNode, DeclSpecifiers, Declarator, Designator, InitDeclarator, InitItem};
    use stratum_diagnostics::{FileId, Span};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn empty_ast_dumps_as_empty() {
        assert_eq!(CAst::new().dump_root(), "<empty>");
    }

    #[test]
    fn dumping_statement_as_expression_uses_fallback() {
        let mut ast = CAst::new();
        let stmt = ast
            .alloc(CNode::Break, Span::point(FileId::from_raw(0), 0))
            .unwrap();
        assert_eq!(ast.dump_expr(stmt), "<stmt>");
    }

    #[test]
    fn dumps_optional_and_invalid_symbol_paths() {
        let mut ast = CAst::new();
        let one = ast.intern("1").unwrap();
        let one = ast.alloc(CNode::IntLiteral(one), span()).unwrap();
        let decl = ast
            .alloc(
                CNode::Declaration {
                    specifiers: DeclSpecifiers::default(),
                    declarators: vec![InitDeclarator {
                        declarator: Declarator::default(),
                        init: None,
                    }],
                },
                span(),
            )
            .unwrap();
        let static_assert = ast
            .alloc(
                CNode::StaticAssert {
                    cond: one,
                    message: None,
                },
                span(),
            )
            .unwrap();
        let empty_expr = ast.alloc(CNode::ExprStmt(None), span()).unwrap();
        let field = ast.intern("field").unwrap();
        let init = ast
            .alloc(
                CNode::InitList(vec![InitItem {
                    designators: vec![Designator::Field(field)],
                    value: one,
                }]),
                span(),
            )
            .unwrap();
        let return_one = ast.alloc(CNode::Return(Some(one)), span()).unwrap();
        let if_without_else = ast
            .alloc(
                CNode::If {
                    cond: one,
                    then_branch: empty_expr,
                    else_branch: None,
                },
                span(),
            )
            .unwrap();
        let function_name = ast.intern("f").unwrap();
        let function_body = ast
            .alloc(CNode::Compound(vec![return_one]), span())
            .unwrap();
        let function = ast
            .alloc(
                CNode::FunctionDef {
                    specifiers: DeclSpecifiers::default(),
                    declarator: Declarator {
                        name: Some(function_name),
                        derivations: Vec::new(),
                    },
                    body: function_body,
                },
                span(),
            )
            .unwrap();
        let root = ast
            .alloc(
                CNode::TranslationUnit(vec![decl, static_assert, init, if_without_else, function]),
                span(),
            )
            .unwrap();
        ast.set_root(root);

        assert_eq!(
            ast.dump_root(),
            "(tu (decl ?) (static-assert 1) (init .field=1) (if 1 (expr)) (fn f (block (return 1))))"
        );
    }
}
