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
                let names: Vec<String> = declarators
                    .iter()
                    .map(|d| {
                        let n = d
                            .declarator
                            .name
                            .map_or("?", |s| self.resolve(s).unwrap_or("<invalid>"))
                            .to_string();
                        match d.init {
                            Some(init) => format!("{}={}", n, self.dump(init)),
                            None => n,
                        }
                    })
                    .collect();
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
    fn dump_expr(&self, id: CNodeId) -> String {
        match self.node(id) {
            CNode::Ident(s) => self.resolve(*s).unwrap_or("<invalid>").to_string(),
            CNode::IntLiteral(s) | CNode::CharLiteral(s) | CNode::FloatLiteral(s) => {
                self.resolve(*s).unwrap_or("<invalid>").to_string()
            }
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
                let a: Vec<String> = args.iter().map(|x| self.dump(*x)).collect();
                format!("(call {} {})", self.dump(*callee), a.join(" "))
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
                let parts: Vec<String> = associations
                    .iter()
                    .map(|assoc| {
                        let key = if assoc.type_name.is_some() {
                            "type"
                        } else {
                            "default"
                        };
                        format!("({key} {})", self.dump(assoc.expr))
                    })
                    .collect();
                format!("(generic {} {})", self.dump(*controlling), parts.join(" "))
            }
            CNode::InitList(items) => self.dump_init_list(items),
            CNode::CompoundLiteral { init, .. } => format!("(compound-lit {})", self.dump(*init)),
            _ => "<stmt>".to_string(),
        }
    }

    /// Renders a braced initialiser list, including any C99 designators.
    fn dump_init_list(&self, items: &[InitItem]) -> String {
        let parts: Vec<String> = items.iter().map(|item| self.dump_init_item(item)).collect();
        format!("(init {})", parts.join(" "))
    }

    fn dump_init_item(&self, item: &InitItem) -> String {
        let value = self.dump(item.value);
        if item.designators.is_empty() {
            return value;
        }
        let designators: String = item
            .designators
            .iter()
            .map(|d| match d {
                Designator::Field(name) => {
                    format!(".{}", self.resolve(*name).unwrap_or("<invalid>"))
                }
                Designator::Index(expr) => format!("[{}]", self.dump(*expr)),
            })
            .collect();
        format!("{designators}={value}")
    }

    fn opt(&self, id: Option<CNodeId>) -> String {
        id.map_or_else(|| "_".to_string(), |i| self.dump(i))
    }

    fn sexpr(&self, head: &str, items: &[CNodeId]) -> String {
        let parts: Vec<String> = items.iter().map(|i| self.dump(*i)).collect();
        format!("({} {})", head, parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use crate::{CAst, CNode};
    use stratum_diagnostics::{FileId, Span};

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
}
