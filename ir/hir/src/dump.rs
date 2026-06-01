//! Deterministic textual rendering of the HIR, for debugging and snapshot tests.

use crate::alloc_prelude::*;
use crate::context::{HirContext, HirNodeId, HirTypeId};
use crate::node::{DeclFlags, Designator, HirInit, HirNode, InitEntry};
use crate::types::HirType;
use core::fmt::Write as _;

impl HirContext {
    /// Renders the program rooted at [`root`](HirContext::root) to a stable, indented form.
    ///
    /// Returns `"<empty>\n"` when no root has been set. The output format is deliberately
    /// simple and deterministic so it can be compared against committed snapshot files.
    #[must_use]
    pub fn dump_root(&self) -> String {
        match self.root() {
            Some(root) => self.dump(root),
            None => "<empty>\n".to_string(),
        }
    }

    /// Renders the subtree rooted at `id` to a stable, indented string.
    #[must_use]
    pub fn dump(&self, id: HirNodeId) -> String {
        let mut out = String::new();
        self.dump_node(id, 0, &mut out);
        out
    }

    fn indent(out: &mut String, depth: usize) {
        for _ in 0..depth {
            out.push_str("  ");
        }
    }

    fn dump_node(&self, id: HirNodeId, depth: usize, out: &mut String) {
        match self.node(id) {
            HirNode::Module(_)
            | HirNode::Function { .. }
            | HirNode::Var { .. }
            | HirNode::TypeAlias { .. }
            | HirNode::Record { .. }
            | HirNode::Enumeration { .. } => self.dump_item(id, depth, out),
            HirNode::Block(_)
            | HirNode::Conditional { .. }
            | HirNode::While { .. }
            | HirNode::DoWhile { .. }
            | HirNode::For { .. }
            | HirNode::Switch { .. }
            | HirNode::Case { .. }
            | HirNode::Default { .. }
            | HirNode::Label { .. }
            | HirNode::Goto(_)
            | HirNode::Break
            | HirNode::Continue
            | HirNode::Return(_)
            | HirNode::ExprStmt(_) => self.dump_stmt(id, depth, out),
            _ => self.dump_expr(id, depth, out),
        }
    }

    fn dump_item(&self, id: HirNodeId, depth: usize, out: &mut String) {
        Self::indent(out, depth);
        match self.node(id) {
            HirNode::Module(items) => {
                out.push_str("module\n");
                self.dump_children(items, depth + 1, out);
            }
            HirNode::Function { .. } => self.dump_function(id, depth, out),
            HirNode::Var {
                name,
                ty,
                flags,
                init,
            } => {
                let _ = writeln!(
                    out,
                    "{}var {}: {}",
                    flags_prefix(*flags),
                    self.resolve(*name).unwrap_or("<invalid>"),
                    self.type_to_string(*ty)
                );
                if let Some(init) = init {
                    self.dump_init(init, depth + 1, out);
                }
            }
            HirNode::TypeAlias { name, ty } => {
                let _ = writeln!(
                    out,
                    "typedef {} = {}",
                    self.resolve(*name).unwrap_or("<invalid>"),
                    self.type_to_string(*ty)
                );
            }
            HirNode::Record { kind, tag, fields } => {
                let tag = tag.map_or("<anonymous>", |t| self.resolve(t).unwrap_or("<invalid>"));
                let _ = writeln!(out, "{} {tag}", kind.spelling());
                for field in fields {
                    Self::indent(out, depth + 1);
                    let fname = field
                        .name
                        .map_or("<unnamed>", |n| self.resolve(n).unwrap_or("<invalid>"));
                    let _ = write!(out, "field {fname}: {}", self.type_to_string(field.ty));
                    if let Some(width) = field.bit_width {
                        out.push_str(" : ");
                        let mut tmp = String::new();
                        self.dump_node(width, 0, &mut tmp);
                        out.push_str(tmp.trim_end());
                    }
                    out.push('\n');
                }
            }
            HirNode::Enumeration { tag, variants } => {
                let tag = tag.map_or("<anonymous>", |t| self.resolve(t).unwrap_or("<invalid>"));
                let _ = writeln!(out, "enum {tag}");
                for variant in variants {
                    Self::indent(out, depth + 1);
                    let _ = writeln!(
                        out,
                        "variant {}",
                        self.resolve(variant.name).unwrap_or("<invalid>")
                    );
                    if let Some(value) = variant.value {
                        self.dump_node(value, depth + 2, out);
                    }
                }
            }
            _ => out.push_str("<invalid-item>\n"),
        }
    }

    fn dump_stmt(&self, id: HirNodeId, depth: usize, out: &mut String) {
        Self::indent(out, depth);
        match self.node(id) {
            HirNode::Block(stmts) => {
                out.push_str("block\n");
                self.dump_children(stmts, depth + 1, out);
            }
            HirNode::Conditional { .. } => self.dump_conditional(id, depth, out),
            HirNode::While { cond, body } => {
                out.push_str("while\n");
                self.dump_node(*cond, depth + 1, out);
                self.dump_node(*body, depth + 1, out);
            }
            HirNode::DoWhile { body, cond } => {
                out.push_str("do-while\n");
                self.dump_node(*body, depth + 1, out);
                self.dump_node(*cond, depth + 1, out);
            }
            HirNode::For { .. } => self.dump_for(id, depth, out),
            HirNode::Switch { scrutinee, body } => {
                out.push_str("switch\n");
                self.dump_node(*scrutinee, depth + 1, out);
                self.dump_node(*body, depth + 1, out);
            }
            HirNode::Case { value, body } => {
                out.push_str("case\n");
                self.dump_node(*value, depth + 1, out);
                self.dump_node(*body, depth + 1, out);
            }
            HirNode::Default { body } => {
                out.push_str("default\n");
                self.dump_node(*body, depth + 1, out);
            }
            HirNode::Label { name, body } => {
                let _ = writeln!(out, "label {}", self.resolve(*name).unwrap_or("<invalid>"));
                self.dump_node(*body, depth + 1, out);
            }
            HirNode::Goto(name) => {
                let _ = writeln!(out, "goto {}", self.resolve(*name).unwrap_or("<invalid>"));
            }
            HirNode::Break => out.push_str("break\n"),
            HirNode::Continue => out.push_str("continue\n"),
            HirNode::Return(value) => {
                out.push_str("return\n");
                if let Some(value) = value {
                    self.dump_node(*value, depth + 1, out);
                }
            }
            HirNode::ExprStmt(None) => out.push_str("empty-stmt\n"),
            HirNode::ExprStmt(Some(expr)) => {
                out.push_str("expr-stmt\n");
                self.dump_node(*expr, depth + 1, out);
            }
            _ => out.push_str("<invalid-stmt>\n"),
        }
    }

    fn dump_expr(&self, id: HirNodeId, depth: usize, out: &mut String) {
        Self::indent(out, depth);
        match self.node(id) {
            HirNode::Assign { op, target, value } => {
                match op {
                    Some(op) => {
                        let _ = writeln!(out, "assign `{}=`", op.symbol());
                    }
                    None => out.push_str("assign\n"),
                }
                self.dump_node(*target, depth + 1, out);
                self.dump_node(*value, depth + 1, out);
            }
            HirNode::Binary { op, lhs, rhs } => {
                let _ = writeln!(out, "binary `{}`", op.symbol());
                self.dump_node(*lhs, depth + 1, out);
                self.dump_node(*rhs, depth + 1, out);
            }
            HirNode::Unary { op, operand } => {
                let _ = writeln!(out, "unary `{}`", op.symbol());
                self.dump_node(*operand, depth + 1, out);
            }
            HirNode::Postfix { op, operand } => {
                let _ = writeln!(out, "postfix `{}`", op.symbol());
                self.dump_node(*operand, depth + 1, out);
            }
            HirNode::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                out.push_str("ternary\n");
                self.dump_node(*cond, depth + 1, out);
                self.dump_node(*then_expr, depth + 1, out);
                self.dump_node(*else_expr, depth + 1, out);
            }
            HirNode::Call { callee, args } => {
                out.push_str("call\n");
                self.dump_node(*callee, depth + 1, out);
                self.dump_children(args, depth + 1, out);
            }
            HirNode::Member { base, field, arrow } => {
                let arrow = if *arrow { "->" } else { "." };
                let _ = writeln!(
                    out,
                    "member {arrow}{}",
                    self.resolve(*field).unwrap_or("<invalid>")
                );
                self.dump_node(*base, depth + 1, out);
            }
            HirNode::Index { base, index } => {
                out.push_str("index\n");
                self.dump_node(*base, depth + 1, out);
                self.dump_node(*index, depth + 1, out);
            }
            HirNode::Cast { ty, operand } => {
                let _ = writeln!(out, "cast {}", self.type_to_string(*ty));
                self.dump_node(*operand, depth + 1, out);
            }
            HirNode::Comma { lhs, rhs } => {
                out.push_str("comma\n");
                self.dump_node(*lhs, depth + 1, out);
                self.dump_node(*rhs, depth + 1, out);
            }
            HirNode::SizeofExpr(operand) => {
                out.push_str("sizeof-expr\n");
                self.dump_node(*operand, depth + 1, out);
            }
            HirNode::SizeofType(ty) => {
                let _ = writeln!(out, "sizeof-type {}", self.type_to_string(*ty));
            }
            HirNode::CompoundLiteral { ty, init } => {
                let _ = writeln!(out, "compound-literal {}", self.type_to_string(*ty));
                self.dump_init(init, depth + 1, out);
            }
            HirNode::Name(_)
            | HirNode::IntLiteral(_)
            | HirNode::FloatLiteral(_)
            | HirNode::StringLiteral(_)
            | HirNode::CharLiteral(_) => self.dump_leaf_expr(id, out),
            _ => out.push_str("<invalid-expr>\n"),
        }
    }

    fn dump_leaf_expr(&self, id: HirNodeId, out: &mut String) {
        match self.node(id) {
            HirNode::Name(symbol) => {
                let _ = writeln!(
                    out,
                    "name `{}`",
                    self.resolve(*symbol).unwrap_or("<invalid>")
                );
            }
            HirNode::IntLiteral(value) => {
                let _ = writeln!(out, "int {value}");
            }
            HirNode::FloatLiteral(symbol) => {
                let _ = writeln!(
                    out,
                    "float {}",
                    self.resolve(*symbol).unwrap_or("<invalid>")
                );
            }
            HirNode::StringLiteral(symbol) => {
                let _ = writeln!(
                    out,
                    "string {:?}",
                    self.resolve(*symbol).unwrap_or("<invalid>")
                );
            }
            HirNode::CharLiteral(value) => {
                let _ = writeln!(out, "char {value}");
            }
            _ => out.push_str("<invalid-expr>\n"),
        }
    }

    fn dump_init(&self, init: &HirInit, depth: usize, out: &mut String) {
        match init {
            HirInit::Expr(expr) => self.dump_node(*expr, depth, out),
            HirInit::List(entries) => {
                Self::indent(out, depth);
                out.push_str("init-list\n");
                for entry in entries {
                    self.dump_init_entry(entry, depth + 1, out);
                }
            }
        }
    }

    fn dump_init_entry(&self, entry: &InitEntry, depth: usize, out: &mut String) {
        for designator in &entry.designators {
            Self::indent(out, depth);
            match designator {
                Designator::Field(field) => {
                    let _ = writeln!(
                        out,
                        "designator .{}",
                        self.resolve(*field).unwrap_or("<invalid>")
                    );
                }
                Designator::Index(index) => {
                    out.push_str("designator []\n");
                    self.dump_node(*index, depth + 1, out);
                }
            }
        }
        self.dump_init(&entry.value, depth, out);
    }

    fn dump_children(&self, children: &[HirNodeId], depth: usize, out: &mut String) {
        for child in children {
            self.dump_node(*child, depth, out);
        }
    }

    fn dump_function(&self, id: HirNodeId, depth: usize, out: &mut String) {
        let HirNode::Function {
            name,
            params,
            ret,
            variadic,
            flags,
            body,
        } = self.node(id)
        else {
            return;
        };
        let _ = write!(
            out,
            "{}function {}(",
            flags_prefix(*flags),
            self.resolve(*name).unwrap_or("<invalid>")
        );
        for (index, param) in params.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            match param.name {
                Some(pname) => {
                    let _ = write!(
                        out,
                        "{}: {}",
                        self.resolve(pname).unwrap_or("<invalid>"),
                        self.type_to_string(param.ty)
                    );
                }
                None => out.push_str(&self.type_to_string(param.ty)),
            }
        }
        if *variadic {
            if params.is_empty() {
                out.push_str("...");
            } else {
                out.push_str(", ...");
            }
        }
        let _ = writeln!(out, ") -> {}", self.type_to_string(*ret));
        if let Some(body) = body {
            self.dump_node(*body, depth + 1, out);
        }
    }

    fn dump_conditional(&self, id: HirNodeId, depth: usize, out: &mut String) {
        let HirNode::Conditional {
            cond,
            then_block,
            else_block,
        } = self.node(id)
        else {
            return;
        };
        out.push_str("if\n");
        self.dump_node(*cond, depth + 1, out);
        Self::indent(out, depth);
        out.push_str("then\n");
        self.dump_node(*then_block, depth + 1, out);
        if let Some(else_block) = else_block {
            Self::indent(out, depth);
            out.push_str("else\n");
            self.dump_node(*else_block, depth + 1, out);
        }
    }

    fn dump_for(&self, id: HirNodeId, depth: usize, out: &mut String) {
        let HirNode::For {
            init,
            cond,
            step,
            body,
        } = self.node(id)
        else {
            return;
        };
        out.push_str("for\n");
        self.dump_for_clause("init", *init, depth, out);
        self.dump_for_clause("cond", *cond, depth, out);
        self.dump_for_clause("step", *step, depth, out);
        Self::indent(out, depth + 1);
        out.push_str("body\n");
        self.dump_node(*body, depth + 2, out);
    }

    fn dump_for_clause(
        &self,
        label: &str,
        clause: Option<HirNodeId>,
        depth: usize,
        out: &mut String,
    ) {
        Self::indent(out, depth + 1);
        let _ = writeln!(out, "{label}");
        if let Some(clause) = clause {
            self.dump_node(clause, depth + 2, out);
        }
    }

    /// Formats a type to a stable single-line string.
    #[must_use]
    pub fn type_to_string(&self, id: HirTypeId) -> String {
        match self.ty(id) {
            HirType::Void => "void".to_string(),
            HirType::Bool => "bool".to_string(),
            HirType::Int { signed, width } => {
                format!("{}{}", if *signed { "i" } else { "u" }, width.bits())
            }
            HirType::Float { bits } => format!("f{bits}"),
            HirType::Pointer(inner) => format!("*{}", self.type_to_string(*inner)),
            HirType::Array { element, length } => match length {
                Some(length) => format!("[{}; {}]", self.type_to_string(*element), length),
                None => format!("[{}]", self.type_to_string(*element)),
            },
            HirType::Function {
                params,
                ret,
                variadic,
            } => self.function_type_to_string(params, *ret, *variadic),
            HirType::Qualified { inner, qualifiers } => {
                let mut prefix = String::new();
                if qualifiers.is_const {
                    prefix.push_str("const ");
                }
                if qualifiers.is_volatile {
                    prefix.push_str("volatile ");
                }
                if qualifiers.is_restrict {
                    prefix.push_str("restrict ");
                }
                if qualifiers.is_atomic {
                    prefix.push_str("_Atomic ");
                }
                format!("{prefix}{}", self.type_to_string(*inner))
            }
            HirType::Tag { kind, name } => {
                let name = name.map_or("<anonymous>", |n| self.resolve(n).unwrap_or("<invalid>"));
                format!("{} {name}", kind.spelling())
            }
            HirType::Named(symbol) => self.resolve(*symbol).unwrap_or("<invalid>").to_string(),
        }
    }

    fn function_type_to_string(
        &self,
        params: &[HirTypeId],
        ret: HirTypeId,
        variadic: bool,
    ) -> String {
        let mut out = String::from("fn(");
        for (index, param) in params.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            out.push_str(&self.type_to_string(*param));
        }
        if variadic {
            out.push_str(if params.is_empty() { "..." } else { ", ..." });
        }
        let _ = write!(out, ") -> {}", self.type_to_string(ret));
        out
    }
}

/// Renders declaration flags as a trailing-space prefix (e.g. `"static "`).
fn flags_prefix(flags: DeclFlags) -> String {
    let mut prefix = String::new();
    if let Some(storage) = flags.storage {
        prefix.push_str(storage.spelling());
        prefix.push(' ');
    }
    if flags.inline {
        prefix.push_str("inline ");
    }
    if flags.noreturn {
        prefix.push_str("_Noreturn ");
    }
    prefix
}

#[cfg(test)]
mod tests {
    use crate::alloc_prelude::*;
    use crate::context::HirContext;
    use crate::node::{
        BinaryOp, DeclFlags, Designator, EnumVariant, Field, HirInit, HirNode, InitEntry, Param,
        PostfixOp, RecordKind, StorageClass, UnaryOp,
    };
    use crate::types::{HirType, IntWidth, Qualifiers, TagKind};
    use stratum_diagnostics::{SourceMap, Span};

    fn span() -> Span {
        let mut map = SourceMap::new();
        let file = map.add_root("t.c", "int main(void){return 0;}").unwrap();
        Span::new(file, 0, 1)
    }

    #[test]
    fn dumps_binary_operator() {
        let s = span();
        let mut hir = HirContext::new();
        let one = hir.alloc(HirNode::IntLiteral(1), s).unwrap();
        let two = hir.alloc(HirNode::IntLiteral(2), s).unwrap();
        let add = hir
            .alloc(
                HirNode::Binary {
                    op: BinaryOp::Add,
                    lhs: one,
                    rhs: two,
                },
                s,
            )
            .unwrap();
        assert_eq!(hir.dump(add), "binary `+`\n  int 1\n  int 2\n");
    }

    #[test]
    fn dumps_function_with_root() {
        let s = span();
        let mut hir = HirContext::new();
        let i32_ty = hir
            .alloc_type(HirType::Int {
                signed: true,
                width: IntWidth::W32,
            })
            .unwrap();
        let zero = hir.alloc(HirNode::IntLiteral(0), s).unwrap();
        let ret = hir.alloc(HirNode::Return(Some(zero)), s).unwrap();
        let body = hir.alloc(HirNode::Block(vec![ret]), s).unwrap();
        let name = hir.intern("main").unwrap();
        let func = hir
            .alloc(
                HirNode::Function {
                    name,
                    params: Vec::<Param>::new(),
                    ret: i32_ty,
                    variadic: false,
                    flags: DeclFlags::default(),
                    body: Some(body),
                },
                s,
            )
            .unwrap();
        let module = hir.alloc(HirNode::Module(vec![func]), s).unwrap();
        hir.set_root(module);
        let expected = "\
module
  function main() -> i32
    block
      return
        int 0
";
        assert_eq!(hir.dump_root(), expected);
    }

    #[test]
    fn empty_context_dump() {
        let hir = HirContext::new();
        assert_eq!(hir.dump_root(), "<empty>\n");
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "coverage fixture intentionally constructs every HIR node and type shape"
    )]
    fn dumps_all_node_families_and_type_shapes() {
        let s = span();
        let mut hir = HirContext::new();
        let name = hir.intern("name").unwrap();
        let field = hir.intern("field").unwrap();
        let alias = hir.intern("Alias").unwrap();

        let void = hir.alloc_type(HirType::Void).unwrap();
        let bool_ty = hir.alloc_type(HirType::Bool).unwrap();
        let i32_ty = hir
            .alloc_type(HirType::Int {
                signed: true,
                width: IntWidth::W32,
            })
            .unwrap();
        let u16_ty = hir
            .alloc_type(HirType::Int {
                signed: false,
                width: IntWidth::W16,
            })
            .unwrap();
        let f32_ty = hir.alloc_type(HirType::Float { bits: 32 }).unwrap();
        let ptr_ty = hir.alloc_type(HirType::Pointer(i32_ty)).unwrap();
        let array_ty = hir
            .alloc_type(HirType::Array {
                element: i32_ty,
                length: Some(3),
            })
            .unwrap();
        let unsized_array_ty = hir
            .alloc_type(HirType::Array {
                element: i32_ty,
                length: None,
            })
            .unwrap();
        let fn_ty = hir
            .alloc_type(HirType::Function {
                params: vec![i32_ty, ptr_ty],
                ret: void,
                variadic: true,
            })
            .unwrap();
        let empty_variadic_fn_ty = hir
            .alloc_type(HirType::Function {
                params: Vec::new(),
                ret: void,
                variadic: true,
            })
            .unwrap();
        let plain_fn_ty = hir
            .alloc_type(HirType::Function {
                params: Vec::new(),
                ret: void,
                variadic: false,
            })
            .unwrap();
        let qualified_ty = hir
            .alloc_type(HirType::Qualified {
                inner: ptr_ty,
                qualifiers: Qualifiers {
                    is_const: true,
                    is_volatile: true,
                    is_restrict: true,
                    is_atomic: true,
                },
            })
            .unwrap();
        let tag_ty = hir
            .alloc_type(HirType::Tag {
                kind: TagKind::Struct,
                name: Some(name),
            })
            .unwrap();
        let anon_tag_ty = hir
            .alloc_type(HirType::Tag {
                kind: TagKind::Union,
                name: None,
            })
            .unwrap();
        let enum_tag_ty = hir
            .alloc_type(HirType::Tag {
                kind: TagKind::Enum,
                name: Some(name),
            })
            .unwrap();
        let named_ty = hir.alloc_type(HirType::Named(alias)).unwrap();

        assert_eq!(hir.type_to_string(bool_ty), "bool");
        assert_eq!(hir.type_to_string(u16_ty), "u16");
        assert_eq!(hir.type_to_string(f32_ty), "f32");
        assert_eq!(hir.type_to_string(array_ty), "[i32; 3]");
        assert_eq!(hir.type_to_string(unsized_array_ty), "[i32]");
        assert_eq!(hir.type_to_string(fn_ty), "fn(i32, *i32, ...) -> void");
        assert_eq!(hir.type_to_string(empty_variadic_fn_ty), "fn(...) -> void");
        assert_eq!(hir.type_to_string(plain_fn_ty), "fn() -> void");
        assert_eq!(
            hir.type_to_string(qualified_ty),
            "const volatile restrict _Atomic *i32"
        );
        assert_eq!(hir.type_to_string(tag_ty), "struct name");
        assert_eq!(hir.type_to_string(anon_tag_ty), "union <anonymous>");
        assert_eq!(hir.type_to_string(enum_tag_ty), "enum name");
        assert_eq!(hir.type_to_string(named_ty), "Alias");

        let one = hir.alloc(HirNode::IntLiteral(1), s).unwrap();
        let two = hir.alloc(HirNode::IntLiteral(2), s).unwrap();
        let flt = hir.alloc(HirNode::FloatLiteral(name), s).unwrap();
        let string = hir.alloc(HirNode::StringLiteral(name), s).unwrap();
        let ch = hir.alloc(HirNode::CharLiteral(65), s).unwrap();
        let var_init = HirInit::List(vec![InitEntry {
            designators: vec![Designator::Field(field), Designator::Index(one)],
            value: HirInit::Expr(two),
        }]);

        let var = hir
            .alloc(
                HirNode::Var {
                    name,
                    ty: qualified_ty,
                    flags: DeclFlags {
                        storage: Some(StorageClass::Static),
                        inline: true,
                        noreturn: true,
                    },
                    init: Some(var_init.clone()),
                },
                s,
            )
            .unwrap();
        let type_alias = hir
            .alloc(
                HirNode::TypeAlias {
                    name: alias,
                    ty: named_ty,
                },
                s,
            )
            .unwrap();
        let record = hir
            .alloc(
                HirNode::Record {
                    kind: RecordKind::Struct,
                    tag: Some(name),
                    fields: vec![Field {
                        name: Some(field),
                        ty: i32_ty,
                        bit_width: Some(one),
                    }],
                },
                s,
            )
            .unwrap();
        let union = hir
            .alloc(
                HirNode::Record {
                    kind: RecordKind::Union,
                    tag: None,
                    fields: vec![Field {
                        name: None,
                        ty: i32_ty,
                        bit_width: None,
                    }],
                },
                s,
            )
            .unwrap();
        let enumeration = hir
            .alloc(
                HirNode::Enumeration {
                    tag: Some(name),
                    variants: vec![EnumVariant {
                        name,
                        value: Some(two),
                    }],
                },
                s,
            )
            .unwrap();
        let empty = hir.alloc(HirNode::ExprStmt(None), s).unwrap();
        let ret = hir.alloc(HirNode::Return(None), s).unwrap();
        let block = hir.alloc(HirNode::Block(vec![empty, ret]), s).unwrap();
        let cond = hir
            .alloc(
                HirNode::Conditional {
                    cond: one,
                    then_block: block,
                    else_block: Some(block),
                },
                s,
            )
            .unwrap();
        let while_node = hir
            .alloc(
                HirNode::While {
                    cond: one,
                    body: block,
                },
                s,
            )
            .unwrap();
        let do_node = hir
            .alloc(
                HirNode::DoWhile {
                    body: block,
                    cond: one,
                },
                s,
            )
            .unwrap();
        let for_node = hir
            .alloc(
                HirNode::For {
                    init: Some(empty),
                    cond: Some(one),
                    step: Some(two),
                    body: block,
                },
                s,
            )
            .unwrap();
        let case = hir
            .alloc(
                HirNode::Case {
                    value: one,
                    body: empty,
                },
                s,
            )
            .unwrap();
        let default = hir.alloc(HirNode::Default { body: empty }, s).unwrap();
        let label = hir.alloc(HirNode::Label { name, body: empty }, s).unwrap();
        let switch_body = hir
            .alloc(HirNode::Block(vec![case, default, label]), s)
            .unwrap();
        let switch = hir
            .alloc(
                HirNode::Switch {
                    scrutinee: one,
                    body: switch_body,
                },
                s,
            )
            .unwrap();
        let goto = hir.alloc(HirNode::Goto(name), s).unwrap();
        let break_node = hir.alloc(HirNode::Break, s).unwrap();
        let continue_node = hir.alloc(HirNode::Continue, s).unwrap();

        let assign = hir
            .alloc(
                HirNode::Assign {
                    op: Some(BinaryOp::Add),
                    target: one,
                    value: two,
                },
                s,
            )
            .unwrap();
        let plain_assign = hir
            .alloc(
                HirNode::Assign {
                    op: None,
                    target: one,
                    value: two,
                },
                s,
            )
            .unwrap();
        let unary = hir
            .alloc(
                HirNode::Unary {
                    op: UnaryOp::Not,
                    operand: one,
                },
                s,
            )
            .unwrap();
        let postfix = hir
            .alloc(
                HirNode::Postfix {
                    op: PostfixOp::Dec,
                    operand: one,
                },
                s,
            )
            .unwrap();
        let ternary = hir
            .alloc(
                HirNode::Ternary {
                    cond: one,
                    then_expr: two,
                    else_expr: ch,
                },
                s,
            )
            .unwrap();
        let callee = hir.alloc(HirNode::Name(name), s).unwrap();
        let call = hir
            .alloc(
                HirNode::Call {
                    callee,
                    args: vec![one, two],
                },
                s,
            )
            .unwrap();
        let member = hir
            .alloc(
                HirNode::Member {
                    base: one,
                    field,
                    arrow: true,
                },
                s,
            )
            .unwrap();
        let dot_member = hir
            .alloc(
                HirNode::Member {
                    base: one,
                    field,
                    arrow: false,
                },
                s,
            )
            .unwrap();
        let index = hir
            .alloc(
                HirNode::Index {
                    base: one,
                    index: two,
                },
                s,
            )
            .unwrap();
        let cast_node = hir
            .alloc(
                HirNode::Cast {
                    ty: i32_ty,
                    operand: one,
                },
                s,
            )
            .unwrap();
        let comma = hir.alloc(HirNode::Comma { lhs: one, rhs: two }, s).unwrap();
        let sizeof_expr = hir.alloc(HirNode::SizeofExpr(one), s).unwrap();
        let sizeof_type = hir.alloc(HirNode::SizeofType(ptr_ty), s).unwrap();
        let compound = hir
            .alloc(
                HirNode::CompoundLiteral {
                    ty: array_ty,
                    init: var_init,
                },
                s,
            )
            .unwrap();
        let expr_stmt = hir.alloc(HirNode::ExprStmt(Some(assign)), s).unwrap();
        let func = hir
            .alloc(
                HirNode::Function {
                    name,
                    params: vec![
                        Param {
                            name: Some(name),
                            ty: i32_ty,
                        },
                        Param {
                            name: None,
                            ty: ptr_ty,
                        },
                    ],
                    ret: void,
                    variadic: true,
                    flags: DeclFlags {
                        storage: Some(StorageClass::Extern),
                        inline: false,
                        noreturn: false,
                    },
                    body: None,
                },
                s,
            )
            .unwrap();
        let variadic_no_params = hir
            .alloc(
                HirNode::Function {
                    name,
                    params: Vec::new(),
                    ret: void,
                    variadic: true,
                    flags: DeclFlags {
                        storage: Some(StorageClass::Auto),
                        inline: false,
                        noreturn: false,
                    },
                    body: None,
                },
                s,
            )
            .unwrap();
        let module = hir
            .alloc(
                HirNode::Module(vec![
                    var,
                    type_alias,
                    record,
                    union,
                    enumeration,
                    func,
                    variadic_no_params,
                    cond,
                    while_node,
                    do_node,
                    for_node,
                    switch,
                    goto,
                    break_node,
                    continue_node,
                    expr_stmt,
                    plain_assign,
                    unary,
                    postfix,
                    ternary,
                    call,
                    member,
                    dot_member,
                    index,
                    cast_node,
                    comma,
                    sizeof_expr,
                    sizeof_type,
                    compound,
                    flt,
                    string,
                ]),
                s,
            )
            .unwrap();

        let dump = hir.dump(module);
        assert!(dump.contains("static inline _Noreturn var name"));
        assert!(dump.contains("extern function name"));
        assert!(dump.contains("auto function name(...)"));
        assert!(dump.contains("member ->field"));
        assert!(dump.contains("member .field"));
        assert!(dump.contains("compound-literal [i32; 3]"));
    }

    #[test]
    fn invalid_private_dump_entry_points_are_labelled() {
        let s = span();
        let mut hir = HirContext::new();
        let lit = hir.alloc(HirNode::IntLiteral(1), s).unwrap();
        let module = hir.alloc(HirNode::Module(Vec::new()), s).unwrap();
        let mut out = String::new();

        hir.dump_item(lit, 0, &mut out);
        hir.dump_stmt(lit, 0, &mut out);
        hir.dump_expr(module, 0, &mut out);
        hir.dump_leaf_expr(module, &mut out);
        hir.dump_function(lit, 0, &mut out);
        hir.dump_conditional(lit, 0, &mut out);
        hir.dump_for(lit, 0, &mut out);

        assert!(out.contains("<invalid-item>"));
        assert!(out.contains("<invalid-stmt>"));
        assert!(out.contains("<invalid-expr>"));
    }
}
