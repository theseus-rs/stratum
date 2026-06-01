//! Raising of the shared HIR back into C source text.
//!
//! This is the reverse of [`lower`](crate::lower::lower): it walks a
//! [`HirContext`] and renders equivalent C source. Two design choices keep it correct
//! without a full pretty-printer:
//!
//! - **Full parenthesization.** Every compound expression is wrapped in parentheses.
//!   Parentheses carry no HIR identity, so re-parsing the emitted text yields the same tree.
//! - **Item-by-item emission.** Each HIR item is rendered independently, mirroring how
//!   lowering produced them (aggregate definitions are their own items, uses reference tags).
//!
//! The declarator algorithm in `Raiser::declare_inner` handles C's inside-out type syntax,
//! including pointer/array/function precedence and `const`/`volatile`/`restrict` placement.
//!
//! Unlike a best-effort pretty-printer, raising is **fallible**: an unresolved symbol or an
//! HIR node appearing in a position it cannot occupy yields an [`Error`]
//! rather than silently emitting invalid C.

use crate::alloc_prelude::*;
use crate::error::{Error, Result};
use stratum_hir::{
    DeclFlags, Designator, HirContext, HirInit, HirNode, HirNodeId, HirType, HirTypeId, IntWidth,
    Qualifiers,
};

/// Raises the whole module held in `hir` into a string of C source.
///
/// # Errors
///
/// Returns an error if `hir` has no module root, if a symbol cannot be resolved, or if an HIR
/// node is encountered in a position it cannot legally occupy.
pub fn raise(hir: &HirContext) -> Result<String> {
    let raiser = Raiser { hir };
    let Some(root) = hir.root() else {
        return Err(Error::UnexpectedHirNode("missing module root"));
    };
    let HirNode::Module(items) = hir.node(root) else {
        return Err(Error::UnexpectedHirNode("module root"));
    };
    let rendered = items
        .iter()
        .map(|&id| raiser.item(id))
        .collect::<Result<Vec<_>>>()?;
    Ok(rendered.join("\n"))
}

struct Raiser<'a> {
    hir: &'a HirContext,
}

impl Raiser<'_> {
    fn sym(&self, symbol: stratum_arena::Symbol) -> Result<String> {
        Ok(self.hir.resolve(symbol)?.to_string())
    }

    // --- Items ---------------------------------------------------------------------------

    fn item(&self, id: HirNodeId) -> Result<String> {
        match self.hir.node(id) {
            HirNode::Function { .. } => self.function(id),
            HirNode::Var { .. } => self.var(id),
            HirNode::TypeAlias { name, ty } => {
                let name = self.sym(*name)?;
                let decl = self.declare(*ty, name)?;
                Ok(format!("typedef {decl};"))
            }
            HirNode::Record { .. } => self.record(id),
            HirNode::Enumeration { .. } => self.enumeration(id),
            _ => Err(Error::UnexpectedHirNode("module item")),
        }
    }

    fn function(&self, id: HirNodeId) -> Result<String> {
        let HirNode::Function {
            name,
            params,
            ret,
            variadic,
            flags,
            body,
        } = self.hir.node(id)
        else {
            return Err(Error::UnexpectedHirNode("function"));
        };
        let mut plist = Vec::with_capacity(params.len());
        for param in params {
            let name = match param.name {
                Some(n) => self.sym(n)?,
                None => String::new(),
            };
            plist.push(self.declare(param.ty, name)?);
        }
        if *variadic {
            plist.push("...".to_string());
        } else if plist.is_empty() {
            plist.push("void".to_string());
        }
        let name = self.sym(*name)?;
        let params = plist.join(", ");
        let head = self.declare(*ret, format!("{name}({params})"))?;
        let prefix = flag_prefix(*flags);
        match body {
            Some(b) => {
                let body = self.stmt(*b)?;
                Ok(format!("{prefix}{head} {body}"))
            }
            None => Ok(format!("{prefix}{head};")),
        }
    }

    fn var(&self, id: HirNodeId) -> Result<String> {
        let HirNode::Var {
            name,
            ty,
            flags,
            init,
        } = self.hir.node(id)
        else {
            return Err(Error::UnexpectedHirNode("variable"));
        };
        let name = self.sym(*name)?;
        let decl = self.declare(*ty, name)?;
        let prefix = flag_prefix(*flags);
        match init {
            Some(i) => {
                let init = self.init(i)?;
                Ok(format!("{prefix}{decl} = {init};"))
            }
            None => Ok(format!("{prefix}{decl};")),
        }
    }

    fn record(&self, id: HirNodeId) -> Result<String> {
        let HirNode::Record { kind, tag, fields } = self.hir.node(id) else {
            return Err(Error::UnexpectedHirNode("record"));
        };
        let tag = match tag {
            Some(t) => format!(" {}", self.sym(*t)?),
            None => String::new(),
        };
        let mut fields_out = Vec::with_capacity(fields.len());
        for field in fields {
            let name = match field.name {
                Some(n) => self.sym(n)?,
                None => String::new(),
            };
            let decl = self.declare(field.ty, name)?;
            let rendered = match field.bit_width {
                Some(w) => {
                    let width = self.expr(w)?;
                    format!("{decl} : {width};")
                }
                None => format!("{decl};"),
            };
            fields_out.push(rendered);
        }
        let body = fields_out.join(" ");
        Ok(format!("{}{tag} {{ {body} }};", kind.spelling()))
    }

    fn enumeration(&self, id: HirNodeId) -> Result<String> {
        let HirNode::Enumeration { tag, variants } = self.hir.node(id) else {
            return Err(Error::UnexpectedHirNode("enumeration"));
        };
        let tag = match tag {
            Some(t) => format!(" {}", self.sym(*t)?),
            None => String::new(),
        };
        let mut variants_out = Vec::with_capacity(variants.len());
        for variant in variants {
            let rendered = match variant.value {
                Some(value) => {
                    let name = self.sym(variant.name)?;
                    let value = self.expr(value)?;
                    format!("{name} = {value}")
                }
                None => self.sym(variant.name)?,
            };
            variants_out.push(rendered);
        }
        let body = variants_out.join(", ");
        Ok(format!("enum{tag} {{ {body} }};"))
    }

    // --- Types / declarators -------------------------------------------------------------

    /// Renders a declaration of type `ty` for the declarator fragment `inner`.
    fn declare(&self, ty: HirTypeId, inner: String) -> Result<String> {
        self.declare_inner(ty, inner, false)
    }

    fn declare_inner(&self, ty: HirTypeId, inner: String, from_pointer: bool) -> Result<String> {
        match self.hir.ty(ty) {
            HirType::Pointer(pointee) => self.declare_inner(*pointee, format!("*{inner}"), true),
            HirType::Array { element, length } => {
                let inner = paren_if(from_pointer, inner);
                let len = length.map(|n| n.to_string()).unwrap_or_default();
                self.declare_inner(*element, format!("{inner}[{len}]"), false)
            }
            HirType::Function {
                params,
                ret,
                variadic,
            } => {
                let inner = paren_if(from_pointer, inner);
                let mut list = Vec::with_capacity(params.len());
                for param in params {
                    let rendered = self.declare_inner(*param, String::new(), false)?;
                    list.push(rendered.trim().to_string());
                }
                if *variadic {
                    list.push("...".to_string());
                } else if list.is_empty() {
                    list.push("void".to_string());
                }
                self.declare_inner(*ret, format!("{inner}({})", list.join(", ")), false)
            }
            HirType::Qualified {
                inner: qinner,
                qualifiers,
            } => self.declare_qualified(*qinner, *qualifiers, inner, from_pointer),
            base => Ok(join(&self.base_spelling(base)?, &inner)),
        }
    }

    fn declare_qualified(
        &self,
        inner_ty: HirTypeId,
        quals: Qualifiers,
        inner: String,
        from_pointer: bool,
    ) -> Result<String> {
        if let HirType::Pointer(pointee) = self.hir.ty(inner_ty) {
            // A qualifier on a pointer type: `*const inner`.
            return self.declare_inner(*pointee, format!("*{} {inner}", quals_str(quals)), true);
        }
        let rendered = self.declare_inner(inner_ty, inner, from_pointer)?;
        Ok(format!("{} {rendered}", quals_str(quals)))
    }

    /// Returns the base (non-derived) type spelling for `base`.
    fn base_spelling(&self, base: &HirType) -> Result<String> {
        let spelling = match base {
            HirType::Void => "void".to_string(),
            HirType::Bool => "_Bool".to_string(),
            HirType::Float { bits } => if *bits == 64 { "double" } else { "float" }.to_string(),
            HirType::Int { signed, width } => int_spelling(*signed, *width),
            HirType::Tag { kind, name } => match name {
                Some(n) => {
                    let name = self.sym(*n)?;
                    format!("{} {name}", kind.spelling())
                }
                None => kind.spelling().to_string(),
            },
            HirType::Named(n) => self.sym(*n)?,
            HirType::Pointer(_)
            | HirType::Array { .. }
            | HirType::Function { .. }
            | HirType::Qualified { .. } => return Err(Error::UnexpectedHirNode("base type")),
        };
        Ok(spelling)
    }

    // --- Statements ----------------------------------------------------------------------

    fn stmt(&self, id: HirNodeId) -> Result<String> {
        match self.hir.node(id) {
            HirNode::Block(stmts) => {
                let body = stmts
                    .iter()
                    .map(|&s| self.stmt(s))
                    .collect::<Result<Vec<_>>>()?
                    .join(" ");
                Ok(format!("{{ {body} }}"))
            }
            HirNode::Conditional {
                cond,
                then_block,
                else_block,
            } => {
                let cond = self.expr(*cond)?;
                let then_block = self.stmt(*then_block)?;
                let base = format!("if ({cond}) {then_block}");
                match else_block {
                    Some(e) => {
                        let else_block = self.stmt(*e)?;
                        Ok(format!("{base} else {else_block}"))
                    }
                    None => Ok(base),
                }
            }
            HirNode::While { cond, body } => {
                let cond = self.expr(*cond)?;
                let body = self.stmt(*body)?;
                Ok(format!("while ({cond}) {body}"))
            }
            HirNode::DoWhile { body, cond } => {
                let body = self.stmt(*body)?;
                let cond = self.expr(*cond)?;
                Ok(format!("do {body} while ({cond});"))
            }
            HirNode::For {
                init,
                cond,
                step,
                body,
            } => self.for_stmt(*init, *cond, *step, *body),
            HirNode::Switch { scrutinee, body } => {
                let scrutinee = self.expr(*scrutinee)?;
                let body = self.stmt(*body)?;
                Ok(format!("switch ({scrutinee}) {body}"))
            }
            HirNode::Case { value, body } => {
                let value = self.expr(*value)?;
                let body = self.stmt(*body)?;
                Ok(format!("case {value}: {body}"))
            }
            HirNode::Default { body } => {
                let body = self.stmt(*body)?;
                Ok(format!("default: {body}"))
            }
            HirNode::Label { name, body } => {
                let name = self.sym(*name)?;
                let body = self.stmt(*body)?;
                Ok(format!("{name}: {body}"))
            }
            HirNode::Goto(name) => {
                let name = self.sym(*name)?;
                Ok(format!("goto {name};"))
            }
            HirNode::Break => Ok("break;".to_string()),
            HirNode::Continue => Ok("continue;".to_string()),
            HirNode::Return(None) => Ok("return;".to_string()),
            HirNode::Return(Some(e)) => {
                let value = self.expr(*e)?;
                Ok(format!("return {value};"))
            }
            HirNode::ExprStmt(None) => Ok(";".to_string()),
            HirNode::ExprStmt(Some(e)) => {
                let expr = self.expr(*e)?;
                Ok(format!("{expr};"))
            }
            HirNode::Var { .. } => self.var(id),
            HirNode::TypeAlias { .. } | HirNode::Record { .. } | HirNode::Enumeration { .. } => {
                self.item(id)
            }
            _ => {
                let expr = self.expr(id)?;
                Ok(format!("{expr};"))
            }
        }
    }

    fn for_stmt(
        &self,
        init: Option<HirNodeId>,
        cond: Option<HirNodeId>,
        step: Option<HirNodeId>,
        body: HirNodeId,
    ) -> Result<String> {
        let init = match init {
            Some(i) => self.stmt(i)?,
            None => ";".to_string(),
        };
        let cond = match cond {
            Some(c) => self.expr(c)?,
            None => String::new(),
        };
        let step = match step {
            Some(s) => self.expr(s)?,
            None => String::new(),
        };
        let body = self.stmt(body)?;
        Ok(format!("for ({init} {cond}; {step}) {body}"))
    }

    // --- Expressions ---------------------------------------------------------------------

    fn expr(&self, id: HirNodeId) -> Result<String> {
        match self.hir.node(id) {
            HirNode::Name(s) | HirNode::FloatLiteral(s) => self.sym(*s),
            HirNode::IntLiteral(v) => Ok(v.to_string()),
            HirNode::StringLiteral(s) => {
                let value = self.sym(*s)?;
                Ok(c_string(&value))
            }
            HirNode::CharLiteral(c) => Ok(format!("'\\x{c:x}'")),
            HirNode::Binary { op, lhs, rhs } => {
                let lhs = self.expr(*lhs)?;
                let rhs = self.expr(*rhs)?;
                Ok(format!("({lhs} {} {rhs})", op.symbol()))
            }
            HirNode::Unary { op, operand } => {
                let operand = self.expr(*operand)?;
                Ok(format!("({}{operand})", op.symbol()))
            }
            HirNode::Postfix { op, operand } => {
                let operand = self.expr(*operand)?;
                Ok(format!("({operand}{})", op.symbol()))
            }
            HirNode::Assign { op, target, value } => {
                let op = op.map_or("=".to_string(), |o| format!("{}=", o.symbol()));
                let target = self.expr(*target)?;
                let value = self.expr(*value)?;
                Ok(format!("({target} {op} {value})"))
            }
            HirNode::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond = self.expr(*cond)?;
                let then_expr = self.expr(*then_expr)?;
                let else_expr = self.expr(*else_expr)?;
                Ok(format!("({cond} ? {then_expr} : {else_expr})"))
            }
            HirNode::Call { callee, args } => {
                let mut args_out = Vec::with_capacity(args.len());
                for arg in args {
                    args_out.push(self.expr(*arg)?);
                }
                let args = args_out.join(", ");
                let callee = self.expr(*callee)?;
                Ok(format!("{callee}({args})"))
            }
            HirNode::Member { base, field, arrow } => {
                let op = if *arrow { "->" } else { "." };
                let base = self.expr(*base)?;
                let field = self.sym(*field)?;
                Ok(format!("({base}{op}{field})"))
            }
            HirNode::Index { base, index } => {
                let base = self.expr(*base)?;
                let index = self.expr(*index)?;
                Ok(format!("({base}[{index}])"))
            }
            HirNode::Cast { ty, operand } => {
                let ty = self.declare(*ty, String::new())?;
                let operand = self.expr(*operand)?;
                Ok(format!("(({ty}){operand})"))
            }
            HirNode::Comma { lhs, rhs } => {
                let lhs = self.expr(*lhs)?;
                let rhs = self.expr(*rhs)?;
                Ok(format!("({lhs}, {rhs})"))
            }
            HirNode::SizeofExpr(e) => Ok(format!("(sizeof {})", self.expr(*e)?)),
            HirNode::SizeofType(ty) => {
                let ty = self.declare(*ty, String::new())?;
                Ok(format!("(sizeof({ty}))"))
            }
            HirNode::CompoundLiteral { ty, init } => {
                let ty = self.declare(*ty, String::new())?;
                let init = self.init(init)?;
                Ok(format!("(({ty}){init})"))
            }
            _ => Err(Error::UnexpectedHirNode("expression")),
        }
    }

    // --- initializers --------------------------------------------------------------------

    fn init(&self, init: &HirInit) -> Result<String> {
        match init {
            HirInit::Expr(e) => self.expr(*e),
            HirInit::List(entries) => {
                let mut parts = Vec::with_capacity(entries.len());
                for entry in entries {
                    let mut designators = String::new();
                    for designator in &entry.designators {
                        designators.push_str(&self.designator(*designator)?);
                    }
                    let value = self.init(&entry.value)?;
                    if designators.is_empty() {
                        parts.push(value);
                    } else {
                        parts.push(format!("{designators} = {value}"));
                    }
                }
                let body = parts.join(", ");
                Ok(format!("{{ {body} }}"))
            }
        }
    }

    fn designator(&self, designator: Designator) -> Result<String> {
        match designator {
            Designator::Field(name) => {
                let name = self.sym(name)?;
                Ok(format!(".{name}"))
            }
            Designator::Index(idx) => {
                let idx = self.expr(idx)?;
                Ok(format!("[{idx}]"))
            }
        }
    }
}

/// Canonical C spelling for an integer of the given signedness and width.
fn int_spelling(signed: bool, width: IntWidth) -> String {
    let base = match width {
        IntWidth::W8 => "char",
        IntWidth::W16 => "short",
        IntWidth::W32 => "int",
        IntWidth::W64 => "long",
    };
    if signed {
        base.to_string()
    } else {
        format!("unsigned {base}")
    }
}

/// Renders the storage-class / `inline` prefix (with a trailing space) for `flags`.
fn flag_prefix(flags: DeclFlags) -> String {
    let mut out = String::new();
    if let Some(storage) = flags.storage {
        out.push_str(storage.spelling());
        out.push(' ');
    }
    if flags.inline {
        out.push_str("inline ");
    }
    if flags.noreturn {
        out.push_str("_Noreturn ");
    }
    out
}

/// Joins the qualifier keywords present in `quals`, in canonical order.
fn quals_str(quals: Qualifiers) -> String {
    let mut parts = Vec::new();
    if quals.is_const {
        parts.push("const");
    }
    if quals.is_volatile {
        parts.push("volatile");
    }
    if quals.is_restrict {
        parts.push("restrict");
    }
    if quals.is_atomic {
        parts.push("_Atomic");
    }
    parts.join(" ")
}

/// Joins a base spelling and a declarator fragment, omitting the space when there is no name.
fn join(spec: &str, inner: &str) -> String {
    if inner.is_empty() {
        spec.to_string()
    } else {
        format!("{spec} {inner}")
    }
}

/// Wraps `inner` in parentheses when an array/function derivation sits inside a pointer.
fn paren_if(condition: bool, inner: String) -> String {
    if condition {
        format!("({inner})")
    } else {
        inner
    }
}

/// Renders `s` as a quoted, escaped C string literal that re-lexes to the same contents.
fn c_string(s: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let _ = write!(out, "\\x{:x}", c as u32);
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::{Raiser, c_string, raise};
    use crate::alloc_prelude::*;
    use crate::error::Error;
    use stratum_arena::Symbol;
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::{
        BinaryOp, DeclFlags, Designator, EnumVariant, Field, HirContext, HirInit, HirNode,
        HirNodeId, HirType, HirTypeId, InitEntry, IntWidth, Param, PostfixOp, Qualifiers,
        RecordKind, StorageClass, TagKind, UnaryOp,
    };

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn int_ty(hir: &mut HirContext) -> HirTypeId {
        hir.alloc_type(HirType::Int {
            signed: true,
            width: IntWidth::W32,
        })
        .unwrap()
    }

    fn int_node(hir: &mut HirContext, value: i128) -> HirNodeId {
        hir.alloc(HirNode::IntLiteral(value), span()).unwrap()
    }

    fn name_node(hir: &mut HirContext, name: Symbol) -> HirNodeId {
        hir.alloc(HirNode::Name(name), span()).unwrap()
    }

    fn expr_stmt(hir: &mut HirContext, expr: HirNodeId) -> HirNodeId {
        hir.alloc(HirNode::ExprStmt(Some(expr)), span()).unwrap()
    }

    fn module(hir: &mut HirContext, items: Vec<HirNodeId>) {
        let root = hir.alloc(HirNode::Module(items), span()).unwrap();
        hir.set_root(root);
    }

    fn function_with_body(
        hir: &mut HirContext,
        name: Symbol,
        ret: HirTypeId,
        params: Vec<Param>,
        stmts: Vec<HirNodeId>,
    ) -> HirNodeId {
        let body = hir.alloc(HirNode::Block(stmts), span()).unwrap();
        hir.alloc(
            HirNode::Function {
                name,
                params,
                ret,
                variadic: false,
                flags: DeclFlags::default(),
                body: Some(body),
            },
            span(),
        )
        .unwrap()
    }

    #[test]
    fn private_item_helpers_reject_wrong_nodes() {
        let mut hir = HirContext::new();
        let lit = hir.alloc(HirNode::IntLiteral(1), span()).unwrap();
        let raiser = Raiser { hir: &hir };

        assert!(matches!(
            raiser.function(lit),
            Err(Error::UnexpectedHirNode("function"))
        ));
        assert!(matches!(
            raiser.var(lit),
            Err(Error::UnexpectedHirNode("variable"))
        ));
        assert!(matches!(
            raiser.record(lit),
            Err(Error::UnexpectedHirNode("record"))
        ));
        assert!(matches!(
            raiser.enumeration(lit),
            Err(Error::UnexpectedHirNode("enumeration"))
        ));
    }

    #[test]
    fn private_base_spelling_rejects_derived_types() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let raiser = Raiser { hir: &hir };

        assert!(matches!(
            raiser.base_spelling(&HirType::Qualified {
                inner: int,
                qualifiers: Qualifiers {
                    is_const: true,
                    is_volatile: false,
                    is_restrict: false,
                    is_atomic: false,
                },
            }),
            Err(Error::UnexpectedHirNode("base type"))
        ));
    }

    #[test]
    fn public_raise_rejects_malformed_roots_and_items() {
        let hir = HirContext::new();
        assert!(matches!(
            raise(&hir),
            Err(Error::UnexpectedHirNode("missing module root"))
        ));

        let mut hir = HirContext::new();
        let lit = hir.alloc(HirNode::IntLiteral(0), span()).unwrap();
        hir.set_root(lit);
        assert!(matches!(
            raise(&hir),
            Err(Error::UnexpectedHirNode("module root"))
        ));

        let mut hir = HirContext::new();
        let brk = hir.alloc(HirNode::Break, span()).unwrap();
        module(&mut hir, vec![brk]);
        assert!(matches!(
            raise(&hir),
            Err(Error::UnexpectedHirNode("module item"))
        ));
    }

    #[test]
    fn public_raise_rejects_statement_values_that_are_not_expressions() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let cont = hir.alloc(HirNode::Continue, span()).unwrap();
        let ret = hir.alloc(HirNode::Return(Some(cont)), span()).unwrap();
        let name = hir.intern("bad").unwrap();
        let function = function_with_body(&mut hir, name, int, Vec::new(), vec![ret]);
        module(&mut hir, vec![function]);

        assert!(matches!(
            raise(&hir),
            Err(Error::UnexpectedHirNode("expression"))
        ));
    }

    #[test]
    fn raises_anonymous_tags_and_variadic_function_types() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let anon_record = hir
            .alloc(
                HirNode::Record {
                    kind: RecordKind::Struct,
                    tag: None,
                    fields: Vec::new(),
                },
                span(),
            )
            .unwrap();
        let variant = hir.intern("A").unwrap();
        let anon_enum = hir
            .alloc(
                HirNode::Enumeration {
                    tag: None,
                    variants: vec![EnumVariant {
                        name: variant,
                        value: None,
                    }],
                },
                span(),
            )
            .unwrap();
        let anon_union = hir
            .alloc_type(HirType::Tag {
                kind: TagKind::Union,
                name: None,
            })
            .unwrap();
        let union_name = hir.intern("u").unwrap();
        let union_var = hir
            .alloc(
                HirNode::Var {
                    name: union_name,
                    ty: anon_union,
                    flags: DeclFlags::default(),
                    init: None,
                },
                span(),
            )
            .unwrap();
        let variadic_fn = hir
            .alloc_type(HirType::Function {
                params: vec![int],
                ret: int,
                variadic: true,
            })
            .unwrap();
        let variadic_ptr = hir.alloc_type(HirType::Pointer(variadic_fn)).unwrap();
        let fp_name = hir.intern("fp").unwrap();
        let fp_var = hir
            .alloc(
                HirNode::Var {
                    name: fp_name,
                    ty: variadic_ptr,
                    flags: DeclFlags::default(),
                    init: None,
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![anon_record, anon_enum, union_var, fp_var]);

        assert_eq!(
            raise(&hir).unwrap(),
            "struct {  };\nenum { A };\nunion u;\nint (*fp)(int, ...);"
        );
    }

    #[test]
    fn raises_rich_unit_type_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let unsigned_short = hir
            .alloc_type(HirType::Int {
                signed: false,
                width: IntWidth::W16,
            })
            .unwrap();
        let long = hir
            .alloc_type(HirType::Int {
                signed: true,
                width: IntWidth::W64,
            })
            .unwrap();
        let void_ty = hir.alloc_type(HirType::Void).unwrap();
        let bool_ty = hir.alloc_type(HirType::Bool).unwrap();
        let float_ty = hir.alloc_type(HirType::Float { bits: 32 }).unwrap();
        let double_ty = hir.alloc_type(HirType::Float { bits: 64 }).unwrap();
        let alias = hir.intern("Alias").unwrap();
        let named_ty = hir.alloc_type(HirType::Named(alias)).unwrap();
        let tag = hir.intern("Tagged").unwrap();
        let tagged_ty = hir
            .alloc_type(HirType::Tag {
                kind: TagKind::Struct,
                name: Some(tag),
            })
            .unwrap();
        let prototype = hir
            .alloc_type(HirType::Function {
                params: Vec::new(),
                ret: int,
                variadic: false,
            })
            .unwrap();
        let prototype_ptr = hir.alloc_type(HirType::Pointer(prototype)).unwrap();

        let enum_tag = hir.intern("Mode").unwrap();
        let variant = hir.intern("On").unwrap();
        let one = int_node(&mut hir, 1);
        let enumeration = hir
            .alloc(
                HirNode::Enumeration {
                    tag: Some(enum_tag),
                    variants: vec![EnumVariant {
                        name: variant,
                        value: Some(one),
                    }],
                },
                span(),
            )
            .unwrap();
        let type_alias = hir
            .alloc(
                HirNode::TypeAlias {
                    name: alias,
                    ty: int,
                },
                span(),
            )
            .unwrap();

        let mut items = vec![type_alias, enumeration];
        for (name, ty) in [
            ("us", unsigned_short),
            ("l", long),
            ("v", void_ty),
            ("b", bool_ty),
            ("f", float_ty),
            ("d", double_ty),
            ("a", named_ty),
            ("tagged", tagged_ty),
            ("fp", prototype_ptr),
        ] {
            let name = hir.intern(name).unwrap();
            items.push(
                hir.alloc(
                    HirNode::Var {
                        name,
                        ty,
                        flags: DeclFlags::default(),
                        init: None,
                    },
                    span(),
                )
                .unwrap(),
            );
        }

        module(&mut hir, items);
        let raised = raise(&hir).unwrap();
        assert!(raised.contains("enum Mode { On = 1 };"));
        assert!(raised.contains("unsigned short us;"));
        assert!(raised.contains("long l;"));
        assert!(raised.contains("void v;"));
        assert!(raised.contains("_Bool b;"));
        assert!(raised.contains("float f;"));
        assert!(raised.contains("double d;"));
        assert!(raised.contains("Alias a;"));
        assert!(raised.contains("struct Tagged tagged;"));
        assert!(raised.contains("int (*fp)(void);"));
    }

    #[test]
    fn raises_rich_unit_control_flow_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let func_name = hir.intern("run").unwrap();
        let one = int_node(&mut hir, 1);
        let zero = int_node(&mut hir, 0);
        let empty_stmt = hir.alloc(HirNode::ExprStmt(None), span()).unwrap();
        let then_block = hir.alloc(HirNode::Block(vec![empty_stmt]), span()).unwrap();
        let else_block = hir.alloc(HirNode::Block(Vec::new()), span()).unwrap();
        let conditional = hir
            .alloc(
                HirNode::Conditional {
                    cond: one,
                    then_block,
                    else_block: Some(else_block),
                },
                span(),
            )
            .unwrap();
        let no_else_block = hir.alloc(HirNode::Block(Vec::new()), span()).unwrap();
        let conditional_without_else = hir
            .alloc(
                HirNode::Conditional {
                    cond: zero,
                    then_block: no_else_block,
                    else_block: None,
                },
                span(),
            )
            .unwrap();
        let break_stmt = hir.alloc(HirNode::Break, span()).unwrap();
        let while_body = hir.alloc(HirNode::Block(vec![break_stmt]), span()).unwrap();
        let while_stmt = hir
            .alloc(
                HirNode::While {
                    cond: one,
                    body: while_body,
                },
                span(),
            )
            .unwrap();
        let continue_stmt = hir.alloc(HirNode::Continue, span()).unwrap();
        let do_body = hir
            .alloc(HirNode::Block(vec![continue_stmt]), span())
            .unwrap();
        let do_while = hir
            .alloc(
                HirNode::DoWhile {
                    body: do_body,
                    cond: zero,
                },
                span(),
            )
            .unwrap();
        let function = function_with_body(
            &mut hir,
            func_name,
            int,
            Vec::new(),
            vec![conditional, conditional_without_else, while_stmt, do_while],
        );
        module(&mut hir, vec![function]);
        let raised = raise(&hir).unwrap();
        assert!(raised.contains("if (1)"));
        assert!(raised.contains("if (0)"));
        assert!(raised.contains("while (1)"));
        assert!(raised.contains("do { continue; } while (0);"));
    }

    #[test]
    fn raises_rich_unit_switch_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let func_name = hir.intern("run").unwrap();
        let one = int_node(&mut hir, 1);
        let case_break = hir.alloc(HirNode::Break, span()).unwrap();
        let case_stmt = hir
            .alloc(
                HirNode::Case {
                    value: one,
                    body: case_break,
                },
                span(),
            )
            .unwrap();
        let default_continue = hir.alloc(HirNode::Continue, span()).unwrap();
        let default_stmt = hir
            .alloc(
                HirNode::Default {
                    body: default_continue,
                },
                span(),
            )
            .unwrap();
        let switch_body = hir
            .alloc(HirNode::Block(vec![case_stmt, default_stmt]), span())
            .unwrap();
        let switch_stmt = hir
            .alloc(
                HirNode::Switch {
                    scrutinee: one,
                    body: switch_body,
                },
                span(),
            )
            .unwrap();
        let function = function_with_body(&mut hir, func_name, int, Vec::new(), vec![switch_stmt]);
        module(&mut hir, vec![function]);

        let raised = raise(&hir).unwrap();
        assert!(raised.contains("switch (1)"));
        assert!(raised.contains("case 1: break;"));
        assert!(raised.contains("default: continue;"));
    }

    #[test]
    fn raises_variadic_function_definition_unit_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let func_name = hir.intern("run").unwrap();
        let param_name = hir.intern("n").unwrap();
        let body = hir.alloc(HirNode::Block(Vec::new()), span()).unwrap();
        let function = hir
            .alloc(
                HirNode::Function {
                    name: func_name,
                    params: vec![Param {
                        name: Some(param_name),
                        ty: int,
                    }],
                    ret: int,
                    variadic: true,
                    flags: DeclFlags::default(),
                    body: Some(body),
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![function]);

        assert!(raise(&hir).unwrap().contains("int run(int n, ...)"));
    }

    #[test]
    fn raises_rich_unit_label_goto_literal_and_return_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let func_name = hir.intern("run").unwrap();
        let label_name = hir.intern("again").unwrap();
        let local_name = hir.intern("local").unwrap();
        let one = int_node(&mut hir, 1);
        let two = int_node(&mut hir, 2);
        let char_lit = hir.alloc(HirNode::CharLiteral(65), span()).unwrap();
        let binary = hir
            .alloc(
                HirNode::Binary {
                    op: BinaryOp::Add,
                    lhs: one,
                    rhs: two,
                },
                span(),
            )
            .unwrap();
        let local = hir
            .alloc(
                HirNode::Var {
                    name: local_name,
                    ty: int,
                    flags: DeclFlags::default(),
                    init: None,
                },
                span(),
            )
            .unwrap();
        let label = hir
            .alloc(
                HirNode::Label {
                    name: label_name,
                    body: local,
                },
                span(),
            )
            .unwrap();
        let goto = hir.alloc(HirNode::Goto(label_name), span()).unwrap();
        let char_stmt = expr_stmt(&mut hir, char_lit);
        let return_binary = hir.alloc(HirNode::Return(Some(binary)), span()).unwrap();
        let function = function_with_body(
            &mut hir,
            func_name,
            int,
            Vec::new(),
            vec![label, goto, char_stmt, return_binary],
        );
        module(&mut hir, vec![function]);

        let raised = raise(&hir).unwrap();
        assert!(raised.contains("again: int local;"));
        assert!(raised.contains("goto again;"));
        assert!(raised.contains("'\\x41';"));
        assert!(raised.contains("return (1 + 2);"));
    }

    #[test]
    fn raises_statement_fallbacks_in_functions() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let typedef_name = hir.intern("I").unwrap();
        let typedef = hir
            .alloc(
                HirNode::TypeAlias {
                    name: typedef_name,
                    ty: int,
                },
                span(),
            )
            .unwrap();
        let return_void = hir.alloc(HirNode::Return(None), span()).unwrap();
        let expr_stmt = hir.alloc(HirNode::IntLiteral(7), span()).unwrap();
        let block = hir
            .alloc(
                HirNode::Block(vec![return_void, typedef, expr_stmt]),
                span(),
            )
            .unwrap();
        let function_name = hir.intern("f").unwrap();
        let func = hir
            .alloc(
                HirNode::Function {
                    name: function_name,
                    params: Vec::new(),
                    ret: int,
                    variadic: false,
                    flags: DeclFlags::default(),
                    body: Some(block),
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![func]);

        assert_eq!(
            raise(&hir).unwrap(),
            "int f(void) { return; typedef int I; 7; }"
        );
    }

    #[test]
    fn raises_c_string_escapes() {
        let mut hir = HirContext::new();
        let char_ty = hir
            .alloc_type(HirType::Int {
                signed: true,
                width: IntWidth::W8,
            })
            .unwrap();
        let char_ptr = hir.alloc_type(HirType::Pointer(char_ty)).unwrap();
        let name = hir.intern("s").unwrap();
        let literal = hir.intern("\\\"\t\r\u{7}").unwrap();
        let literal = hir.alloc(HirNode::StringLiteral(literal), span()).unwrap();
        let var = hir
            .alloc(
                HirNode::Var {
                    name,
                    ty: char_ptr,
                    flags: DeclFlags::default(),
                    init: Some(HirInit::Expr(literal)),
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![var]);

        assert_eq!(raise(&hir).unwrap(), "char *s = \"\\\\\\\"\\t\\r\\x7\";");
    }

    #[test]
    fn c_string_escapes_every_special_character_class() {
        assert_eq!(
            c_string("\\\"\n\t\r\u{7}plain"),
            "\"\\\\\\\"\\n\\t\\r\\x7plain\""
        );
    }

    #[test]
    fn raises_initializer_designators_and_array_declarators() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let int_array = hir
            .alloc_type(HirType::Array {
                element: int,
                length: Some(3),
            })
            .unwrap();
        let name_a = hir.intern("a").unwrap();
        let field_x = hir.intern("x").unwrap();
        let zero = int_node(&mut hir, 0);
        let one = int_node(&mut hir, 1);
        let two = int_node(&mut hir, 2);

        let array_var = hir
            .alloc(
                HirNode::Var {
                    name: name_a,
                    ty: int_array,
                    flags: DeclFlags {
                        storage: Some(StorageClass::Static),
                        inline: false,
                        noreturn: false,
                    },
                    init: Some(HirInit::List(vec![
                        InitEntry {
                            designators: vec![Designator::Index(zero)],
                            value: HirInit::Expr(one),
                        },
                        InitEntry {
                            designators: vec![Designator::Field(field_x)],
                            value: HirInit::Expr(two),
                        },
                    ])),
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![array_var]);

        assert_eq!(
            raise(&hir).unwrap(),
            "static int a[3] = { [0] = 1, .x = 2 };"
        );
    }

    #[test]
    fn raises_call_assignment_and_conditional_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let int_ptr = hir.alloc_type(HirType::Pointer(int)).unwrap();
        let name_g = hir.intern("g").unwrap();
        let name_p = hir.intern("p").unwrap();
        let field_x = hir.intern("x").unwrap();
        let one = int_node(&mut hir, 1);
        let two = int_node(&mut hir, 2);
        let name = name_node(&mut hir, name_g);
        let ptr_name = name_node(&mut hir, name_p);
        let member = hir
            .alloc(
                HirNode::Member {
                    base: ptr_name,
                    field: field_x,
                    arrow: false,
                },
                span(),
            )
            .unwrap();
        let index = hir
            .alloc(
                HirNode::Index {
                    base: name,
                    index: two,
                },
                span(),
            )
            .unwrap();
        let call = hir
            .alloc(
                HirNode::Call {
                    callee: name,
                    args: vec![member, index],
                },
                span(),
            )
            .unwrap();
        let assign = hir
            .alloc(
                HirNode::Assign {
                    op: Some(BinaryOp::Add),
                    target: name,
                    value: call,
                },
                span(),
            )
            .unwrap();
        let ternary = hir
            .alloc(
                HirNode::Ternary {
                    cond: name,
                    then_expr: one,
                    else_expr: two,
                },
                span(),
            )
            .unwrap();
        let assign_stmt = expr_stmt(&mut hir, assign);
        let ternary_stmt = expr_stmt(&mut hir, ternary);
        let function = function_with_body(
            &mut hir,
            name_g,
            int,
            vec![Param {
                name: Some(name_p),
                ty: int_ptr,
            }],
            vec![assign_stmt, ternary_stmt],
        );
        module(&mut hir, vec![function]);

        let raised = raise(&hir).unwrap();
        assert!(raised.contains("(g += g((p.x), (g[2])))"));
        assert!(raised.contains("(g ? 1 : 2)"));
    }

    #[test]
    fn raises_cast_sizeof_compound_and_comma_surface() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let int_ptr = hir.alloc_type(HirType::Pointer(int)).unwrap();
        let int_array = hir
            .alloc_type(HirType::Array {
                element: int,
                length: Some(3),
            })
            .unwrap();
        let name_g = hir.intern("g").unwrap();
        let zero = int_node(&mut hir, 0);
        let one = int_node(&mut hir, 1);
        let name = name_node(&mut hir, name_g);
        let unary = hir
            .alloc(
                HirNode::Unary {
                    op: UnaryOp::AddressOf,
                    operand: name,
                },
                span(),
            )
            .unwrap();
        let postfix = hir
            .alloc(
                HirNode::Postfix {
                    op: PostfixOp::Dec,
                    operand: name,
                },
                span(),
            )
            .unwrap();
        let comma = hir
            .alloc(
                HirNode::Comma {
                    lhs: unary,
                    rhs: postfix,
                },
                span(),
            )
            .unwrap();
        let cast = hir
            .alloc(
                HirNode::Cast {
                    ty: int_ptr,
                    operand: zero,
                },
                span(),
            )
            .unwrap();
        let sizeof_expr = hir.alloc(HirNode::SizeofExpr(name), span()).unwrap();
        let sizeof_type = hir.alloc(HirNode::SizeofType(int_ptr), span()).unwrap();
        let compound = hir
            .alloc(
                HirNode::CompoundLiteral {
                    ty: int_array,
                    init: HirInit::List(vec![InitEntry {
                        designators: Vec::new(),
                        value: HirInit::Expr(one),
                    }]),
                },
                span(),
            )
            .unwrap();
        let cast_stmt = expr_stmt(&mut hir, cast);
        let sizeof_expr_stmt = expr_stmt(&mut hir, sizeof_expr);
        let sizeof_type_stmt = expr_stmt(&mut hir, sizeof_type);
        let compound_stmt = expr_stmt(&mut hir, compound);
        let return_stmt = hir.alloc(HirNode::Return(Some(comma)), span()).unwrap();
        let function = function_with_body(
            &mut hir,
            name_g,
            int,
            Vec::new(),
            vec![
                cast_stmt,
                sizeof_expr_stmt,
                sizeof_type_stmt,
                compound_stmt,
                return_stmt,
            ],
        );
        module(&mut hir, vec![function]);

        let raised = raise(&hir).unwrap();
        assert!(raised.contains("((int *)0)"));
        assert!(raised.contains("(sizeof g)"));
        assert!(raised.contains("(sizeof(int *))"));
        assert!(raised.contains("((int [3]){ 1 })"));
        assert!(raised.contains("return ((&g), (g--));"));
    }

    fn qualified_record_items(
        hir: &mut HirContext,
        int: HirTypeId,
        int_ptr: HirTypeId,
    ) -> Vec<HirNodeId> {
        let qualifiers = Qualifiers {
            is_const: true,
            is_volatile: true,
            is_restrict: true,
            is_atomic: true,
        };
        let qualified_int = hir
            .alloc_type(HirType::Qualified {
                inner: int,
                qualifiers,
            })
            .unwrap();
        let qualified_ptr = hir
            .alloc_type(HirType::Qualified {
                inner: int_ptr,
                qualifiers,
            })
            .unwrap();
        let tag_name = hir.intern("R").unwrap();
        let field_name = hir.intern("x").unwrap();
        let bit_width = int_node(hir, 1);
        let record = hir
            .alloc(
                HirNode::Record {
                    kind: RecordKind::Struct,
                    tag: Some(tag_name),
                    fields: vec![
                        Field {
                            name: Some(field_name),
                            ty: int,
                            bit_width: None,
                        },
                        Field {
                            name: None,
                            ty: int,
                            bit_width: Some(bit_width),
                        },
                    ],
                },
                span(),
            )
            .unwrap();
        let qualified_scalar_name = hir.intern("q").unwrap();
        let qualified_scalar_var = hir
            .alloc(
                HirNode::Var {
                    name: qualified_scalar_name,
                    ty: qualified_int,
                    flags: DeclFlags::default(),
                    init: None,
                },
                span(),
            )
            .unwrap();
        let qualified_pointer_name = hir.intern("qp").unwrap();
        let qualified_pointer_var = hir
            .alloc(
                HirNode::Var {
                    name: qualified_pointer_name,
                    ty: qualified_ptr,
                    flags: DeclFlags::default(),
                    init: None,
                },
                span(),
            )
            .unwrap();
        vec![record, qualified_scalar_var, qualified_pointer_var]
    }

    fn synthetic_for_loop_function(hir: &mut HirContext, int: HirTypeId) -> HirNodeId {
        let loop_name = hir.intern("i").unwrap();
        let loop_expr = name_node(hir, loop_name);
        let init_stmt = expr_stmt(hir, loop_expr);
        let step = hir
            .alloc(
                HirNode::Postfix {
                    op: PostfixOp::Inc,
                    operand: loop_expr,
                },
                span(),
            )
            .unwrap();
        let continue_stmt = hir.alloc(HirNode::Continue, span()).unwrap();
        let body = hir
            .alloc(HirNode::Block(vec![continue_stmt]), span())
            .unwrap();
        let populated_for = hir
            .alloc(
                HirNode::For {
                    init: Some(init_stmt),
                    cond: Some(loop_expr),
                    step: Some(step),
                    body,
                },
                span(),
            )
            .unwrap();
        let empty_body = hir.alloc(HirNode::Block(Vec::new()), span()).unwrap();
        let sparse_for = hir
            .alloc(
                HirNode::For {
                    init: None,
                    cond: None,
                    step: None,
                    body: empty_body,
                },
                span(),
            )
            .unwrap();
        function_with_body(
            hir,
            loop_name,
            int,
            Vec::new(),
            vec![populated_for, sparse_for],
        )
    }

    #[test]
    fn raises_qualified_records_and_for_loops() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let int_ptr = hir.alloc_type(HirType::Pointer(int)).unwrap();
        let mut items = qualified_record_items(&mut hir, int, int_ptr);
        let function = synthetic_for_loop_function(&mut hir, int);
        items.push(function);
        module(&mut hir, items);

        let raised = raise(&hir).unwrap();
        assert!(raised.contains("struct R { int x; int : 1; };"));
        assert!(raised.contains("const volatile restrict _Atomic int q;"));
        assert!(raised.contains("int *const volatile restrict _Atomic qp;"));
        assert!(raised.contains("for ("));
    }

    #[test]
    fn unnamed_parameters_raise_as_empty_declarators() {
        let mut hir = HirContext::new();
        let int = int_ty(&mut hir);
        let name = hir.intern("f").unwrap();
        let func = hir
            .alloc(
                HirNode::Function {
                    name,
                    params: vec![Param {
                        name: None,
                        ty: int,
                    }],
                    ret: int,
                    variadic: false,
                    flags: DeclFlags::default(),
                    body: None,
                },
                span(),
            )
            .unwrap();
        module(&mut hir, vec![func]);

        assert_eq!(raise(&hir).unwrap(), "int f(int);");
    }
}
