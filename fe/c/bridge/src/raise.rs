//! Raising of the shared HIR back into C source text.
//!
//! This is the reverse of [`lower`](crate::lower::lower): it walks a
//! [`HirContext`](stratum_hir::HirContext) and renders equivalent C source. Two design
//! choices keep it correct without a full pretty-printer:
//!
//! - **Full parenthesisation.** Every compound expression is wrapped in parentheses.
//!   Parentheses carry no HIR identity, so re-parsing the emitted text yields the same tree.
//! - **Item-by-item emission.** Each HIR item is rendered independently, mirroring how
//!   lowering produced them (aggregate definitions are their own items, uses reference tags).
//!
//! The declarator algorithm in [`Raiser::declare_inner`] handles C's inside-out type syntax,
//! including pointer/array/function precedence and `const`/`volatile`/`restrict` placement.
//!
//! Unlike a best-effort pretty-printer, raising is **fallible**: an unresolved symbol or an
//! HIR node appearing in a position it cannot occupy yields an [`Error`](crate::error::Error)
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
                Ok(format!("typedef {};", self.declare(*ty, self.sym(*name)?)?))
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
        let mut plist: Vec<String> = params
            .iter()
            .map(|p| {
                let name = match p.name {
                    Some(n) => self.sym(n)?,
                    None => String::new(),
                };
                self.declare(p.ty, name)
            })
            .collect::<Result<Vec<_>>>()?;
        if *variadic {
            plist.push("...".to_string());
        } else if plist.is_empty() {
            plist.push("void".to_string());
        }
        let head = self.declare(*ret, format!("{}({})", self.sym(*name)?, plist.join(", ")))?;
        let prefix = flag_prefix(*flags);
        match body {
            Some(b) => Ok(format!("{prefix}{head} {}", self.stmt(*b)?)),
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
        let decl = self.declare(*ty, self.sym(*name)?)?;
        let prefix = flag_prefix(*flags);
        match init {
            Some(i) => Ok(format!("{prefix}{decl} = {};", self.init(i)?)),
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
        let body = fields
            .iter()
            .map(|f| {
                let name = match f.name {
                    Some(n) => self.sym(n)?,
                    None => String::new(),
                };
                let decl = self.declare(f.ty, name)?;
                match f.bit_width {
                    Some(w) => Ok(format!("{decl} : {};", self.expr(w)?)),
                    None => Ok(format!("{decl};")),
                }
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");
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
        let body = variants
            .iter()
            .map(|v| match v.value {
                Some(val) => Ok(format!("{} = {}", self.sym(v.name)?, self.expr(val)?)),
                None => self.sym(v.name),
            })
            .collect::<Result<Vec<_>>>()?
            .join(", ");
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
                let mut list: Vec<String> = params
                    .iter()
                    .map(|p| {
                        Ok(self
                            .declare_inner(*p, String::new(), false)?
                            .trim()
                            .to_string())
                    })
                    .collect::<Result<Vec<_>>>()?;
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
        Ok(match base {
            HirType::Void => "void".to_string(),
            HirType::Bool => "_Bool".to_string(),
            HirType::Float { bits } => if *bits == 64 { "double" } else { "float" }.to_string(),
            HirType::Int { signed, width } => int_spelling(*signed, *width),
            HirType::Tag { kind, name } => match name {
                Some(n) => format!("{} {}", kind.spelling(), self.sym(*n)?),
                None => kind.spelling().to_string(),
            },
            HirType::Named(n) => self.sym(*n)?,
            HirType::Pointer(_)
            | HirType::Array { .. }
            | HirType::Function { .. }
            | HirType::Qualified { .. } => return Err(Error::UnexpectedHirNode("base type")),
        })
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
                let base = format!("if ({}) {}", self.expr(*cond)?, self.stmt(*then_block)?);
                match else_block {
                    Some(e) => Ok(format!("{base} else {}", self.stmt(*e)?)),
                    None => Ok(base),
                }
            }
            HirNode::While { cond, body } => Ok(format!(
                "while ({}) {}",
                self.expr(*cond)?,
                self.stmt(*body)?
            )),
            HirNode::DoWhile { body, cond } => Ok(format!(
                "do {} while ({});",
                self.stmt(*body)?,
                self.expr(*cond)?
            )),
            HirNode::For {
                init,
                cond,
                step,
                body,
            } => self.for_stmt(*init, *cond, *step, *body),
            HirNode::Switch { scrutinee, body } => Ok(format!(
                "switch ({}) {}",
                self.expr(*scrutinee)?,
                self.stmt(*body)?
            )),
            HirNode::Case { value, body } => Ok(format!(
                "case {}: {}",
                self.expr(*value)?,
                self.stmt(*body)?
            )),
            HirNode::Default { body } => Ok(format!("default: {}", self.stmt(*body)?)),
            HirNode::Label { name, body } => {
                Ok(format!("{}: {}", self.sym(*name)?, self.stmt(*body)?))
            }
            HirNode::Goto(name) => Ok(format!("goto {};", self.sym(*name)?)),
            HirNode::Break => Ok("break;".to_string()),
            HirNode::Continue => Ok("continue;".to_string()),
            HirNode::Return(None) => Ok("return;".to_string()),
            HirNode::Return(Some(e)) => Ok(format!("return {};", self.expr(*e)?)),
            HirNode::ExprStmt(None) => Ok(";".to_string()),
            HirNode::ExprStmt(Some(e)) => Ok(format!("{};", self.expr(*e)?)),
            HirNode::Var { .. } => self.var(id),
            HirNode::TypeAlias { .. } | HirNode::Record { .. } | HirNode::Enumeration { .. } => {
                self.item(id)
            }
            _ => Ok(format!("{};", self.expr(id)?)),
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
        Ok(format!("for ({init} {cond}; {step}) {}", self.stmt(body)?))
    }

    // --- Expressions ---------------------------------------------------------------------

    fn expr(&self, id: HirNodeId) -> Result<String> {
        match self.hir.node(id) {
            HirNode::Name(s) | HirNode::FloatLiteral(s) => self.sym(*s),
            HirNode::IntLiteral(v) => Ok(v.to_string()),
            HirNode::StringLiteral(s) => Ok(c_string(&self.sym(*s)?)),
            HirNode::CharLiteral(c) => Ok(format!("'\\x{c:x}'")),
            HirNode::Binary { op, lhs, rhs } => Ok(format!(
                "({} {} {})",
                self.expr(*lhs)?,
                op.symbol(),
                self.expr(*rhs)?
            )),
            HirNode::Unary { op, operand } => {
                Ok(format!("({}{})", op.symbol(), self.expr(*operand)?))
            }
            HirNode::Postfix { op, operand } => {
                Ok(format!("({}{})", self.expr(*operand)?, op.symbol()))
            }
            HirNode::Assign { op, target, value } => {
                let op = op.map_or("=".to_string(), |o| format!("{}=", o.symbol()));
                Ok(format!(
                    "({} {op} {})",
                    self.expr(*target)?,
                    self.expr(*value)?
                ))
            }
            HirNode::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Ok(format!(
                "({} ? {} : {})",
                self.expr(*cond)?,
                self.expr(*then_expr)?,
                self.expr(*else_expr)?
            )),
            HirNode::Call { callee, args } => {
                let args = args
                    .iter()
                    .map(|&a| self.expr(a))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ");
                Ok(format!("{}({args})", self.expr(*callee)?))
            }
            HirNode::Member { base, field, arrow } => {
                let op = if *arrow { "->" } else { "." };
                Ok(format!("({}{op}{})", self.expr(*base)?, self.sym(*field)?))
            }
            HirNode::Index { base, index } => {
                Ok(format!("({}[{}])", self.expr(*base)?, self.expr(*index)?))
            }
            HirNode::Cast { ty, operand } => Ok(format!(
                "(({}){})",
                self.declare(*ty, String::new())?,
                self.expr(*operand)?
            )),
            HirNode::Comma { lhs, rhs } => {
                Ok(format!("({}, {})", self.expr(*lhs)?, self.expr(*rhs)?))
            }
            HirNode::SizeofExpr(e) => Ok(format!("(sizeof {})", self.expr(*e)?)),
            HirNode::SizeofType(ty) => {
                Ok(format!("(sizeof({}))", self.declare(*ty, String::new())?))
            }
            HirNode::CompoundLiteral { ty, init } => Ok(format!(
                "(({}){})",
                self.declare(*ty, String::new())?,
                self.init(init)?
            )),
            _ => Err(Error::UnexpectedHirNode("expression")),
        }
    }

    // --- initializers --------------------------------------------------------------------

    fn init(&self, init: &HirInit) -> Result<String> {
        match init {
            HirInit::Expr(e) => self.expr(*e),
            HirInit::List(entries) => {
                let body = entries
                    .iter()
                    .map(|entry| {
                        let designators = entry
                            .designators
                            .iter()
                            .map(|d| self.designator(*d))
                            .collect::<Result<Vec<_>>>()?
                            .join("");
                        if designators.is_empty() {
                            self.init(&entry.value)
                        } else {
                            Ok(format!("{designators} = {}", self.init(&entry.value)?))
                        }
                    })
                    .collect::<Result<Vec<_>>>()?
                    .join(", ");
                Ok(format!("{{ {body} }}"))
            }
        }
    }

    fn designator(&self, designator: Designator) -> Result<String> {
        match designator {
            Designator::Field(name) => Ok(format!(".{}", self.sym(name)?)),
            Designator::Index(idx) => Ok(format!("[{}]", self.expr(idx)?)),
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
    use super::{Raiser, raise};
    use crate::alloc_prelude::*;
    use crate::error::Error;
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::{
        DeclFlags, EnumVariant, HirContext, HirInit, HirNode, HirType, IntWidth, Param, Qualifiers,
        RecordKind, TagKind,
    };

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn int_ty(hir: &mut HirContext) -> stratum_hir::HirTypeId {
        hir.alloc_type(HirType::Int {
            signed: true,
            width: IntWidth::W32,
        })
        .unwrap()
    }

    fn module(hir: &mut HirContext, items: Vec<stratum_hir::HirNodeId>) {
        let root = hir.alloc(HirNode::Module(items), span()).unwrap();
        hir.set_root(root);
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
                },
            }),
            Err(Error::UnexpectedHirNode("base type"))
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
