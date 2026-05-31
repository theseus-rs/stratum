//! The lowering driver: walks a [`CAst`] and emits [`HirNode`]s into a [`HirContext`].

use crate::alloc_prelude::*;
use stratum_arena::Symbol as CSymbol;
use stratum_c_ast::{
    CAst, CNode, CNodeId, DeclSpecifiers, Declarator, Derivation, Designator as CDesignator,
    Enumerator, FieldDecl, InitDeclarator, StorageClass, TypeSpecifier,
};
use stratum_diagnostics::{Diagnostic, Span};
use stratum_hir::{
    DeclFlags, EnumVariant, Field, HirContext, HirInit, HirNode, HirNodeId, InitEntry, Param,
    RecordKind, StorageClass as HirStorage,
};

/// The result of lowering a translation unit into HIR.
#[derive(Debug)]
pub struct LowerResult {
    /// The populated HIR context. Its root is the lowered `Module`.
    pub hir: HirContext,
    /// Diagnostics emitted during lowering (invalid literals, etc.).
    pub diagnostics: Vec<Diagnostic>,
}

impl LowerResult {
    /// Returns `true` if any error-severity diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == stratum_diagnostics::Severity::Error)
    }
}

/// Lowers `ast` into a fresh [`HirContext`], returning it alongside any diagnostics.
///
/// # Errors
///
/// Returns an error if lowering cannot resolve an AST symbol or allocate HIR storage.
pub fn lower(ast: &CAst) -> crate::error::Result<LowerResult> {
    let mut hir = HirContext::new();
    let lowering = CLowering::new(ast);
    let (root, diagnostics) = lowering.run(&mut hir)?;
    hir.set_root(root);
    Ok(LowerResult { hir, diagnostics })
}

/// The lowering driver for the C frontend.
///
/// It walks the [`CAst`] and emits HIR nodes into a [`HirContext`], accumulating diagnostics
/// as it goes. The bidirectional seam is [`CBridge`](crate::bridge::CBridge), which delegates
/// its `lower` direction here.
#[derive(Debug)]
pub struct CLowering<'a> {
    pub(crate) ast: &'a CAst,
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl<'a> CLowering<'a> {
    /// Creates a lowering driver over `ast`.
    #[must_use]
    pub fn new(ast: &'a CAst) -> Self {
        Self {
            ast,
            diagnostics: Vec::new(),
        }
    }

    /// Lowers the whole translation unit, returning the module node id and diagnostics.
    pub(crate) fn run(
        mut self,
        cx: &mut HirContext,
    ) -> crate::error::Result<(HirNodeId, Vec<Diagnostic>)> {
        let root = self.lower_module(cx)?;
        Ok((root, self.diagnostics))
    }

    fn lower_module(&mut self, cx: &mut HirContext) -> crate::error::Result<HirNodeId> {
        let mut items = Vec::new();
        if let Some(root) = self.ast.root()
            && let CNode::TranslationUnit(decls) = self.ast.node(root)
        {
            let decls = decls.clone();
            for decl in decls {
                self.lower_top_level(cx, decl, &mut items)?;
            }
        }
        let span = self.root_span();
        cx.alloc(HirNode::Module(items), span)
            .map_err(crate::error::Error::from)
    }

    fn lower_top_level(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        match self.ast.node(id) {
            CNode::FunctionDef {
                specifiers,
                declarator,
                body,
            } => {
                let specifiers = specifiers.clone();
                let declarator = declarator.clone();
                let body = *body;
                self.lower_aggregate_defs(cx, &specifiers, id, out)?;
                let node = self.lower_function(cx, &specifiers, &declarator, Some(body), id)?;
                out.push(node);
            }
            CNode::Declaration {
                specifiers,
                declarators,
            } => {
                let specifiers = specifiers.clone();
                let declarators = declarators.clone();
                self.lower_declaration(cx, &specifiers, &declarators, id, out)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Lowers a declaration (at module or block scope) into HIR items: any inline aggregate
    /// definitions first, then a `typedef`, function, or variable per declarator.
    pub(crate) fn lower_declaration(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarators: &[InitDeclarator],
        node: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        self.lower_aggregate_defs(cx, specifiers, node, out)?;
        let is_typedef = specifiers.storage.contains(&StorageClass::Typedef);
        let span = self.ast.span(node);
        for init in declarators {
            if is_typedef {
                self.lower_typedef(cx, specifiers, init, span, out)?;
            } else if is_function_declarator(&init.declarator) {
                let fn_node = self.lower_function(cx, specifiers, &init.declarator, None, node)?;
                out.push(fn_node);
            } else {
                self.lower_variable(cx, specifiers, init, span, out)?;
            }
        }
        Ok(())
    }

    fn lower_typedef(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        init: &InitDeclarator,
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let Some(name) = init.declarator.name else {
            return Ok(());
        };
        let name = self.lower_symbol(cx, name)?;
        let ty = self.lower_type(cx, specifiers, &init.declarator.derivations)?;
        out.push(
            cx.alloc(HirNode::TypeAlias { name, ty }, span)
                .map_err(crate::error::Error::from)?,
        );
        Ok(())
    }

    fn lower_variable(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        init: &InitDeclarator,
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let Some(name) = init.declarator.name else {
            return Ok(());
        };
        let name = self.lower_symbol(cx, name)?;
        let ty = self.lower_type(cx, specifiers, &init.declarator.derivations)?;
        let flags = Self::decl_flags(specifiers);
        let init = match init.init {
            Some(e) => Some(self.lower_init(cx, e)?),
            None => None,
        };
        out.push(
            cx.alloc(
                HirNode::Var {
                    name,
                    ty,
                    flags,
                    init,
                },
                span,
            )
            .map_err(crate::error::Error::from)?,
        );
        Ok(())
    }

    /// Emits [`Record`](HirNode::Record)/[`Enumeration`](HirNode::Enumeration) items for any
    /// `struct`/`union`/`enum` *definitions* present in the specifiers.
    fn lower_aggregate_defs(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        node: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let span = self.ast.span(node);
        let specs = specifiers.type_specifiers.clone();
        for spec in &specs {
            match spec {
                TypeSpecifier::Struct {
                    tag,
                    fields: Some(fields),
                } => self.emit_record(cx, RecordKind::Struct, *tag, fields, span, out)?,
                TypeSpecifier::Union {
                    tag,
                    fields: Some(fields),
                } => self.emit_record(cx, RecordKind::Union, *tag, fields, span, out)?,
                TypeSpecifier::Enum {
                    tag,
                    enumerators: Some(enumerators),
                } => self.emit_enum(cx, *tag, enumerators, span, out)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn emit_record(
        &mut self,
        cx: &mut HirContext,
        kind: RecordKind,
        tag: Option<CSymbol>,
        fields: &[FieldDecl],
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let tag = match tag {
            Some(t) => Some(self.lower_symbol(cx, t)?),
            None => None,
        };
        let mut lowered_fields = Vec::with_capacity(fields.len());
        for field in fields {
            let name = match field.declarator.name {
                Some(n) => Some(self.lower_symbol(cx, n)?),
                None => None,
            };
            let ty = self.lower_type(cx, &field.specifiers, &field.declarator.derivations)?;
            let bit_width = match field.bit_width {
                Some(w) => Some(self.lower_expr(cx, w)?),
                None => None,
            };
            lowered_fields.push(Field {
                name,
                ty,
                bit_width,
            });
        }
        out.push(
            cx.alloc(
                HirNode::Record {
                    kind,
                    tag,
                    fields: lowered_fields,
                },
                span,
            )
            .map_err(crate::error::Error::from)?,
        );
        Ok(())
    }

    fn emit_enum(
        &mut self,
        cx: &mut HirContext,
        tag: Option<CSymbol>,
        enumerators: &[Enumerator],
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let tag = match tag {
            Some(t) => Some(self.lower_symbol(cx, t)?),
            None => None,
        };
        let mut variants = Vec::with_capacity(enumerators.len());
        for enumerator in enumerators {
            let name = self.lower_symbol(cx, enumerator.name)?;
            let value = match enumerator.value {
                Some(v) => Some(self.lower_expr(cx, v)?),
                None => None,
            };
            variants.push(EnumVariant { name, value });
        }
        out.push(
            cx.alloc(HirNode::Enumeration { tag, variants }, span)
                .map_err(crate::error::Error::from)?,
        );
        Ok(())
    }

    fn lower_function(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarator: &Declarator,
        body: Option<CNodeId>,
        node: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(node);
        let name = match declarator.name {
            Some(n) => self.lower_symbol(cx, n)?,
            None => cx.intern("<anonymous>")?,
        };
        let (params, ret, variadic) = self.lower_function_signature(cx, specifiers, declarator)?;
        let flags = Self::decl_flags(specifiers);
        let body = match body {
            Some(b) => Some(self.lower_block(cx, b)?),
            None => None,
        };
        cx.alloc(
            HirNode::Function {
                name,
                params,
                ret,
                variadic,
                flags,
                body,
            },
            span,
        )
        .map_err(crate::error::Error::from)
    }

    fn lower_function_signature(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarator: &Declarator,
    ) -> crate::error::Result<(Vec<Param>, stratum_hir::HirTypeId, bool)> {
        let fn_index = declarator
            .derivations
            .iter()
            .position(|d| matches!(d, Derivation::Function { .. }));
        let mut params = Vec::new();
        let mut variadic = false;
        if let Some(idx) = fn_index
            && let Some(Derivation::Function {
                params: c_params,
                variadic: is_variadic,
            }) = declarator.derivations.get(idx)
        {
            variadic = *is_variadic;
            let c_params = c_params.clone();
            for p in &c_params {
                let name = match p.declarator.name {
                    Some(n) => Some(self.lower_symbol(cx, n)?),
                    None => None,
                };
                let ty = self.lower_type(cx, &p.specifiers, &p.declarator.derivations)?;
                params.push(Param { name, ty });
            }
        }
        // The return type is the base specifiers wrapped by any derivations that appear
        // *outside* (after) the function derivation, e.g. `int *f(void)`.
        let ret = match fn_index {
            Some(idx) => {
                let derivations = declarator.derivations.get(idx + 1..).unwrap_or_default();
                self.lower_type(cx, specifiers, derivations)?
            }
            None => self.lower_type(cx, specifiers, &[])?,
        };
        Ok((params, ret, variadic))
    }

    /// Lowers a C initialiser (a scalar expression or a braced list) into a [`HirInit`].
    pub(crate) fn lower_init(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirInit> {
        if let CNode::InitList(items) = self.ast.node(id) {
            let items = items.clone();
            let mut entries = Vec::with_capacity(items.len());
            for item in items {
                let mut designators = Vec::with_capacity(item.designators.len());
                for designator in item.designators {
                    designators.push(self.lower_designator(cx, designator)?);
                }
                entries.push(InitEntry {
                    designators,
                    value: self.lower_init(cx, item.value)?,
                });
            }
            Ok(HirInit::List(entries))
        } else {
            Ok(HirInit::Expr(self.lower_expr(cx, id)?))
        }
    }

    fn lower_designator(
        &mut self,
        cx: &mut HirContext,
        designator: CDesignator,
    ) -> crate::error::Result<stratum_hir::Designator> {
        match designator {
            CDesignator::Field(name) => {
                Ok(stratum_hir::Designator::Field(self.lower_symbol(cx, name)?))
            }
            CDesignator::Index(expr) => {
                Ok(stratum_hir::Designator::Index(self.lower_expr(cx, expr)?))
            }
        }
    }

    /// Builds the HIR declaration flags (storage class plus `inline`) from C specifiers,
    /// ignoring `typedef`, which is handled by a dedicated lowering path.
    fn decl_flags(specifiers: &DeclSpecifiers) -> DeclFlags {
        let storage = specifiers.storage.iter().find_map(|s| match s {
            StorageClass::Extern => Some(HirStorage::Extern),
            StorageClass::Static => Some(HirStorage::Static),
            StorageClass::Auto => Some(HirStorage::Auto),
            StorageClass::Register => Some(HirStorage::Register),
            StorageClass::ThreadLocal => Some(HirStorage::ThreadLocal),
            StorageClass::Constexpr => Some(HirStorage::Constexpr),
            StorageClass::Typedef => None,
        });
        DeclFlags {
            storage,
            inline: specifiers.inline,
            noreturn: specifiers.noreturn,
        }
    }

    /// Resolves a C-interner symbol and re-interns it into the HIR context's interner.
    ///
    /// C and HIR each own a separate interner, so symbols are never shared directly.
    pub(crate) fn lower_symbol(
        &self,
        cx: &mut HirContext,
        sym: CSymbol,
    ) -> crate::error::Result<stratum_arena::Symbol> {
        let text = self.ast.resolve(sym)?;
        Ok(cx.intern(text)?)
    }

    pub(crate) fn root_span(&self) -> Span {
        self.ast.root().map_or_else(
            || Span::point(stratum_diagnostics::FileId::from_raw(0), 0),
            |r| self.ast.span(r),
        )
    }
}

/// Returns `true` if the declarator's outermost derivation is a function.
pub(crate) fn is_function_declarator(declarator: &Declarator) -> bool {
    matches!(
        declarator.derivations.first(),
        Some(Derivation::Function { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::{CLowering, lower};
    use crate::alloc_prelude::*;
    use crate::bridge::CBridge;
    use crate::test_utils::{build, dump};
    use stratum_c_ast::{
        CAst, CNode, DeclSpecifiers, Declarator, InitDeclarator, StorageClass, TypeSpecifier,
    };
    use stratum_diagnostics::{FileId, Span};
    use stratum_hir::{HirBridge, HirContext, HirNode};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn int_specs() -> DeclSpecifiers {
        DeclSpecifiers {
            type_specifiers: vec![TypeSpecifier::Int],
            ..DeclSpecifiers::default()
        }
    }

    #[test]
    fn empty_unit_lowers_to_empty_module() {
        assert_eq!(dump(""), "module\n");
    }

    #[test]
    fn function_with_return() {
        let out = dump("int main(void) { return 0; }");
        assert!(out.contains("function main"));
        assert!(out.contains("return"));
        assert!(out.contains("int 0"));
    }

    #[test]
    fn function_prototype_has_no_body() {
        let out = dump("int f(int a);");
        assert!(out.contains("function f(a: i32) -> i32"), "got: {out}");
    }

    #[test]
    fn variadic_prototype_is_preserved() {
        let out = dump("int printf(char *fmt, ...);");
        assert!(out.contains("function printf("), "got: {out}");
        assert!(out.contains(", ...) -> i32"), "got: {out}");
    }

    #[test]
    fn storage_class_and_inline_flags_are_preserved() {
        let out = dump(
            "static inline _Noreturn int f(void) { return 0; } \
             thread_local int tls; constexpr int c = 1;",
        );
        assert!(
            out.contains("static inline _Noreturn function f"),
            "got: {out}"
        );
        assert!(out.contains("_Thread_local var tls"), "got: {out}");
        assert!(out.contains("constexpr var c"), "got: {out}");
    }

    #[test]
    fn auto_and_register_storage_flags_are_preserved() {
        let out = dump("void f(void) { auto int a; register int r; }");
        assert!(out.contains("auto var a"), "got: {out}");
        assert!(out.contains("register var r"), "got: {out}");
    }

    #[test]
    fn typedef_lowers_to_type_alias() {
        let out = dump("typedef int myint; myint x;");
        assert!(out.contains("typedef myint = i32"), "got: {out}");
        assert!(out.contains("var x: myint"), "got: {out}");
    }

    #[test]
    fn struct_definition_lowers_to_record() {
        let out = dump("struct Point { int x; int y; };");
        assert!(out.contains("struct Point"), "got: {out}");
        assert!(out.contains("field x: i32"), "got: {out}");
        assert!(out.contains("field y: i32"), "got: {out}");
    }

    #[test]
    fn union_definition_lowers_to_record() {
        let out = dump("union U { int i; float f; };");
        assert!(out.contains("union U"), "got: {out}");
        assert!(out.contains("field i: i32"), "got: {out}");
        assert!(out.contains("field f: f32"), "got: {out}");
    }

    #[test]
    fn anonymous_aggregates_and_abstract_fields_lower() {
        let out = dump("union { int; } u; enum { A };");
        assert!(out.contains("union <anonymous>"), "got: {out}");
        assert!(out.contains("field <unnamed>: i32"), "got: {out}");
        assert!(out.contains("enum <anonymous>"), "got: {out}");
    }

    #[test]
    fn bitfields_are_preserved() {
        let out = dump("struct Flags { unsigned a : 1; unsigned b : 3; };");
        assert!(out.contains("field a: u32 : "), "got: {out}");
        assert!(out.contains("int 1"), "got: {out}");
    }

    #[test]
    fn enum_definition_lowers_to_enumeration() {
        let out = dump("enum Color { Red, Green = 5, Blue };");
        assert!(out.contains("enum Color"), "got: {out}");
        assert!(out.contains("variant Red"), "got: {out}");
        assert!(out.contains("variant Green"), "got: {out}");
        assert!(out.contains("int 5"), "got: {out}");
    }

    #[test]
    fn struct_with_variable_emits_record_and_var() {
        let out = dump("struct P { int x; } p;");
        assert!(out.contains("struct P"), "got: {out}");
        assert!(out.contains("var p: struct P"), "got: {out}");
    }

    #[test]
    fn aggregate_initializer_lowers_to_init_list() {
        let out = dump("int a[3] = { 1, 2, 3 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("int 1"), "got: {out}");
        assert!(out.contains("int 3"), "got: {out}");
    }

    #[test]
    fn nested_aggregate_initializer() {
        let out = dump("int m[2][2] = { { 1, 2 }, { 3, 4 } };");
        let lists = out.matches("init-list").count();
        assert!(lists >= 3, "expected nested init lists, got: {out}");
    }

    #[test]
    fn lowering_is_total_no_errors_on_rich_input() {
        let src = "
            typedef unsigned long size_t;
            struct Node { int value; struct Node *next; };
            enum E { A, B = 2, C };
            static int counter = 0;
            int sum(int *xs, int n, ...) {
                int total = 0;
                for (int i = 0; i < n; i++) {
                    switch (xs[i]) {
                        case 0: continue;
                        default: total += xs[i] ? xs[i] : -1;
                    }
                }
                return total;
            }
        ";
        let ast = build(src);
        let result = lower(&ast).unwrap();
        assert!(!result.has_errors(), "got: {:?}", result.diagnostics);
    }

    #[test]
    fn designated_initializers_lower_with_designators() {
        let out = dump("struct P { int x; int y; }; struct P p = { .y = 2, .x = 1 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("designator .y"), "got: {out}");
        assert!(out.contains("designator .x"), "got: {out}");
    }

    #[test]
    fn array_index_designators_lower() {
        let out = dump("int a[4] = { [2] = 9, [0] = 1 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("designator []"), "got: {out}");
    }

    #[test]
    fn separate_interners_resolve_names() {
        let out = dump("int g; void f(void) { g = 1; }");
        assert!(out.contains("name `g`"), "got: {out}");
    }

    #[test]
    fn lowering_empty_ast_uses_synthetic_root_span() {
        let ast = CAst::new();
        let lowered = lower(&ast).unwrap();
        assert_eq!(lowered.hir.dump_root(), "module\n");

        let mut hir = HirContext::new();
        let root = CBridge.lower(&ast, &mut hir).unwrap();
        assert!(matches!(hir.node(root), HirNode::Module(items) if items.is_empty()));
        assert_eq!(hir.root(), Some(root));
    }

    #[test]
    fn non_declaration_top_level_items_are_ignored() {
        let mut ast = CAst::new();
        let sym = ast.intern("1").unwrap();
        let literal = ast.alloc(CNode::IntLiteral(sym), span()).unwrap();
        let root = ast
            .alloc(CNode::TranslationUnit(vec![literal]), span())
            .unwrap();
        ast.set_root(root);

        let lowered = lower(&ast).unwrap();
        assert_eq!(lowered.hir.dump_root(), "module\n");
    }

    #[test]
    fn nameless_declarators_do_not_emit_typedefs_or_variables() {
        let mut ast = CAst::new();
        let node = ast
            .alloc(
                CNode::Declaration {
                    specifiers: int_specs(),
                    declarators: Vec::new(),
                },
                span(),
            )
            .unwrap();
        let init = InitDeclarator {
            declarator: Declarator::default(),
            init: None,
        };
        let mut typedef_specs = int_specs();
        typedef_specs.storage.push(StorageClass::Typedef);
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        let mut out = Vec::new();

        lowering
            .lower_declaration(
                &mut hir,
                &typedef_specs,
                std::slice::from_ref(&init),
                node,
                &mut out,
            )
            .unwrap();
        lowering
            .lower_declaration(&mut hir, &int_specs(), &[init], node, &mut out)
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn anonymous_function_without_function_derivation_gets_default_signature() {
        let mut ast = CAst::new();
        let node = ast
            .alloc(
                CNode::Declaration {
                    specifiers: int_specs(),
                    declarators: Vec::new(),
                },
                span(),
            )
            .unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        let function = lowering
            .lower_function(&mut hir, &int_specs(), &Declarator::default(), None, node)
            .unwrap();
        assert!(hir.dump(function).contains("function <anonymous>() -> i32"));
    }

    #[test]
    fn typedef_storage_is_ignored_by_decl_flags() {
        let mut specs = int_specs();
        specs.storage.push(StorageClass::Typedef);
        let flags = CLowering::decl_flags(&specs);
        assert_eq!(flags.storage, None);
    }
}
