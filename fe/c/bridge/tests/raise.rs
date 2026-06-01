//! Direct `HIR → C source` (raise) tests.
//!
//! Where `roundtrip.rs` proves losslessness by re-lowering, these tests pin the *textual*
//! output of [`raise`] for representative constructs and exercise the bidirectional
//! [`CBridge`] contract and the failure paths (malformed HIR, missing root).

use stratum_arena::Interner;
use stratum_c_ast::{CAst, CNode, DeclSpecifiers, Declarator, InitDeclarator, TypeSpecifier};
use stratum_c_bridge::{CBridge, LowerResult, lower, raise};
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::{FileId, SourceMap, Span};
use stratum_hir::{
    BinaryOp, DeclFlags, EnumVariant, Field, HirBridge, HirContext, HirInit, HirNode, HirNodeId,
    HirType, HirTypeId, IntWidth, Param, PostfixOp, Qualifiers, RecordKind, StorageClass,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Lowers `src` to a [`HirContext`], asserting no errors were produced.
fn lower_result(src: &str) -> TestResult<LowerResult> {
    let mut map = SourceMap::new();
    let file = map.add_root("raise.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;
    Ok(lower(&parsed.ast)?)
}

/// Lowers `src` to a [`HirContext`], asserting no errors were produced.
fn lower_source(src: &str) -> TestResult<HirContext> {
    let result = lower_result(src)?;
    if result.has_errors() {
        return Err(std::io::Error::other(format!(
            "unexpected errors lowering {src:?}: {:#?}",
            result.diagnostics
        ))
        .into());
    }
    Ok(result.hir)
}

/// Raises `src` (after lowering) back to C source text.
fn raised(src: &str) -> TestResult<String> {
    Ok(raise(&lower_source(src)?)?)
}

fn assert_raises_unchanged(src: &str) -> TestResult {
    let out = raised(src)?;
    if out != src {
        return Err(std::io::Error::other(format!("raised output changed: {out}")).into());
    }
    Ok(())
}

fn require_contains(haystack: &str, needle: &str) -> TestResult {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("missing {needle:?} in {haystack}")).into())
    }
}

fn span() -> Span {
    Span::point(FileId::from_raw(0), 0)
}

fn int_node(hir: &mut HirContext, value: i128) -> TestResult<HirNodeId> {
    Ok(hir.alloc(HirNode::IntLiteral(value), span())?)
}

fn name_node(hir: &mut HirContext, name: stratum_arena::Symbol) -> TestResult<HirNodeId> {
    Ok(hir.alloc(HirNode::Name(name), span())?)
}

// --- Items ------------------------------------------------------------------------------

#[test]
fn raises_variable_with_initializer() -> TestResult {
    assert_raises_unchanged("int x = 5;")
}

#[test]
fn raises_typedef() -> TestResult {
    assert_raises_unchanged("typedef int Int;")
}

#[test]
fn raises_function_definition() -> TestResult {
    assert_raises_unchanged("int f(int a) { return a; }")
}

#[test]
fn raises_void_prototype() -> TestResult {
    assert_raises_unchanged("int f(void);")
}

#[test]
fn raises_variadic_prototype() -> TestResult {
    assert_raises_unchanged("int printf(char *fmt, ...);")
}

#[test]
fn raises_storage_and_inline_prefix() -> TestResult {
    assert_raises_unchanged("static inline int f(void) { return 0; }")?;
    assert_raises_unchanged("_Noreturn int f(void);")
}

#[test]
fn raises_struct_with_bitfield() -> TestResult {
    assert_raises_unchanged("struct Flags { unsigned int a : 1; int : 4; };")
}

#[test]
fn raises_enum_with_explicit_values() -> TestResult {
    assert_raises_unchanged("enum E { A = 1, B, C = 5 };")
}

#[test]
fn lowering_edge_paths_are_covered_in_raise_binary() -> TestResult {
    let empty = lower(&CAst::new())?;
    if empty.hir.dump_root() != "module\n" {
        return Err(std::io::Error::other("empty AST did not lower to an empty module").into());
    }

    let mut ast = CAst::new();
    let name = ast.intern("x")?;
    let bad = ast.intern("bad")?;
    let bad = ast.alloc(CNode::IntLiteral(bad), span())?;
    let decl = ast.alloc(
        CNode::Declaration {
            specifiers: DeclSpecifiers {
                type_specifiers: vec![TypeSpecifier::Int],
                ..DeclSpecifiers::default()
            },
            declarators: vec![InitDeclarator {
                declarator: Declarator {
                    name: Some(name),
                    derivations: Vec::new(),
                },
                init: Some(bad),
            }],
        },
        span(),
    )?;
    let root = ast.alloc(CNode::TranslationUnit(vec![decl]), span())?;
    ast.set_root(root);

    let result = lower(&ast)?;
    if !result.has_errors() {
        return Err(std::io::Error::other("invalid literal did not report an error").into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SyntheticTypes {
    int: HirTypeId,
    ushort: HirTypeId,
    long: HirTypeId,
    bool_ty: HirTypeId,
    void_ty: HirTypeId,
    float_ty: HirTypeId,
    double_ty: HirTypeId,
    named: HirTypeId,
    int_ptr: HirTypeId,
    qualified_int: HirTypeId,
    qualified_ptr: HirTypeId,
    prototype: HirTypeId,
    variadic_prototype: HirTypeId,
}

fn synthetic_types(hir: &mut HirContext) -> TestResult<SyntheticTypes> {
    let int = hir.alloc_type(HirType::Int {
        signed: true,
        width: IntWidth::W32,
    })?;
    let ushort = hir.alloc_type(HirType::Int {
        signed: false,
        width: IntWidth::W16,
    })?;
    let long = hir.alloc_type(HirType::Int {
        signed: true,
        width: IntWidth::W64,
    })?;
    let alias_name = hir.intern("Alias")?;
    let named = hir.alloc_type(HirType::Named(alias_name))?;
    let int_ptr = hir.alloc_type(HirType::Pointer(int))?;
    let qualifiers = Qualifiers {
        is_const: true,
        is_volatile: true,
        is_restrict: true,
        is_atomic: true,
    };
    let qualified_int = hir.alloc_type(HirType::Qualified {
        inner: int,
        qualifiers,
    })?;
    let qualified_ptr = hir.alloc_type(HirType::Qualified {
        inner: int_ptr,
        qualifiers,
    })?;
    let prototype = hir.alloc_type(HirType::Function {
        params: Vec::new(),
        ret: int,
        variadic: false,
    })?;
    let variadic_prototype = hir.alloc_type(HirType::Function {
        params: vec![int],
        ret: int,
        variadic: true,
    })?;
    Ok(SyntheticTypes {
        int,
        ushort,
        long,
        bool_ty: hir.alloc_type(HirType::Bool)?,
        void_ty: hir.alloc_type(HirType::Void)?,
        float_ty: hir.alloc_type(HirType::Float { bits: 32 })?,
        double_ty: hir.alloc_type(HirType::Float { bits: 64 })?,
        named,
        int_ptr,
        qualified_int,
        qualified_ptr,
        prototype,
        variadic_prototype,
    })
}

fn synthetic_record_and_enum(
    hir: &mut HirContext,
    types: SyntheticTypes,
    one: HirNodeId,
) -> TestResult<Vec<HirNodeId>> {
    let name_x = hir.intern("x")?;
    let tag = hir.intern("R")?;
    let record = hir.alloc(
        HirNode::Record {
            kind: RecordKind::Struct,
            tag: Some(tag),
            fields: vec![
                Field {
                    name: Some(name_x),
                    ty: types.int,
                    bit_width: None,
                },
                Field {
                    name: None,
                    ty: types.int,
                    bit_width: Some(one),
                },
            ],
        },
        span(),
    )?;
    let variant_a = hir.intern("A")?;
    let variant_b = hir.intern("B")?;
    let enumeration = hir.alloc(
        HirNode::Enumeration {
            tag: None,
            variants: vec![
                EnumVariant {
                    name: variant_a,
                    value: Some(one),
                },
                EnumVariant {
                    name: variant_b,
                    value: None,
                },
            ],
        },
        span(),
    )?;
    Ok(vec![record, enumeration])
}

fn synthetic_var_items(hir: &mut HirContext, types: SyntheticTypes) -> TestResult<Vec<HirNodeId>> {
    let pointer_to_prototype = hir.alloc_type(HirType::Pointer(types.prototype))?;
    let pointer_to_variadic = hir.alloc_type(HirType::Pointer(types.variadic_prototype))?;
    let vars = [
        ("q", types.qualified_int),
        ("qp", types.qualified_ptr),
        ("u", types.ushort),
        ("l", types.long),
        ("b", types.bool_ty),
        ("v", types.void_ty),
        ("f", types.float_ty),
        ("d", types.double_ty),
        ("a", types.named),
        ("fnp", pointer_to_prototype),
        ("vfp", pointer_to_variadic),
    ];
    let mut items = Vec::new();
    for (name, ty) in vars {
        let name = hir.intern(name)?;
        items.push(hir.alloc(
            HirNode::Var {
                name,
                ty,
                flags: DeclFlags::default(),
                init: None,
            },
            span(),
        )?);
    }
    let str_name = hir.intern("s")?;
    let str_value = hir.intern("\\\"\t\r\u{7}")?;
    let str_literal = hir.alloc(HirNode::StringLiteral(str_value), span())?;
    items.push(hir.alloc(
        HirNode::Var {
            name: str_name,
            ty: types.int_ptr,
            flags: DeclFlags::default(),
            init: Some(HirInit::Expr(str_literal)),
        },
        span(),
    )?);
    Ok(items)
}

fn synthetic_control_function(
    hir: &mut HirContext,
    types: SyntheticTypes,
    one: HirNodeId,
    two: HirNodeId,
) -> TestResult<HirNodeId> {
    let name_y = hir.intern("y")?;
    let n_expr = name_node(hir, name_y)?;
    let assignment = hir.alloc(
        HirNode::Assign {
            op: None,
            target: n_expr,
            value: one,
        },
        span(),
    )?;
    let init_stmt = hir.alloc(HirNode::ExprStmt(Some(assignment)), span())?;
    let step = hir.alloc(
        HirNode::Postfix {
            op: PostfixOp::Inc,
            operand: n_expr,
        },
        span(),
    )?;
    let continue_stmt = hir.alloc(HirNode::Continue, span())?;
    let for_body = hir.alloc(HirNode::Block(vec![continue_stmt]), span())?;
    let for_stmt = hir.alloc(
        HirNode::For {
            init: Some(init_stmt),
            cond: Some(n_expr),
            step: Some(step),
            body: for_body,
        },
        span(),
    )?;
    let empty_body = hir.alloc(HirNode::Block(Vec::new()), span())?;
    let sparse_for = hir.alloc(
        HirNode::For {
            init: None,
            cond: None,
            step: None,
            body: empty_body,
        },
        span(),
    )?;
    let sum = hir.alloc(
        HirNode::Binary {
            op: BinaryOp::Add,
            lhs: one,
            rhs: two,
        },
        span(),
    )?;
    let return_sum = hir.alloc(HirNode::Return(Some(sum)), span())?;
    let body = hir.alloc(
        HirNode::Block(vec![for_stmt, sparse_for, return_sum]),
        span(),
    )?;
    let function_name = hir.intern("run")?;
    Ok(hir.alloc(
        HirNode::Function {
            name: function_name,
            params: vec![Param {
                name: Some(name_y),
                ty: types.int,
            }],
            ret: types.int,
            variadic: true,
            flags: DeclFlags {
                storage: Some(StorageClass::Static),
                inline: true,
                noreturn: true,
            },
            body: Some(body),
        },
        span(),
    )?)
}

#[test]
fn raises_synthetic_hir_edges() -> TestResult {
    let mut hir = HirContext::new();
    let types = synthetic_types(&mut hir)?;
    let one = int_node(&mut hir, 1)?;
    let two = int_node(&mut hir, 2)?;
    let mut module_items = synthetic_record_and_enum(&mut hir, types, one)?;
    module_items.extend(synthetic_var_items(&mut hir, types)?);
    module_items.push(synthetic_control_function(&mut hir, types, one, two)?);

    let root = hir.alloc(HirNode::Module(module_items), span())?;
    hir.set_root(root);

    let out = raise(&hir)?;
    require_contains(&out, "struct R { int x; int : 1; };")?;
    require_contains(&out, "enum { A = 1, B };")?;
    require_contains(&out, "const volatile restrict _Atomic int q;")?;
    require_contains(&out, "*const volatile restrict _Atomic qp")?;
    require_contains(&out, "unsigned short u;")?;
    require_contains(&out, "long l;")?;
    require_contains(&out, "int (*fnp)(void);")?;
    require_contains(&out, "int (*vfp)(int, ...);")?;
    require_contains(&out, "\"\\\\\\\"\\t\\r\\x7\"")?;
    require_contains(&out, "static inline _Noreturn int run(int y, ...)")?;
    require_contains(&out, "for (")?;
    Ok(())
}

// --- Types / declarators ----------------------------------------------------------------

#[test]
fn raises_pointer_and_array_declarators() -> TestResult {
    assert_raises_unchanged("int *p;")?;
    assert_raises_unchanged("int a[3];")?;
    assert_raises_unchanged("int (*fp)(int, int);")?;
    Ok(())
}

#[test]
fn raises_qualifiers_including_restrict() -> TestResult {
    assert_raises_unchanged("const int a = 0;")?;
    assert_raises_unchanged("int *restrict p;")?;
    assert_raises_unchanged("_Atomic int a;")?;
    Ok(())
}

// --- Expressions ------------------------------------------------------------------------

#[test]
fn raises_fully_parenthesized_expressions() -> TestResult {
    let out = raised("int f(int a, int b) { return a + b * 2; }")?;
    if out != "int f(int a, int b) { return (a + (b * 2)); }" {
        return Err(std::io::Error::other(format!("unexpected raised output: {out}")).into());
    }
    Ok(())
}

#[test]
fn raises_member_subscript_and_call() -> TestResult {
    let out = raised(
        "struct P { int x; }; int g(int); \
         int f(struct P *p, int *a) { return g(p->x) + a[0]; }",
    )?;
    require_contains(&out, "(p->x)")?;
    require_contains(&out, "(a[0])")?;
    require_contains(&out, "g((p->x))")?;
    Ok(())
}

#[test]
fn raises_cast_and_sizeof() -> TestResult {
    let out = raised("int f(double d) { return (int) d + sizeof(int); }")?;
    require_contains(&out, "((int)d)")?;
    require_contains(&out, "(sizeof(int))")?;
    Ok(())
}

#[test]
fn raises_string_and_char_literals() -> TestResult {
    let out = raised("const char *s = \"hi\\n\"; char c = 'A';")?;
    require_contains(&out, "\"hi\\n\"")?;
    require_contains(&out, "'\\x41'")?;
    Ok(())
}

// --- Statements -------------------------------------------------------------------------

#[test]
fn raises_control_flow_shapes() -> TestResult {
    let out = raised(
        "int f(int n) { while (n) n--; do { n++; } while (n); \
         for (int i = 0; i < n; i++) ; switch (n) { case 0: break; default: break; } \
         return n; }",
    )?;
    require_contains(&out, "while (n)")?;
    require_contains(&out, "do {")?;
    require_contains(&out, "for (")?;
    require_contains(&out, "switch (n)")?;
    require_contains(&out, "case 0:")?;
    require_contains(&out, "default:")?;
    Ok(())
}

#[test]
fn raises_rich_bridge_surface() -> TestResult {
    let out = raised(
        "typedef int Int; \
         struct P { int x; int y; }; union U { int i; float f; }; enum E { A = 1, B, C = 5 }; \
         static inline int g(int x) { return x; } \
         int f(struct P *p, struct P q, int *a, double d) { \
             int b = true; void *np = nullptr; int arr[4] = { [0] = 1, [3] = 9 }; \
             struct P r = (struct P){ .x = 7, .y = 8 }; \
             b = +b; b = ~b; b = !b; ++b; --b; b++; b--; \
             b = b * 2 / 3 % 4 + (b << 1) - (b >> 1); \
             b = (b < 1) + (b <= 2) + (b > 3) + (b >= 4) + (b == 5) + (b != 6); \
             b = (b & 7) ^ (b | 8); b = (b && 1) || 0; \
             b += 1; b -= 1; b *= 2; b /= 2; b %= 2; b <<= 1; b >>= 1; b &= 7; b |= 8; b ^= 9; \
             if (b) { b = p->x + q.y + a[2] + r.x + arr[3]; } else { b = (int)d; } \
             switch (b) { case 0: break; default: goto done; } \
             for (int i = 0; i < 3; i++) { continue; } \
             while (b) { b--; } do { b++; } while (b < 10); \
         done: return g(b ? b : 1) + (b++, b) + sizeof(int) + sizeof b \
             + alignof b + _Alignof(int) + _Generic(b, int: b, default: 0) + (int)np; \
         }",
    )?;
    require_contains(&out, "typedef int Int;")?;
    require_contains(&out, "struct P")?;
    require_contains(&out, "union U")?;
    require_contains(&out, "enum E")?;
    require_contains(&out, "static inline int g")?;
    require_contains(&out, "switch (b)")?;
    require_contains(&out, "for (")?;
    require_contains(&out, "while (b)")?;
    require_contains(&out, "do {")?;
    require_contains(&out, "goto done;")?;
    require_contains(&out, "(b ? b : 1)")?;
    require_contains(&out, "((b++), b)")?;
    require_contains(&out, "(sizeof(int))")?;
    require_contains(&out, "(sizeof b)")?;
    require_contains(&out, "void *np = 0;")?;
    Ok(())
}

// --- CBridge trait ----------------------------------------------------------------------

#[test]
fn cbridge_lower_sets_root_and_raises() -> TestResult {
    let src = "int x = 1;";
    let mut map = SourceMap::new();
    let file = map.add_root("bridge.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;

    let mut hir = HirContext::new();
    let root = CBridge.lower(&parsed.ast, &mut hir)?;
    if hir.root() != Some(root) {
        return Err(std::io::Error::other("lower did not set HIR root").into());
    }
    if !matches!(hir.node(root), HirNode::Module(_)) {
        return Err(std::io::Error::other("HIR root is not a module").into());
    }
    let raised = CBridge.raise(&hir)?;
    if raised != src {
        return Err(std::io::Error::other(format!("unexpected raised output: {raised}")).into());
    }
    Ok(())
}

// --- Failure paths ----------------------------------------------------------------------

#[test]
fn raising_without_a_root_is_an_error() {
    let hir = HirContext::new();
    assert!(raise(&hir).is_err());
}

#[test]
fn raising_a_non_module_root_is_an_error() {
    let mut hir = HirContext::new();
    let lit = hir.alloc(HirNode::IntLiteral(1), span()).unwrap();
    hir.set_root(lit);
    assert!(raise(&hir).is_err());
}

#[test]
fn raising_an_illegal_module_item_is_an_error() {
    // A bare statement (`Break`) is not a legal module-level item.
    let mut hir = HirContext::new();
    let brk = hir.alloc(HirNode::Break, span()).unwrap();
    let module = hir.alloc(HirNode::Module(vec![brk]), span()).unwrap();
    hir.set_root(module);
    assert!(raise(&hir).is_err());
}

#[test]
fn raising_a_statement_with_an_illegal_expression_is_an_error() {
    // A `Return` whose value is a statement node (`Continue`) cannot be raised as an
    // expression.
    let mut hir = HirContext::new();
    let cont = hir.alloc(HirNode::Continue, span()).unwrap();
    let ret = hir.alloc(HirNode::Return(Some(cont)), span()).unwrap();
    let block = hir.alloc(HirNode::Block(vec![ret]), span()).unwrap();
    let name = hir.intern("f").unwrap();
    let ret_ty = hir
        .alloc_type(HirType::Int {
            signed: true,
            width: IntWidth::W32,
        })
        .unwrap();
    let func = hir
        .alloc(
            HirNode::Function {
                name,
                params: Vec::new(),
                ret: ret_ty,
                variadic: false,
                flags: DeclFlags::default(),
                body: Some(block),
            },
            span(),
        )
        .unwrap();
    let module = hir.alloc(HirNode::Module(vec![func]), span()).unwrap();
    hir.set_root(module);
    assert!(raise(&hir).is_err());
}
