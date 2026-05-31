//! Direct `HIR → C source` (raise) tests.
//!
//! Where `roundtrip.rs` proves losslessness by re-lowering, these tests pin the *textual*
//! output of [`raise`] for representative constructs and exercise the bidirectional
//! [`CBridge`] contract and the failure paths (malformed HIR, missing root).

use stratum_arena::Interner;
use stratum_c_bridge::{CBridge, lower, raise};
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::{FileId, SourceMap, Span};
use stratum_hir::{HirBridge, HirContext, HirNode};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Lowers `src` to a [`HirContext`], asserting no errors were produced.
fn lower_source(src: &str) -> TestResult<HirContext> {
    let mut map = SourceMap::new();
    let file = map.add_root("raise.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;
    let result = lower(&parsed.ast)?;
    assert!(
        !result.has_errors(),
        "unexpected errors lowering {src:?}: {:#?}",
        result.diagnostics
    );
    Ok(result.hir)
}

/// Raises `src` (after lowering) back to C source text.
fn raised(src: &str) -> TestResult<String> {
    Ok(raise(&lower_source(src)?)?)
}

fn assert_raises_unchanged(src: &str) -> TestResult {
    assert_eq!(raised(src)?, src);
    Ok(())
}

fn span() -> Span {
    Span::point(FileId::from_raw(0), 0)
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
    assert_eq!(
        raised("int f(int a, int b) { return a + b * 2; }")?,
        "int f(int a, int b) { return (a + (b * 2)); }"
    );
    Ok(())
}

#[test]
fn raises_member_subscript_and_call() -> TestResult {
    let out = raised(
        "struct P { int x; }; int g(int); \
         int f(struct P *p, int *a) { return g(p->x) + a[0]; }",
    )?;
    assert!(out.contains("(p->x)"), "got: {out}");
    assert!(out.contains("(a[0])"), "got: {out}");
    assert!(out.contains("g((p->x))"), "got: {out}");
    Ok(())
}

#[test]
fn raises_cast_and_sizeof() -> TestResult {
    let out = raised("int f(double d) { return (int) d + sizeof(int); }")?;
    assert!(out.contains("((int)d)"), "got: {out}");
    assert!(out.contains("(sizeof(int))"), "got: {out}");
    Ok(())
}

#[test]
fn raises_string_and_char_literals() -> TestResult {
    let out = raised("const char *s = \"hi\\n\"; char c = 'A';")?;
    assert!(out.contains("\"hi\\n\""), "got: {out}");
    assert!(out.contains("'\\x41'"), "got: {out}");
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
    assert!(out.contains("while (n)"), "got: {out}");
    assert!(out.contains("do {"), "got: {out}");
    assert!(out.contains("for ("), "got: {out}");
    assert!(out.contains("switch (n)"), "got: {out}");
    assert!(out.contains("case 0:"), "got: {out}");
    assert!(out.contains("default:"), "got: {out}");
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
    assert_eq!(hir.root(), Some(root));
    assert!(matches!(hir.node(root), HirNode::Module(_)));
    assert_eq!(CBridge.raise(&hir)?, src);
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
        .alloc_type(stratum_hir::HirType::Int {
            signed: true,
            width: stratum_hir::IntWidth::W32,
        })
        .unwrap();
    let func = hir
        .alloc(
            HirNode::Function {
                name,
                params: Vec::new(),
                ret: ret_ty,
                variadic: false,
                flags: stratum_hir::DeclFlags::default(),
                body: Some(block),
            },
            span(),
        )
        .unwrap();
    let module = hir.alloc(HirNode::Module(vec![func]), span()).unwrap();
    hir.set_root(module);
    assert!(raise(&hir).is_err());
}
