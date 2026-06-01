//! Bidirectional `source ↔ HIR` losslessness tests.
//!
//! These tests prove that the faithful HIR retains enough structure to reconstruct
//! equivalent C source. For each fixture we:
//!
//! 1. lower the original source to a [`HirContext`] and capture its canonical dump (`H1`);
//! 2. raise C source back out of that HIR with the library [`raise`] entry point;
//! 3. lower the *raised* source again and capture its dump (`H2`);
//! 4. assert `H1 == H2`.
//!
//! Equality of the two dumps means the round-trip preserved every construct: control-flow
//! shapes, declarations, types, initializers, and operators. The raiser fully parenthesizes
//! expressions (parentheses carry no HIR identity, so this is free) and emits each HIR item
//! independently, which is exactly how the lowering produced them.

use stratum_arena::Interner;
use stratum_c_ast::{
    CAst, CNode, DeclSpecifiers, Declarator, Derivation, InitItem, PostfixOp as CPostfixOp,
    TypeSpecifier,
};
use stratum_c_bridge::{lower, raise};
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::{FileId, SourceMap, Span};
use stratum_hir::{
    BinaryOp, DeclFlags, EnumVariant, Field, HirContext, HirInit, HirNode, HirNodeId, HirType,
    HirTypeId, IntWidth, Param, PostfixOp, Qualifiers, RecordKind, StorageClass,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Lowers `src` to a [`HirContext`], asserting no errors were produced.
fn lower_source(src: &str) -> TestResult<HirContext> {
    let mut map = SourceMap::new();
    let file = map.add_root("roundtrip.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;
    let result = lower(&parsed.ast)?;
    if result.has_errors() {
        return Err(std::io::Error::other(format!(
            "unexpected errors lowering {src:?}: {:#?}",
            result.diagnostics
        ))
        .into());
    }
    Ok(result.hir)
}

/// Asserts that `src` survives a `source -> HIR -> source -> HIR` round-trip unchanged.
fn assert_lossless(src: &str) -> TestResult {
    let first = lower_source(src)?;
    let dump1 = first.dump_root();
    let emitted = raise(&first)?;
    let second = lower_source(&emitted)?;
    let dump2 = second.dump_root();
    if dump1 != dump2 {
        return Err(std::io::Error::other(format!(
            "round-trip changed the HIR.\n--- source ---\n{src}\n--- emitted ---\n{emitted}\n\
             --- dump1 ---\n{dump1}\n--- dump2 ---\n{dump2}"
        ))
        .into());
    }
    Ok(())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message.into()).into())
    }
}

fn require_contains(haystack: &str, needle: &str) -> TestResult {
    ensure(
        haystack.contains(needle),
        format!("missing {needle:?} in {haystack}"),
    )
}

fn synthetic_span() -> Span {
    Span::point(FileId::from_raw(0), 0)
}

fn int_specifiers() -> DeclSpecifiers {
    DeclSpecifiers {
        type_specifiers: vec![TypeSpecifier::Int],
        ..DeclSpecifiers::default()
    }
}

#[test]
fn synthetic_ast_edges_lower_in_roundtrip_binary() -> TestResult {
    let mut ast = CAst::new();
    let f = ast.intern("f")?;
    let one = ast.intern("1")?;
    let one = ast.alloc(CNode::IntLiteral(one), synthetic_span())?;
    let init = ast.alloc(
        CNode::InitList(vec![InitItem {
            designators: Vec::new(),
            value: one,
        }]),
        synthetic_span(),
    )?;
    let empty_init = ast.alloc(CNode::InitList(Vec::new()), synthetic_span())?;
    let post_dec = ast.alloc(
        CNode::Postfix {
            op: CPostfixOp::PostDec,
            operand: one,
        },
        synthetic_span(),
    )?;
    let fallback = ast.alloc(CNode::Break, synthetic_span())?;
    let init_stmt = ast.alloc(CNode::ExprStmt(Some(init)), synthetic_span())?;
    let empty_init_stmt = ast.alloc(CNode::ExprStmt(Some(empty_init)), synthetic_span())?;
    let post_dec_stmt = ast.alloc(CNode::ExprStmt(Some(post_dec)), synthetic_span())?;
    let fallback_stmt = ast.alloc(CNode::ExprStmt(Some(fallback)), synthetic_span())?;
    let body = ast.alloc(
        CNode::Compound(vec![
            init_stmt,
            empty_init_stmt,
            post_dec_stmt,
            fallback_stmt,
        ]),
        synthetic_span(),
    )?;
    let function = ast.alloc(
        CNode::FunctionDef {
            specifiers: int_specifiers(),
            declarator: Declarator {
                name: Some(f),
                derivations: vec![Derivation::Function {
                    params: Vec::new(),
                    variadic: false,
                }],
            },
            body,
        },
        synthetic_span(),
    )?;
    let root = ast.alloc(CNode::TranslationUnit(vec![function]), synthetic_span())?;
    ast.set_root(root);

    let result = lower(&ast)?;
    ensure(!result.has_errors(), format!("{:#?}", result.diagnostics))?;
    require_contains(&result.hir.dump_root(), "postfix `--`")?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct RoundtripTypes {
    int: HirTypeId,
    ushort: HirTypeId,
    qualified_int: HirTypeId,
    qualified_ptr: HirTypeId,
}

fn roundtrip_synthetic_types(hir: &mut HirContext) -> TestResult<RoundtripTypes> {
    let int = hir.alloc_type(HirType::Int {
        signed: true,
        width: IntWidth::W32,
    })?;
    let ushort = hir.alloc_type(HirType::Int {
        signed: false,
        width: IntWidth::W16,
    })?;
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
    Ok(RoundtripTypes {
        int,
        ushort,
        qualified_int,
        qualified_ptr,
    })
}

fn roundtrip_declaration_items(
    hir: &mut HirContext,
    types: RoundtripTypes,
    name: stratum_arena::Symbol,
    label: stratum_arena::Symbol,
    one: HirNodeId,
    sum: HirNodeId,
) -> TestResult<Vec<HirNodeId>> {
    let short_name = hir.intern("Short")?;
    let typedef = hir.alloc(
        HirNode::TypeAlias {
            name: short_name,
            ty: types.ushort,
        },
        synthetic_span(),
    )?;
    let record = hir.alloc(
        HirNode::Record {
            kind: RecordKind::Struct,
            tag: None,
            fields: vec![
                Field {
                    name: Some(name),
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
        synthetic_span(),
    )?;
    let enum_tag = hir.intern("E")?;
    let enumeration = hir.alloc(
        HirNode::Enumeration {
            tag: Some(enum_tag),
            variants: vec![
                EnumVariant {
                    name,
                    value: Some(one),
                },
                EnumVariant {
                    name: label,
                    value: None,
                },
            ],
        },
        synthetic_span(),
    )?;
    let local = hir.alloc(
        HirNode::Var {
            name,
            ty: types.int,
            flags: DeclFlags::default(),
            init: Some(HirInit::Expr(sum)),
        },
        synthetic_span(),
    )?;
    Ok(vec![typedef, record, enumeration, local])
}

fn roundtrip_qualified_locals(
    hir: &mut HirContext,
    types: RoundtripTypes,
) -> TestResult<Vec<HirNodeId>> {
    let qualified_scalar_name = hir.intern("q")?;
    let qualified_scalar_local = hir.alloc(
        HirNode::Var {
            name: qualified_scalar_name,
            ty: types.qualified_int,
            flags: DeclFlags::default(),
            init: None,
        },
        synthetic_span(),
    )?;
    let qualified_pointer_name = hir.intern("qp")?;
    let qualified_pointer_local = hir.alloc(
        HirNode::Var {
            name: qualified_pointer_name,
            ty: types.qualified_ptr,
            flags: DeclFlags::default(),
            init: None,
        },
        synthetic_span(),
    )?;
    Ok(vec![qualified_scalar_local, qualified_pointer_local])
}

fn roundtrip_for_statements(
    hir: &mut HirContext,
    name: stratum_arena::Symbol,
) -> TestResult<Vec<HirNodeId>> {
    let name_expr = hir.alloc(HirNode::Name(name), synthetic_span())?;
    let for_init = hir.alloc(HirNode::ExprStmt(Some(name_expr)), synthetic_span())?;
    let for_step = hir.alloc(
        HirNode::Postfix {
            op: PostfixOp::Inc,
            operand: name_expr,
        },
        synthetic_span(),
    )?;
    let continue_stmt = hir.alloc(HirNode::Continue, synthetic_span())?;
    let for_body = hir.alloc(HirNode::Block(vec![continue_stmt]), synthetic_span())?;
    let populated = hir.alloc(
        HirNode::For {
            init: Some(for_init),
            cond: Some(name_expr),
            step: Some(for_step),
            body: for_body,
        },
        synthetic_span(),
    )?;
    let empty_for_body = hir.alloc(HirNode::Block(Vec::new()), synthetic_span())?;
    let sparse = hir.alloc(
        HirNode::For {
            init: None,
            cond: None,
            step: None,
            body: empty_for_body,
        },
        synthetic_span(),
    )?;
    Ok(vec![populated, sparse])
}

#[test]
fn synthetic_hir_edges_raise_in_roundtrip_binary() -> TestResult {
    let mut missing_root = HirContext::new();
    ensure(
        raise(&missing_root).is_err(),
        "missing root raised successfully",
    )?;
    let bad_root = missing_root.alloc(HirNode::IntLiteral(0), synthetic_span())?;
    missing_root.set_root(bad_root);
    ensure(
        raise(&missing_root).is_err(),
        "non-module root raised successfully",
    )?;

    let mut hir = HirContext::new();
    let types = roundtrip_synthetic_types(&mut hir)?;
    let name = hir.intern("x")?;
    let label = hir.intern("again")?;
    let one = hir.alloc(HirNode::IntLiteral(1), synthetic_span())?;
    let two = hir.alloc(HirNode::IntLiteral(2), synthetic_span())?;
    let sum = hir.alloc(
        HirNode::Binary {
            op: BinaryOp::Add,
            lhs: one,
            rhs: two,
        },
        synthetic_span(),
    )?;
    let mut items = roundtrip_declaration_items(&mut hir, types, name, label, one, sum)?;
    let local = *items
        .get(3)
        .ok_or_else(|| std::io::Error::other("missing synthetic local"))?;
    items.extend(roundtrip_qualified_locals(&mut hir, types)?);
    items.extend(roundtrip_for_statements(&mut hir, name)?);
    let return_none = hir.alloc(HirNode::Return(None), synthetic_span())?;
    let empty_stmt = hir.alloc(HirNode::ExprStmt(None), synthetic_span())?;
    let label_stmt = hir.alloc(
        HirNode::Label {
            name: label,
            body: local,
        },
        synthetic_span(),
    )?;
    let goto_stmt = hir.alloc(HirNode::Goto(label), synthetic_span())?;
    items.extend([return_none, empty_stmt, label_stmt, goto_stmt]);
    let body = hir.alloc(HirNode::Block(items), synthetic_span())?;
    let function = hir.alloc(
        HirNode::Function {
            name,
            params: vec![Param {
                name: None,
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
        synthetic_span(),
    )?;
    let root = hir.alloc(HirNode::Module(vec![function]), synthetic_span())?;
    hir.set_root(root);

    let out = raise(&hir)?;
    require_contains(&out, "static inline _Noreturn int x(int, ...)")?;
    require_contains(&out, "typedef unsigned short Short;")?;
    require_contains(&out, "enum E { x = 1, again };")?;
    require_contains(&out, "const volatile restrict _Atomic int q;")?;
    require_contains(&out, "*const volatile restrict _Atomic qp")?;
    require_contains(&out, "for (")?;
    Ok(())
}

// --- Declarations and types --------------------------------------------------------------

#[test]
fn scalar_variable_declarations() -> TestResult {
    assert_lossless(
        "int a; unsigned int b; char c; unsigned char d; short e; unsigned short f; \
         long g; unsigned long h; float i; double j; _Bool k;",
    )
}

#[test]
fn qualified_and_pointer_types() -> TestResult {
    assert_lossless(
        "const int a; volatile int b; const volatile int c; int *p; const int *q; \
         int *const r; int **pp; char *const *s;",
    )
}

#[test]
fn array_and_function_pointer_types() -> TestResult {
    assert_lossless("int a[3]; int m[2][4]; int (*fp)(int, int); int (*pa)[5]; char *names[2];")
}

#[test]
fn nested_pointer_array_and_function_declarators() -> TestResult {
    assert_lossless(
        "int *(*g)(int); int (*matrix[3])[4]; int *(*fns[2])(void); \
         char *(*lookup)(const char *key);",
    )
}

#[test]
fn storage_classes_and_inline() -> TestResult {
    assert_lossless(
        "static int a; extern int b; _Thread_local int t; constexpr int c = 1; \
         static inline int f(void) { return 0; }",
    )
}

#[test]
fn block_scope_storage_classes() -> TestResult {
    assert_lossless(
        "int f(void) { auto int a = 1; register int r = 2; static int s = 3; extern int e; \
         return a + r + s; }",
    )
}

#[test]
fn restrict_qualified_pointers() -> TestResult {
    assert_lossless(
        "int *restrict p; const int *restrict q; \
         void f(int *restrict a, const char *restrict b) { ; }",
    )
}

#[test]
fn long_double_and_short_widths() -> TestResult {
    assert_lossless(
        "short s; unsigned short us; long l; unsigned long ul; \
         signed char sc; float fl; double db;",
    )
}

#[test]
fn typedefs() -> TestResult {
    assert_lossless("typedef int Int; typedef int *IntPtr; typedef int Array[4]; Int x;")
}

#[test]
fn function_prototypes_and_definitions() -> TestResult {
    assert_lossless(
        "int f(void); int g(int a, int b); int h(int, char); double k(double x, ...); \
         int main(void) { return 0; }",
    )
}

// --- Aggregates and enums ----------------------------------------------------------------

#[test]
fn struct_and_union_definitions() -> TestResult {
    assert_lossless(
        "struct Point { int x; int y; }; union U { int i; float f; }; \
         struct Point origin;",
    )
}

#[test]
fn struct_with_bitfields() -> TestResult {
    assert_lossless("struct Flags { unsigned int a : 1; unsigned int b : 3; int : 4; };")
}

#[test]
fn enum_definitions() -> TestResult {
    assert_lossless("enum Color { Red, Green, Blue }; enum E { A = 1, B = 5, C }; enum Color c;")
}

#[test]
fn typedef_of_struct() -> TestResult {
    assert_lossless("typedef struct Node { int v; } Node; Node n;")
}

// --- Statements --------------------------------------------------------------------------

#[test]
fn if_else_chains() -> TestResult {
    assert_lossless(
        "int f(int x) { if (x) return 1; if (x > 0) { return 2; } else { return 3; } return 0; }",
    )
}

#[test]
fn while_and_do_while_loops() -> TestResult {
    assert_lossless(
        "int f(int n) { while (n > 0) { n = n - 1; } do { n = n + 1; } while (n < 10); return n; }",
    )
}

#[test]
fn for_loops_with_all_clause_combinations() -> TestResult {
    assert_lossless(
        "int f(void) { int s = 0; for (int i = 0; i < 10; i++) s = s + i; \
         for (;;) break; for (int j = 0;;) { j++; break; } return s; }",
    )
}

#[test]
fn switch_with_cases_and_default() -> TestResult {
    assert_lossless(
        "int f(int x) { switch (x) { case 0: return 1; case 1: case 2: return 2; \
         default: return 3; } }",
    )
}

#[test]
fn labels_goto_break_continue() -> TestResult {
    assert_lossless(
        "int f(int n) { int i = 0; loop: if (i < n) { i++; goto loop; } \
         while (1) { if (i) break; else continue; } return i; }",
    )
}

#[test]
fn local_declarations_and_empty_statements() -> TestResult {
    assert_lossless("int f(void) { int a = 1; const int b = 2; int *p = &a; ; ; return a + b; }")
}

// --- Expressions -------------------------------------------------------------------------

#[test]
fn arithmetic_and_logical_operators() -> TestResult {
    assert_lossless(
        "int f(int a, int b) { return a + b - a * b / 2 % 3 + (a << 1) - (b >> 2) \
         + (a & b) + (a | b) + (a ^ b); }",
    )
}

#[test]
fn comparison_and_boolean_operators() -> TestResult {
    assert_lossless(
        "int f(int a, int b) { return (a < b) + (a <= b) + (a > b) + (a >= b) \
         + (a == b) + (a != b) + (a && b) + (a || b) + !a; }",
    )
}

#[test]
fn unary_and_increment_operators() -> TestResult {
    assert_lossless(
        "int f(int a) { int b = -a; b = +a; b = ~a; b = !a; ++b; --b; b++; b--; \
         int *p = &a; int c = *p; return b + c; }",
    )
}

#[test]
fn assignment_and_compound_assignment() -> TestResult {
    assert_lossless(
        "int f(int a) { a = 1; a += 2; a -= 3; a *= 4; a /= 5; a %= 6; a <<= 1; \
         a >>= 1; a &= 7; a |= 8; a ^= 9; return a; }",
    )
}

#[test]
fn ternary_comma_and_calls() -> TestResult {
    assert_lossless(
        "int g(int x) { return x; } \
         int f(int a) { int b = a > 0 ? a : -a; b = (a++, a + 1); return g(b) + g(a); }",
    )
}

#[test]
fn member_access_and_subscript() -> TestResult {
    assert_lossless(
        "struct P { int x; int y; }; \
         int f(struct P *p, struct P q, int *a) { return p->x + q.y + a[2] + p->y; }",
    )
}

#[test]
fn casts_and_sizeof() -> TestResult {
    assert_lossless(
        "int f(double d) { int a = (int) d; unsigned long s = sizeof(int); \
         unsigned long t = sizeof d; return a + (int) s + (int) t; }",
    )
}

#[test]
fn literals_of_every_kind() -> TestResult {
    assert_lossless(
        "int f(void) { int a = 42; int b = 0x1F; int c = 010; double d = 3.14; \
         char e = 'A'; char nl = '\\n'; const char *s = \"hello\"; return a + b + c; }",
    )
}

#[test]
fn string_concatenation() -> TestResult {
    assert_lossless("const char *s = \"foo\" \"bar\" \"baz\";")
}

// --- initializers (C99) ------------------------------------------------------------------

#[test]
fn scalar_and_aggregate_initializers() -> TestResult {
    assert_lossless("int a = 5; int v[3] = { 1, 2, 3 }; struct P { int x; int y; } p = { 1, 2 };")
}

#[test]
fn designated_initializers() -> TestResult {
    assert_lossless(
        "struct P { int x; int y; }; \
         struct P p = { .x = 1, .y = 2 }; int v[4] = { [0] = 1, [3] = 9 };",
    )
}

#[test]
fn nested_and_compound_literals() -> TestResult {
    assert_lossless(
        "struct P { int x; int y; }; \
         int grid[2][2] = { { 1, 2 }, { 3, 4 } }; \
         int f(void) { struct P q = (struct P){ .x = 7, .y = 8 }; return q.x; }",
    )
}

#[test]
fn rich_bridge_surface_round_trips() -> TestResult {
    assert_lossless(
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
    )
}
