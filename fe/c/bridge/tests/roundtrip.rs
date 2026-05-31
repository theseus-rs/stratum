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
use stratum_c_bridge::{lower, raise};
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;
use stratum_hir::HirContext;

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
    assert!(
        !result.has_errors(),
        "unexpected errors lowering {src:?}: {:#?}",
        result.diagnostics
    );
    Ok(result.hir)
}

/// Asserts that `src` survives a `source -> HIR -> source -> HIR` round-trip unchanged.
fn assert_lossless(src: &str) -> TestResult {
    let first = lower_source(src)?;
    let dump1 = first.dump_root();
    let emitted = raise(&first)?;
    let second = lower_source(&emitted)?;
    let dump2 = second.dump_root();
    assert_eq!(
        dump1, dump2,
        "round-trip changed the HIR.\n--- source ---\n{src}\n--- emitted ---\n{emitted}\n\
         --- dump1 ---\n{dump1}\n--- dump2 ---\n{dump2}"
    );
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
    assert_lossless("static int a; extern int b; static inline int f(void) { return 0; }")
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
