#![allow(clippy::unwrap_used)]
//! Unit tests for token finalisation and the parser.

use crate::alloc_prelude::*;
use crate::{finalize_with_dialect, parse_with_dialect};
use stratum_arena::Interner;
use stratum_c_ast::CAst;
use stratum_c_lexer::{Dialect, lex};
use stratum_diagnostics::SourceMap;

/// Parses `src` end-to-end and returns the resulting AST.
fn parse_src(src: &str) -> CAst {
    parse_src_with_dialect(src, Dialect::DEFAULT)
}

fn parse_src_with_dialect(src: &str, dialect: Dialect) -> CAst {
    let mut map = SourceMap::new();
    let file = map.add_root("t.c", src);
    let mut interner = Interner::new();
    let lexed = lex(src, file.unwrap(), &mut interner).unwrap();
    assert!(!lexed.has_errors(), "lex errors");
    let finalized = finalize_with_dialect(&lexed.tokens, &mut interner, dialect);
    assert!(finalized.diagnostics.is_empty(), "finalize errors");
    let result = parse_with_dialect(&finalized.tokens, interner, dialect).unwrap();
    assert!(
        !result.has_errors(),
        "parse errors: {:?}",
        result.diagnostics
    );
    result.ast
}

/// Parses `src` and renders its AST via the shared dumper for assertions.
fn dump_root(src: &str) -> String {
    parse_src(src).dump_root()
}

#[test]
fn empty_function() {
    assert_eq!(dump_root("int main(void) {}"), "(tu (fn main (block )))");
}

#[test]
fn return_statement() {
    assert_eq!(
        dump_root("int f() { return 0; }"),
        "(tu (fn f (block (return 0))))"
    );
}

#[test]
fn arithmetic_precedence() {
    assert_eq!(
        dump_root("int f() { return 1 + 2 * 3; }"),
        "(tu (fn f (block (return (Add 1 (Mul 2 3))))))"
    );
}

#[test]
fn assignment_is_right_associative() {
    assert_eq!(
        dump_root("int f() { a = b = c; }"),
        "(tu (fn f (block (expr (Assign a (Assign b c))))))"
    );
}

#[test]
fn local_declaration_with_init() {
    assert_eq!(
        dump_root("int f() { int x = 5; }"),
        "(tu (fn f (block (decl x=5))))"
    );
}

#[test]
fn if_else_statement() {
    assert_eq!(
        dump_root("int f() { if (a) return 1; else return 2; }"),
        "(tu (fn f (block (if a (return 1) (return 2)))))"
    );
}

#[test]
fn while_loop() {
    assert_eq!(
        dump_root("int f() { while (a) b; }"),
        "(tu (fn f (block (while a (expr b)))))"
    );
}

#[test]
fn for_loop() {
    assert_eq!(
        dump_root("int f() { for (i = 0; i < n; i++) body; }"),
        "(tu (fn f (block (for (Assign i 0) (Lt i n) (PostInc i) (expr body)))))"
    );
}

#[test]
fn function_call_and_members() {
    assert_eq!(
        dump_root("int f() { g(a, b->c); }"),
        "(tu (fn f (block (expr (call g a (mem-> b c))))))"
    );
}

#[test]
fn unary_and_postfix() {
    assert_eq!(
        dump_root("int f() { return -x + y++; }"),
        "(tu (fn f (block (return (Add (Neg x) (PostInc y))))))"
    );
}

#[test]
fn global_declaration() {
    assert_eq!(dump_root("int x = 3;"), "(tu (decl x=3))");
}

#[test]
fn global_declaration_with_multiple_declarators() {
    assert_eq!(dump_root("int x, y;"), "(tu (decl x y))");
}

#[test]
fn typedef_then_use() {
    // After `typedef int myint;`, `myint` must parse as a type, not an identifier.
    assert_eq!(
        dump_root("typedef int myint; myint x;"),
        "(tu (decl myint) (decl x))"
    );
}

#[test]
fn cast_expression() {
    assert_eq!(
        dump_root("int f() { return (int)x; }"),
        "(tu (fn f (block (return (cast x)))))"
    );
}

#[test]
fn sizeof_type_and_expr() {
    assert_eq!(
        dump_root("int f() { return sizeof(int) + sizeof x; }"),
        "(tu (fn f (block (return (Add (sizeof-type) (sizeof x))))))"
    );
}

#[test]
fn struct_declaration() {
    let ast = parse_src("struct Point { int x; int y; };");
    assert!(ast.root().is_some());
}

#[test]
fn pointer_and_array_declarators() {
    assert_eq!(
        dump_root("int *p; char buf[10];"),
        "(tu (decl p) (decl buf))"
    );
}

#[test]
fn comma_and_conditional() {
    assert_eq!(
        dump_root("int f() { return a ? b : c, d; }"),
        "(tu (fn f (block (return (comma (?: a b c) d)))))"
    );
}

#[test]
fn initializer_list() {
    assert_eq!(
        dump_root("int a[3] = { 1, 2, 3 };"),
        "(tu (decl a=(init 1 2 3)))"
    );
}

#[test]
fn nested_initializer_list() {
    assert_eq!(
        dump_root("int m[2][2] = { { 1, 2 }, { 3, 4 } };"),
        "(tu (decl m=(init (init 1 2) (init 3 4))))"
    );
}

#[test]
fn field_designated_initializer() {
    assert_eq!(
        dump_root("struct P { int x; int y; }; struct P p = { .y = 2, .x = 1 };"),
        "(tu (decl ) (decl p=(init .y=2 .x=1)))"
    );
}

#[test]
fn array_designated_initializer() {
    assert_eq!(
        dump_root("int a[4] = { [2] = 9, [0] = 1 };"),
        "(tu (decl a=(init [2]=9 [0]=1)))"
    );
}

#[test]
fn compound_literal_expression() {
    assert_eq!(
        dump_root("void f(void) { q = (struct P){ 7 }; }"),
        "(tu (fn f (block (expr (Assign q (compound-lit (init 7)))))))"
    );
}

#[test]
fn missing_semicolon_reports_error() {
    let mut map = SourceMap::new();
    let src = "int f() { return 0 }";
    let file = map.add_root("t.c", src);
    let mut interner = Interner::new();
    let lexed = lex(src, file.unwrap(), &mut interner).unwrap();
    let finalized = finalize_with_dialect(&lexed.tokens, &mut interner, Dialect::DEFAULT);
    let result = parse_with_dialect(&finalized.tokens, interner, Dialect::DEFAULT).unwrap();
    assert!(result.has_errors());
}

#[test]
fn rich_c23_surface_parses_in_unit_test_binary() {
    let src = r#"
        typedef int Int;
        struct P { int x; int y; };
        union U { int i; float f; };
        enum E { A = 1, B, C = 5 };
        _Static_assert(1, "ok");
        static_assert(1);
        _Noreturn void no_return(void);
        thread_local _BitInt(17) bits;
        const volatile _Atomic int qualified;
        _Complex double complex_value;
        alignas(16) int expr_aligned;
        alignas(int) int typed_align;
        typeof(bits) bit_copy;
        typeof_unqual(int *) ptr;
        int (*nested_fp)(Int, ...);
        _Decimal32 d32;
        _Decimal64 d64;
        _Decimal128 d128;
        struct Bits {
            _Static_assert(1, "field ok");
            unsigned x : 3, y;
        };

        int g(int x) { return x; }

        int f(struct P *p, struct P q, int *a, double d) {
            [[maybe_unused]] int b = true;
            _Static_assert(1, "block ok");
            int c = false;
            char ch = '\n';
            char *s = "hi";
            float fl = 1.25;
            void *np = nullptr;
            int arr[4] = { [0] = 1, [3] = 9 };
            struct P r = (struct P){ .x = 7, .y = 8 };
            b = +b;
            b = ~b;
            b = !b;
            ++b;
            --b;
            b++;
            b--;
            b = b * 2 / 3 % 4 + (b << 1) - (b >> 1);
            b = (b < 1) + (b <= 2) + (b > 3) + (b >= 4) + (b == 5) + (b != 6);
            b = (b & 7) ^ (b | 8);
            b = (b && 1) || 0;
            b += 1;
            b -= 1;
            b *= 2;
            b /= 2;
            b %= 2;
            b <<= 1;
            b >>= 1;
            b &= 7;
            b |= 8;
            b ^= 9;
            if (b) {
                b = p->x + q.y + a[2] + r.x + arr[3];
            } else {
                b = (int)d;
            }
            switch (b) {
            case 0:
                break;
            default:
                goto done;
            }
            for (int i = 0; i < 3; i++) {
                continue;
            }
            while (b) {
                b--;
            }
            do {
                b++;
            } while (b < 10);
        label_decl:
            int declared_after_label;
        label_assert:
            _Static_assert(1, "label ok");
        label_empty:
            ;
            for (; ; ) {
                break;
            }
        done:
            return g(b ? b : 1) + (b++, b) + _Generic(b, int: b, default: 0)
                + sizeof(int) + sizeof b + alignof b + _Alignof(int)
                + s[0] + ch + c + declared_after_label + (int)fl;
        }
    "#;

    let ast = parse_src_with_dialect(src, Dialect::C23);
    assert!(ast.dump_root().contains("(fn f"));
}
