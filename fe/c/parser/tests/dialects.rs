//! Dialect-gating tests for ISO C syntax added after C89.

mod common;
use common::{assert_errors_with_dialect, assert_ok_with_dialect, run_with_dialect};
use stratum_c_lexer::Dialect;

#[test]
fn c89_accepts_classic_declarations_and_rejects_c99_syntax() {
    assert_ok_with_dialect("int f(void) { int x; x = 1; return x; }", Dialect::C89);
    assert_ok_with_dialect("int inline;", Dialect::C89);
    assert_errors_with_dialect("int f(void) { x = 1; int y; }", Dialect::C89);
    assert_errors_with_dialect(
        "int f(void) { for (int i = 0; i < 1; ++i) ; }",
        Dialect::C89,
    );
    assert_errors_with_dialect("int a[3] = { [1] = 2 };", Dialect::C89);
    assert_errors_with_dialect("void f(void) { p = (int){ 1 }; }", Dialect::C89);
    assert_errors_with_dialect("enum E { A, };", Dialect::C89);
}

#[test]
fn c99_accepts_c99_features_but_rejects_c11_keywords() {
    assert_ok_with_dialect(
        "restrict int *rp; _Imaginary float im; inline int f(int *restrict p) { _Bool b = 1; for (int i = 0; i < 1; ++i) ; return b; }",
        Dialect::C99,
    );
    assert_ok_with_dialect("int a[3] = { [1] = 2, };", Dialect::C99);
    assert_ok_with_dialect("void f(void) { p = (int[]){ 1, 2 }[0]; }", Dialect::C99);
    assert_errors_with_dialect("_Static_assert(1, \"ok\");", Dialect::C99);
    assert_errors_with_dialect("int f(void) { return _Generic(1, int: 2); }", Dialect::C99);
}

#[test]
fn c11_and_c17_accept_static_assert_alignof_atomic_and_generic() {
    let src = r#"
        _Static_assert(1, "ok");
        _Noreturn void stop(void);
        _Thread_local _Atomic int tls;
        _Atomic(int) ai;
        _Alignas(int) int aligned_like_int;
        struct S { _Static_assert(1, "field ok"); int x; };
        int f(void) {
            return _Alignof(int) + _Generic(1, int: 2, default: 3);
        }
    "#;
    assert_ok_with_dialect(src, Dialect::C11);
    assert_ok_with_dialect(src, Dialect::C17);
}

#[test]
fn c23_accepts_new_keywords_attributes_and_relaxed_forms() {
    let src = r"
        [[maybe_unused]] constexpr int c = true;
        static_assert(c);
        thread_local _BitInt(17) bits;
        alignas(16) bool flag = false;
        alignas(int) int typed_align;
        typeof(c) copy;
        typeof_unqual(int *) ptr;
        _Decimal32 d32;
        _Decimal64 d64;
        _Decimal128 d128;
        void f(void) {
            [[maybe_unused]] int local_attr;
            static_assert(1);
            int g = _Generic(1, int: 2, default: 3);
            label: int x = alignof c;
            done:
            int empty[1] = {};
            void *p = nullptr;
        }
        void g(void) { tail: }
    ";
    let parsed = run_with_dialect(src, Dialect::C23);
    assert!(
        !parsed.has_errors,
        "unexpected C23 diagnostics: {:#?}",
        parsed.diagnostics
    );
    assert!(parsed.dump.contains("(static-assert c)"));
    assert!(parsed.dump.contains("(generic 1 (type 2) (default 3))"));
}

#[test]
fn c23_features_are_rejected_by_c17() {
    assert_errors_with_dialect("[[maybe_unused]] int x;", Dialect::C17);
    assert_errors_with_dialect("static_assert(1);", Dialect::C17);
    assert_errors_with_dialect("bool flag = true;", Dialect::C17);
    assert_errors_with_dialect("_BitInt(5) x;", Dialect::C17);
    assert_errors_with_dialect("void f(void) { int a[1] = {}; }", Dialect::C17);
    assert_errors_with_dialect("[[unterminated", Dialect::C23);
    assert_errors_with_dialect("_Static_assert(1);", Dialect::C11);
    assert_errors_with_dialect("_Static_assert(1, 2);", Dialect::C11);
}

#[test]
fn c23_nested_attribute_tokens_are_skipped() {
    assert_ok_with_dialect("[[outer([[inner]])]] int x;", Dialect::C23);
}
