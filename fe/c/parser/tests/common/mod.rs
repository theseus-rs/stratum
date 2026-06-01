//! Shared helpers for the C parser integration tests.
//!
//! These helpers drive the full lex → finalize → parse pipeline and expose the parser's
//! stable S-expression dump so test groups can make precise, readable assertions about the
//! shape of the produced [`CAst`](stratum_c_ast::CAst).

#![allow(dead_code)]

use stratum_arena::Interner;
use stratum_c_lexer::Dialect;
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize_with_dialect, parse_with_dialect};
use stratum_diagnostics::SourceMap;

/// The outcome of running the front of the pipeline over a source string.
pub struct Parsed {
    /// The rendered S-expression dump of the translation unit.
    pub dump: String,
    /// Diagnostics rendered to their messages, in order.
    pub diagnostics: Vec<String>,
    /// Whether any error-level diagnostic was produced across lex/finalize/parse.
    pub has_errors: bool,
}

/// Runs lex → finalize → parse over `src`, collecting diagnostics from every phase.
#[must_use]
pub fn run(src: &str) -> Parsed {
    run_with_dialect(src, Dialect::DEFAULT)
}

/// Runs lex → finalize → parse over `src` using a specific dialect.
#[must_use]
pub fn run_with_dialect(src: &str, dialect: Dialect) -> Parsed {
    let mut map = SourceMap::new();
    let file = map.add_root("test.c", src);
    let mut interner = Interner::new();

    let Ok(file) = file else {
        return Parsed {
            dump: String::new(),
            diagnostics: vec!["failed to add source file".to_string()],
            has_errors: true,
        };
    };
    let Ok(lexed) = lex(src, file, &mut interner) else {
        return Parsed {
            dump: String::new(),
            diagnostics: vec!["failed to lex source".to_string()],
            has_errors: true,
        };
    };
    let mut diagnostics: Vec<String> = lexed.diagnostics.iter().map(render).collect();
    let mut has_errors = lexed.has_errors();

    let finalized = finalize_with_dialect(&lexed.tokens, &mut interner, dialect);
    diagnostics.extend(finalized.diagnostics.iter().map(render));
    has_errors |= finalized.diagnostics.iter().any(is_error);

    let Ok(result) = parse_with_dialect(&finalized.tokens, interner, dialect) else {
        return Parsed {
            dump: String::new(),
            diagnostics,
            has_errors: true,
        };
    };
    diagnostics.extend(result.diagnostics.iter().map(render));
    has_errors |= result.has_errors();

    Parsed {
        dump: result.ast.dump_root(),
        diagnostics,
        has_errors,
    }
}

/// Parses `src`, asserting that no phase reported an error, and returns the dump.
#[must_use]
pub fn dump(src: &str) -> String {
    let parsed = run(src);
    assert!(
        !parsed.has_errors,
        "unexpected errors for {src:?}: {:#?}",
        parsed.diagnostics
    );
    parsed.dump
}

/// Asserts that `src` parses cleanly and produces exactly `expected`.
pub fn assert_dump(src: &str, expected: &str) {
    assert_eq!(dump(src), expected, "mismatch for source: {src:?}");
}

/// Asserts that `src` parses cleanly (no errors), ignoring the exact dump.
pub fn assert_ok(src: &str) {
    let parsed = run(src);
    assert!(
        !parsed.has_errors,
        "expected {src:?} to parse cleanly, got: {:#?}",
        parsed.diagnostics
    );
}

/// Asserts that `src` parses cleanly for `dialect`, ignoring the exact dump.
pub fn assert_ok_with_dialect(src: &str, dialect: Dialect) {
    let parsed = run_with_dialect(src, dialect);
    assert!(
        !parsed.has_errors,
        "expected {src:?} to parse cleanly as {}, got: {:#?}",
        dialect.spelling(),
        parsed.diagnostics
    );
}

/// Asserts that `src` produces at least one error diagnostic.
pub fn assert_errors(src: &str) {
    let parsed = run(src);
    assert!(
        parsed.has_errors,
        "expected {src:?} to produce errors, but it parsed cleanly: {}",
        parsed.dump
    );
}

/// Asserts that `src` produces at least one error diagnostic for `dialect`.
pub fn assert_errors_with_dialect(src: &str, dialect: Dialect) {
    let parsed = run_with_dialect(src, dialect);
    assert!(
        parsed.has_errors,
        "expected {src:?} to produce errors as {}, but it parsed cleanly: {}",
        dialect.spelling(),
        parsed.dump
    );
}

fn render(diagnostic: &stratum_diagnostics::Diagnostic) -> String {
    diagnostic.message().to_string()
}

fn is_error(diagnostic: &stratum_diagnostics::Diagnostic) -> bool {
    diagnostic.severity() == stratum_diagnostics::Severity::Error
}

#[test]
fn rich_c23_surface_parses_in_each_integration_crate() {
    let src = r#"
        typedef int Int;
        struct P { int x; int y; };
        union U { int i; float f; };
        enum E { A = 1, B, C = 5 };
        _Static_assert(1, "ok");
        static_assert(1);
        thread_local _BitInt(17) bits;
        alignas(16) int expr_aligned;
        alignas(int) int typed_align;
        typeof(1 + 2) expr_type;
        typeof(bits) bit_copy;
        typeof_unqual(int *) ptr;
        struct Forward;
        enum Implicit { IA, IB = 2, };
        int * const const_ptr;
        int unsized[];
        int multi_a, multi_b;
        _Decimal32 d32;
        _Decimal64 d64;
        _Decimal128 d128;
        _Complex double complex_value;

        int g(int x) { return x; }
        void h(void) { return; }

        int f(struct P *p, struct P q, int *a, double d) {
            [[maybe_unused]] int b = true;
            int c = false;
            void *np = nullptr;
            char *s = "hi";
            float fl = 1.25;
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
            if (c) {
                b = b + 1;
            }
            switch (b) {
            case 0:
                break;
            case 1:
                b = 2;
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
        done:
            return g(b ? b : 1) + (b++, b) + _Generic(b, int: b, default: 0)
                + sizeof(int) + sizeof b + alignof b + _Alignof(int) + s[0] + c + (int)fl;
        }
    "#;
    assert_ok_with_dialect(src, Dialect::C23);
}

#[test]
fn edge_parser_paths_run_in_each_integration_crate() {
    assert_ok("");

    assert_ok_with_dialect(
        r#"
            _Noreturn void no_return(void);
            const volatile _Atomic int qualified;
            int * volatile * restrict chain;
            int (*fp)(int, ...);
            enum Forward;
            struct Bits {
                _Static_assert(1, "field ok");
                unsigned x : 3, y;
            };

            int f(void) {
                [[outer([[inner]])]] int value = '\n';
                _Static_assert(1, "block ok");
                f();
                value = (1);
            label_decl:
                int declared_after_label;
            label_assert:
                _Static_assert(1, "label ok");
            label_empty:
                ;
                for (; ; ) {
                    break;
                }
                return value + declared_after_label;
            }

            int g(void) {
            tail_label:
            }
        "#,
        Dialect::C23,
    );

    assert_errors_with_dialect("enum Old { A, };", Dialect::C89);
    assert_errors("enum Bad { ; };");
    assert_errors("_Static_assert(1, 2);");
    assert_errors_with_dialect("static_assert(1);", Dialect::C11);
    assert_errors_with_dialect("int f(void) { f(); int x; return x; }", Dialect::C89);
    assert_errors("int f(void) { do ; }");
    assert_errors("int f(void) { goto ; }");
    assert_errors("int f(void) { .bad = 1; }");
    assert_errors("int f(void) { return 1 int; }");
    assert_errors_with_dialect("[[unterminated int x;", Dialect::C23);
    assert_errors_with_dialect("int f(void) { return alignof; }", Dialect::C23);
}

#[test]
fn expression_and_declarator_edges_run_in_each_integration_crate() {
    assert_ok_with_dialect(
        r#"
            typedef int T;
            int value;
            int (paren_decl);
            int (*nested_fp)(T, ...);
            int matrix[3];
            struct MoreBits {
                int : 0;
                int named : (1 + 2);
            };

            int expr_edges(void) {
                int x = 1;
                return (x) + 1.0 + "s"[0] + 'c' + false + (int){ 1 };
            }
        "#,
        Dialect::C23,
    );

    assert_errors("int f(void) { return value.; }");
    assert_errors("int f(void) { return +; }");
    assert_errors("int f(void) { return (int; }");
    assert_errors("typedef int T; int f(void) { return (T); }");
    assert_errors_with_dialect("void f(int a[static 3]);", Dialect::C23);
    assert_errors_with_dialect("int a[] = { };", Dialect::C11);
    assert_errors_with_dialect("int f(void) { [[unterminated(] return 0; }", Dialect::C23);
}
