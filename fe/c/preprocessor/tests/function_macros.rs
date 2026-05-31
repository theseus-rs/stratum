//! Integration tests for function-like macros: parameters, `#`, `##`, rescanning,
//! blue-painting, and variadic (`...` / `__VA_ARGS__`) macros.

mod common;

use common::{assert_errors, assert_expands};

#[test]
fn simple_function_macro() {
    assert_expands("#define ID(x) x\nID(42)", "42");
}

#[test]
fn function_macro_with_two_params() {
    assert_expands("#define ADD(a,b) a + b\nADD(1,2)", "1 + 2");
}

#[test]
fn parenthesized_macro_protects_precedence() {
    assert_expands("#define SQ(x) ((x)*(x))\nSQ(3)", "( ( 3 ) * ( 3 ) )");
}

#[test]
fn macro_without_parens_is_not_invoked() {
    assert_expands("#define F(x) x\nF + 1", "F + 1");
}

#[test]
fn empty_argument_list() {
    assert_expands("#define NOW() 1\nNOW()", "1");
}

#[test]
fn argument_is_itself_expanded() {
    assert_expands("#define A 5\n#define ID(x) x\nID(A)", "5");
}

#[test]
fn nested_invocation_of_same_macro() {
    assert_expands(
        "#define INC(x) ((x)+1)\nINC(INC(1))",
        "( ( ( ( 1 ) + 1 ) ) + 1 )",
    );
}

#[test]
fn conditional_expression_macro() {
    assert_expands(
        "#define MAX(a,b) ((a)>(b)?(a):(b))\nMAX(1,2)",
        "( ( 1 ) > ( 2 ) ? ( 1 ) : ( 2 ) )",
    );
}

#[test]
fn macro_result_participates_in_surrounding_expression() {
    assert_expands("#define ADD(a,b) a+b\nADD(1,2)*3", "1 + 2 * 3");
}

#[test]
fn too_few_arguments_is_an_error() {
    assert_errors("#define F(a,b) a b\nF(1)");
}

#[test]
fn too_many_arguments_is_an_error() {
    assert_errors("#define F(a,b) a b\nF(1,2,3)");
}

#[test]
fn function_macro_name_without_call_passes_through() {
    assert_expands("#define t(a) a\nt(t)(1)", "t ( 1 )");
}

// --- Stringizing (`#`) -------------------------------------------------------------------

#[test]
fn stringize_parameter() {
    assert_expands("#define STR(x) #x\nSTR(hello)", "\"hello\"");
}

#[test]
fn stringize_collapses_internal_whitespace() {
    assert_expands("#define STR(x) #x\nSTR(a   b)", "\"a b\"");
}

#[test]
fn stringize_does_not_expand_argument() {
    assert_expands("#define V 99\n#define STR(x) #x\nSTR(V)", "\"V\"");
}

#[test]
fn indirect_stringize_expands_first() {
    assert_expands(
        "#define STR(x) #x\n#define XSTR(x) STR(x)\n#define V 99\nXSTR(V)",
        "\"99\"",
    );
}

// --- Token pasting (`##`) ----------------------------------------------------------------

#[test]
fn paste_two_identifiers() {
    assert_expands("#define CAT(a,b) a##b\nCAT(foo,bar)", "foobar");
}

#[test]
fn paste_ignores_surrounding_whitespace() {
    assert_expands("#define CAT(a,b) a ## b\nCAT(   x  ,  y  )", "xy");
}

#[test]
fn paste_digits_forms_number() {
    assert_expands("#define CAT(a,b) a##b\nCAT(1,2)", "12");
}

#[test]
fn paste_result_is_rescanned_for_macros() {
    assert_expands(
        "#define glue(a,b) a##b\n#define xglue(a,b) glue(a,b)\nxglue(1,2)",
        "12",
    );
}

// --- Variadic macros (C99) ---------------------------------------------------------------

#[test]
fn variadic_macro_forwards_all_arguments() {
    assert_expands("#define V(...) __VA_ARGS__\nV(1,2,3)", "1 , 2 , 3");
}

#[test]
fn variadic_macro_with_leading_named_param() {
    assert_expands("#define V(a,...) a : __VA_ARGS__\nV(x,1,2)", "x : 1 , 2");
}

#[test]
fn variadic_macro_with_single_variadic_argument() {
    assert_expands("#define V(...) [__VA_ARGS__]\nV(only)", "[ only ]");
}
