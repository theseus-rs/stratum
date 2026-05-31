//! Integration tests for object-like macro definition and expansion.

mod common;

use common::{assert_errors, assert_expands};

#[test]
fn simple_object_macro_substitutes() {
    assert_expands("#define A 1\nA", "1");
}

#[test]
fn object_macro_used_multiple_times() {
    assert_expands("#define A 1\nA + A", "1 + 1");
}

#[test]
fn empty_object_macro_vanishes() {
    assert_expands("#define E\nE x E", "x");
}

#[test]
fn macro_body_with_multiple_tokens() {
    assert_expands("#define PAIR 1 , 2\nPAIR", "1 , 2");
}

#[test]
fn macro_expands_to_another_macro() {
    assert_expands("#define A B\n#define B 7\nA", "7");
}

#[test]
fn macro_referencing_itself_is_blue_painted() {
    assert_expands("#define A A\nA", "A");
}

#[test]
fn indirect_self_reference_terminates() {
    assert_expands("#define A B\n#define B A\nA", "A");
}

#[test]
fn redefinition_with_identical_body_is_allowed() {
    assert_expands("#define A 1\n#define A 1\nA", "1");
}

#[test]
fn undef_removes_definition() {
    assert_expands("#define X 5\n#undef X\nX", "X");
}

#[test]
fn undef_of_undefined_macro_is_harmless() {
    assert_expands("#undef NEVER\nok", "ok");
}

#[test]
fn redefine_after_undef() {
    assert_expands("#define X 1\n#undef X\n#define X 2\nX", "2");
}

#[test]
fn object_macro_only_replaces_whole_identifiers() {
    assert_expands("#define A 1\nApple A", "Apple 1");
}

#[test]
fn macro_in_expression_context() {
    assert_expands("#define N 10\nint a[N];", "int a [ 10 ] ;");
}

#[test]
fn chained_object_macros() {
    assert_expands("#define A B\n#define B C\n#define C 42\nA", "42");
}

#[test]
fn define_without_replacement_is_defined() {
    assert_expands("#define FLAG\n#ifdef FLAG\nyes\n#endif", "yes");
}

#[test]
fn macro_name_missing_is_an_error() {
    assert_errors("#define\nx");
}
