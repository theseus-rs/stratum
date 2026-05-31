//! Parser tests for error reporting: the parser must reject malformed input with a
//! diagnostic rather than panicking or silently accepting it. These cover the common syntax
//! mistakes a real C frontend has to diagnose.

mod common;
use common::{assert_errors, assert_ok};

#[test]
fn missing_semicolon_after_declaration() {
    assert_errors("int x");
}

#[test]
fn missing_semicolon_after_return() {
    assert_errors("int f(void) { return 0 }");
}

#[test]
fn unbalanced_parentheses_in_expression() {
    assert_errors("int f(void) { return (1 + 2; }");
}

#[test]
fn unclosed_brace_initializer() {
    assert_errors("int a[2] = { 1, 2 ;");
}

#[test]
fn missing_value_after_designator() {
    assert_errors("int a[2] = { [0] = };");
}

#[test]
fn dangling_binary_operator() {
    assert_errors("int f(void) { return 1 +; }");
}

#[test]
fn missing_condition_in_if() {
    assert_errors("void f(void) { if () { } }");
}

#[test]
fn unterminated_function_body() {
    assert_errors("int f(void) {");
}

#[test]
fn stray_close_brace() {
    assert_errors("int f(void) { } }");
}

#[test]
fn missing_member_name_after_dot() {
    assert_errors("void f(void) { s. ; }");
}

#[test]
fn empty_translation_unit_is_ok() {
    assert_ok("");
}

#[test]
fn valid_program_after_recovery_point() {
    // A well-formed program with several declarations should not be flagged.
    assert_ok("int a; int b; int f(void) { return a + b; }");
}
