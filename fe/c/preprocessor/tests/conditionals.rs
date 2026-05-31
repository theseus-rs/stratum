//! Integration tests for conditional compilation: `#if`/`#ifdef`/`#ifndef`/`#elif`/`#else`/
//! `#endif` and the `#if` constant-expression evaluator.

mod common;

use common::{assert_errors, assert_expands};

// --- #ifdef / #ifndef --------------------------------------------------------------------

#[test]
fn ifdef_taken_when_defined() {
    assert_expands("#define FOO\n#ifdef FOO\nyes\n#endif", "yes");
}

#[test]
fn ifdef_skipped_when_undefined() {
    assert_expands("#ifdef FOO\nyes\n#endif", "");
}

#[test]
fn ifndef_taken_when_undefined() {
    assert_expands("#ifndef FOO\nyes\n#endif", "yes");
}

#[test]
fn ifndef_skipped_when_defined() {
    assert_expands("#define FOO 1\n#ifndef FOO\na\n#else\nb\n#endif", "b");
}

#[test]
fn ifdef_else_branch() {
    assert_expands("#ifdef FOO\na\n#else\nb\n#endif", "b");
}

// --- defined() operator ------------------------------------------------------------------

#[test]
fn defined_with_parentheses() {
    assert_expands("#define FOO\n#if defined(FOO)\na\n#endif", "a");
}

#[test]
fn defined_without_parentheses() {
    assert_expands("#if defined FOO\na\n#else\nb\n#endif", "b");
}

#[test]
fn not_defined_operator() {
    assert_expands("#if !defined(FOO)\na\n#endif", "a");
}

#[test]
fn undefined_identifier_evaluates_to_zero() {
    assert_expands("#if UNDEFINED\na\n#else\nb\n#endif", "b");
}

// --- Constant-expression evaluation ------------------------------------------------------

#[test]
fn arithmetic_precedence() {
    assert_expands("#if 2+3*4 == 14\nok\n#endif", "ok");
}

#[test]
fn parentheses_and_shift() {
    assert_expands("#if (1<<4) == 16\nok\n#endif", "ok");
}

#[test]
fn hexadecimal_literal() {
    assert_expands("#if 0x10 == 16\nok\n#endif", "ok");
}

#[test]
fn integer_division_truncates() {
    assert_expands("#if 10 / 3 == 3\nok\n#endif", "ok");
}

#[test]
fn modulo_operator() {
    assert_expands("#if 5 % 2 == 1\nok\n#endif", "ok");
}

#[test]
fn bitwise_not() {
    assert_expands("#if ~0 == -1\nok\n#endif", "ok");
}

#[test]
fn logical_and() {
    assert_expands("#if 1 && 0\na\n#else\nb\n#endif", "b");
}

#[test]
fn logical_or() {
    assert_expands("#if 1 || 0\na\n#endif", "a");
}

#[test]
fn ternary_in_condition() {
    assert_expands("#if 1 ? 2 : 3\nok\n#endif", "ok");
}

#[test]
fn character_constant_in_condition() {
    assert_expands("#if 'A' == 65\nok\n#endif", "ok");
}

#[test]
fn macro_expanded_in_condition() {
    assert_expands("#define N 3\n#if N > 2\nbig\n#endif", "big");
}

// --- #elif chains and nesting ------------------------------------------------------------

#[test]
fn elif_first_true_branch_wins() {
    assert_expands("#if 1\nA\n#elif 1\nB\n#else\nC\n#endif", "A");
}

#[test]
fn elif_selected_when_if_false() {
    assert_expands("#if 0\na\n#elif 1\nx\n#endif", "x");
}

#[test]
fn elif_else_fallthrough() {
    assert_expands(
        "#if defined(FOO)\na\n#elif defined(BAR)\nb\n#else\nc\n#endif",
        "c",
    );
}

#[test]
fn nested_conditionals() {
    assert_expands("#if 1\n#if 0\na\n#else\nb\n#endif\n#endif", "b");
}

#[test]
fn skipped_block_does_not_evaluate_directives() {
    assert_expands("#if 0\n#error should not fire\n#endif\nok", "ok");
}

// --- Error cases -------------------------------------------------------------------------

#[test]
fn empty_if_condition_is_an_error() {
    assert_errors("#if\nx\n#endif");
}

#[test]
fn endif_without_if_is_an_error() {
    assert_errors("#endif");
}

#[test]
fn ifdef_without_name_is_an_error() {
    assert_errors("#ifdef\nx\n#endif");
}
