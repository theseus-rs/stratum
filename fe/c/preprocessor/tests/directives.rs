//! Integration tests for miscellaneous directives and lexical preprocessing concerns:
//! `#pragma`, `#error`, `#line`, the null directive, unknown directives, line splicing, and
//! comment handling.

mod common;

use common::{assert_errors, assert_expands};

// --- #pragma -----------------------------------------------------------------------------

#[test]
fn pragma_once_is_accepted() {
    assert_expands("#pragma once\nx", "x");
}

#[test]
fn unknown_pragma_is_ignored() {
    assert_expands("#pragma FOO diagnostic\nx", "x");
}

// --- #error ------------------------------------------------------------------------------

#[test]
fn error_directive_reports_diagnostic() {
    assert_errors("#error boom\n");
}

#[test]
fn empty_error_directive_still_reports() {
    assert_errors("#error\n");
}

#[test]
fn error_in_skipped_branch_does_not_fire() {
    assert_expands("#if 0\n#error nope\n#endif\nok", "ok");
}

// --- #line -------------------------------------------------------------------------------

#[test]
fn line_directive_is_accepted() {
    assert_expands("#line 100\nx", "x");
}

// --- Null and unknown directives ---------------------------------------------------------

#[test]
fn null_directive_is_harmless() {
    assert_expands("#\nx", "x");
}

#[test]
fn unknown_directive_is_an_error() {
    assert_errors("#unknown\nok");
}

// --- Whitespace and lexical preprocessing ------------------------------------------------

#[test]
fn whitespace_around_directive_is_tolerated() {
    assert_expands("   #   define   A   1  \nA", "1");
}

#[test]
fn line_splicing_joins_logical_lines() {
    assert_expands("a \\\nb", "a b");
}

#[test]
fn spliced_define_continues_macro_body() {
    assert_expands("#define A 1 + \\\n2\nA", "1 + 2");
}

#[test]
fn block_comment_becomes_whitespace() {
    assert_expands("int /* comment */ x;", "int x ;");
}

#[test]
fn line_comment_is_stripped() {
    assert_expands("// line comment\nx", "x");
}

#[test]
fn trailing_line_comment_in_macro_body() {
    assert_expands("#define A 1 // trailing\nA", "1");
}
