//! Integration tests for `#include` processing: quoted includes, nested includes, header
//! guards, computed includes, and missing-file diagnostics.

mod common;

use common::{assert_errors_with, assert_expands_with};

#[test]
fn quoted_include_inserts_file_contents() {
    assert_expands_with(
        "#include \"a.h\"\nmain",
        &[("a.h", "A_CONTENT\n")],
        "A_CONTENT main",
    );
}

#[test]
fn included_file_is_fully_preprocessed() {
    assert_expands_with(
        "#include \"b.h\"\n#ifdef INB\nyes\n#endif",
        &[("b.h", "#define INB 1\nB_CONTENT\n")],
        "B_CONTENT yes",
    );
}

#[test]
fn nested_includes_are_expanded() {
    assert_expands_with(
        "#include \"nested.h\"\nmain",
        &[
            ("nested.h", "#include \"a.h\"\nNESTED\n"),
            ("a.h", "A_CONTENT\n"),
        ],
        "A_CONTENT NESTED main",
    );
}

#[test]
fn macros_from_include_are_visible_afterwards() {
    assert_expands_with(
        "#include \"def.h\"\nVALUE",
        &[("def.h", "#define VALUE 7\n")],
        "7",
    );
}

#[test]
fn include_guard_prevents_double_inclusion() {
    let guard = "#ifndef G\n#define G\nGUARDED\n#endif\n";
    assert_expands_with(
        "#include \"guard.h\"\n#include \"guard.h\"\nmain",
        &[("guard.h", guard)],
        "GUARDED main",
    );
}

#[test]
fn computed_include_via_macro() {
    assert_expands_with(
        "#define HDR \"a.h\"\n#include HDR\nmain",
        &[("a.h", "A_CONTENT\n")],
        "A_CONTENT main",
    );
}

#[test]
fn empty_included_file_contributes_nothing() {
    assert_expands_with("#include \"empty.h\"\nmain", &[("empty.h", "")], "main");
}

#[test]
fn missing_include_is_an_error() {
    assert_errors_with("#include \"missing.h\"\nx", &[]);
}
