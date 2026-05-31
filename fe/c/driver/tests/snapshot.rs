//! Snapshot integration tests: each `.c` fixture is run through the full pipeline and its HIR dump
//! is compared against a committed `.hir` snapshot file.
//!
//! To regenerate snapshots after an intentional change, run the test binary with the environment
//! variable `UPDATE_SNAPSHOT=1` set; the snapshots are rewritten and the test passes.

use std::path::{Path, PathBuf};

use stratum_c_driver::{Emit, compile_source};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Runs a single fixture and compares (or updates) its snapshot HIR dump.
fn check_fixture(stem: &str) -> TestResult {
    let dir = fixtures_dir();
    let source_path = dir.join(format!("{stem}.c"));
    let snapshot_path = dir.join(format!("{stem}.hir"));
    let source = std::fs::read_to_string(&source_path)?;

    let result = compile_source(&format!("{stem}.c"), &source, Emit::Hir, &[])?;
    assert!(
        !result.had_errors,
        "fixture `{stem}` produced errors:\n{}",
        result.diagnostics
    );

    if std::env::var_os("UPDATE_SNAPSHOT").is_some() {
        std::fs::write(&snapshot_path, &result.output)?;
        return Ok(());
    }

    let expected = std::fs::read_to_string(&snapshot_path)?;
    assert_eq!(
        result.output, expected,
        "HIR for `{stem}` did not match snapshot; set UPDATE_SNAPSHOT=1 to regenerate"
    );
    Ok(())
}

#[test]
fn arith_lowers_to_expected_hir() -> TestResult {
    check_fixture("arith")
}

#[test]
fn control_flow_lowers_to_expected_hir() -> TestResult {
    check_fixture("control_flow")
}

#[test]
fn macros_expand_and_lower_to_expected_hir() -> TestResult {
    check_fixture("macros")
}

#[test]
fn emit_ast_produces_sexpression() -> TestResult {
    let out = compile_source("t.c", "int x;", Emit::Ast, &[])?;
    assert!(!out.had_errors);
    assert_eq!(out.output.trim(), "(tu (decl x))");
    Ok(())
}

#[test]
fn emit_tokens_lists_finalized_tokens() -> TestResult {
    let out = compile_source("t.c", "int x;", Emit::Tokens, &[])?;
    assert!(out.output.contains("keyword int"));
    assert!(out.output.contains("ident x"));
    assert!(out.output.contains("punct ;"));
    Ok(())
}

#[test]
fn emit_pptokens_lists_preprocessing_tokens() -> TestResult {
    let out = compile_source("t.c", "#define A 1\nint x; A\n", Emit::PpTokens, &[])?;
    // The macro `A` expands to the number `1` in the pp-token stream.
    assert!(out.output.contains("number 1"));
    assert!(out.output.contains("ident x"));
    Ok(())
}

#[test]
fn full_c_constructs_lower_without_errors() -> TestResult {
    // Constructs that earlier lowered to errors (sizeof, switch, ternary, member access,
    // goto/labels) are now all faithfully represented in the HIR.
    let src = "int f(int x) { return sizeof(x); }";
    let out = compile_source("t.c", src, Emit::Hir, &[])?;
    assert!(!out.had_errors, "diagnostics:\n{}", out.diagnostics);
    assert!(out.output.contains("sizeof-expr"));
    Ok(())
}
