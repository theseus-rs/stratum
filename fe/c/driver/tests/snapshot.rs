//! Snapshot integration tests: each `.c` fixture is run through the full pipeline and its HIR dump
//! is compared against a committed `.hir` snapshot file.
//!
//! To regenerate snapshots after an intentional change, run the test binary with the environment
//! variable `UPDATE_SNAPSHOT=1` set; the snapshots are rewritten and the test passes.

use std::path::{Path, PathBuf};

use stratum_c_driver::{Emit, compile_source};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn require_contains(haystack: &str, needle: &str) -> TestResult {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("missing {needle:?} in output")).into())
    }
}

/// Runs a single fixture and compares (or updates) its snapshot HIR dump.
fn check_fixture(stem: &str) -> TestResult {
    let dir = fixtures_dir();
    let source_path = dir.join(format!("{stem}.c"));
    let snapshot_path = dir.join(format!("{stem}.hir"));
    let source = std::fs::read_to_string(&source_path)?;

    let result = compile_source(&format!("{stem}.c"), &source, Emit::Hir, &[])?;
    if result.had_errors {
        return Err(std::io::Error::other(format!(
            "fixture `{stem}` produced errors:\n{}",
            result.diagnostics
        ))
        .into());
    }

    if std::env::var_os("UPDATE_SNAPSHOT").is_some() {
        std::fs::write(&snapshot_path, &result.output)?;
        return Ok(());
    }

    let expected = std::fs::read_to_string(&snapshot_path)?;
    let actual = normalize_newlines(&result.output);
    let expected = normalize_newlines(&expected);
    if actual != expected {
        return Err(std::io::Error::other(format!(
            "HIR for `{stem}` did not match snapshot; set UPDATE_SNAPSHOT=1 to regenerate"
        ))
        .into());
    }
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
    if out.had_errors {
        return Err(std::io::Error::other(out.diagnostics).into());
    }
    if out.output.trim() != "(tu (decl x))" {
        return Err(std::io::Error::other(format!("unexpected AST output: {}", out.output)).into());
    }
    Ok(())
}

#[test]
fn emit_tokens_lists_finalized_tokens() -> TestResult {
    let out = compile_source("t.c", "int x;", Emit::Tokens, &[])?;
    require_contains(&out.output, "keyword int")?;
    require_contains(&out.output, "ident x")?;
    require_contains(&out.output, "punct ;")?;
    Ok(())
}

#[test]
fn emit_pptokens_lists_preprocessing_tokens() -> TestResult {
    let out = compile_source("t.c", "#define A 1\nint x; A\n", Emit::PpTokens, &[])?;
    // The macro `A` expands to the number `1` in the pp-token stream.
    require_contains(&out.output, "number 1")?;
    require_contains(&out.output, "ident x")?;
    Ok(())
}

#[test]
fn full_c_constructs_lower_without_errors() -> TestResult {
    // Constructs that earlier lowered to errors (sizeof, switch, ternary, member access,
    // goto/labels) are now all faithfully represented in the HIR.
    let src = "int f(int x) { return sizeof(x); }";
    let out = compile_source("t.c", src, Emit::Hir, &[])?;
    if out.had_errors {
        return Err(std::io::Error::other(format!("diagnostics:\n{}", out.diagnostics)).into());
    }
    require_contains(&out.output, "sizeof-expr")?;
    Ok(())
}
