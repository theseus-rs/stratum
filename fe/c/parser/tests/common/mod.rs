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
