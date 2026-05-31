//! Shared helpers for the C preprocessor integration tests.
//!
//! These drive [`preprocess`](stratum_c_preprocessor::preprocess) over an in-memory source
//! (optionally with virtual header files) and render the expanded preprocessing-token stream
//! to a normalised, whitespace-insensitive string so test groups can assert precisely on the
//! result of macro expansion, conditional inclusion, and directive handling.

#![allow(dead_code)]

use stratum_arena::Interner;
use stratum_c_lexer::{PpTokenKind, Punctuator};
use stratum_c_preprocessor::{MapIncludeResolver, preprocess};
use stratum_diagnostics::{Severity, SourceMap};

/// The outcome of preprocessing a source string.
pub struct Expanded {
    /// The significant preprocessing tokens, rendered and joined by single spaces.
    pub tokens: String,
    /// The rendered diagnostic messages, in order.
    pub diagnostics: Vec<String>,
    /// Whether any error-severity diagnostic was produced.
    pub has_errors: bool,
}

/// Preprocesses `src` with no available header files.
#[must_use]
pub fn run(src: &str) -> Expanded {
    run_with(src, &[])
}

/// Preprocesses `src` with the given `(name, contents)` virtual header files available to
/// `#include`.
#[must_use]
pub fn run_with(src: &str, headers: &[(&str, &str)]) -> Expanded {
    let mut map = SourceMap::new();
    let file = map.add_root("main.c", src);
    let mut interner = Interner::new();
    let mut resolver = MapIncludeResolver::new();
    for (name, contents) in headers {
        resolver.insert(*name, *contents);
    }

    let Ok(file) = file else {
        return Expanded {
            tokens: String::new(),
            diagnostics: vec!["failed to add source file".to_string()],
            has_errors: true,
        };
    };

    let result = preprocess(file, src, &mut interner, &mut map, &mut resolver);
    let tokens = render(&result.tokens, &interner);
    let diagnostics = result
        .diagnostics
        .iter()
        .map(|d| d.message().to_string())
        .collect();
    let has_errors = result
        .diagnostics
        .iter()
        .any(|d| d.severity() == Severity::Error);

    Expanded {
        tokens,
        diagnostics,
        has_errors,
    }
}

/// Asserts that `src` preprocesses without error and yields exactly `expected` tokens.
pub fn assert_expands(src: &str, expected: &str) {
    let out = run(src);
    assert!(
        !out.has_errors,
        "unexpected errors for {src:?}: {:#?}",
        out.diagnostics
    );
    assert_eq!(out.tokens, expected, "mismatch for source: {src:?}");
}

/// Asserts that `src` (with the given headers) preprocesses without error to `expected`.
pub fn assert_expands_with(src: &str, headers: &[(&str, &str)], expected: &str) {
    let out = run_with(src, headers);
    assert!(
        !out.has_errors,
        "unexpected errors for {src:?}: {:#?}",
        out.diagnostics
    );
    assert_eq!(out.tokens, expected, "mismatch for source: {src:?}");
}

/// Asserts that `src` produces at least one error diagnostic.
pub fn assert_errors(src: &str) {
    let out = run(src);
    assert!(
        out.has_errors,
        "expected {src:?} to error, but it expanded to: {}",
        out.tokens
    );
}

/// Asserts that `src` (with the given headers) produces at least one error diagnostic.
pub fn assert_errors_with(src: &str, headers: &[(&str, &str)]) {
    let out = run_with(src, headers);
    assert!(
        out.has_errors,
        "expected {src:?} to error, but it expanded to: {}",
        out.tokens
    );
}

/// Renders the significant preprocessing tokens (dropping newlines) to a single string.
fn render(tokens: &[stratum_c_lexer::PpToken], interner: &Interner) -> String {
    let mut out = Vec::new();
    for token in tokens {
        let rendered = match token.kind {
            PpTokenKind::Identifier(sym)
            | PpTokenKind::Number(sym)
            | PpTokenKind::CharConst(sym)
            | PpTokenKind::StringLit(sym) => interner
                .resolve(sym)
                .map_or_else(|_| "<invalid>".to_string(), str::to_string),
            PpTokenKind::Punct(p) => Punctuator::spelling(p).to_string(),
            PpTokenKind::Newline => continue,
            PpTokenKind::Other(c) => c.to_string(),
        };
        out.push(rendered);
    }
    out.join(" ")
}
