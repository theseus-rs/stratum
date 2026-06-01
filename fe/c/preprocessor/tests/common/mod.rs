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
use stratum_diagnostics::SourceMap;

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
    let has_errors = result.has_errors();

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

#[test]
fn rich_preprocessor_surface_expands_in_each_integration_crate() {
    let src = r#"
        #
        #define H "hdr.h"
        #include H
        #include <angle.h>
        #define X 1
        #define ADD(a, b) a + b
        #define ZERO() zero
        #define STR(x) #x
        #define HASH_TAIL(x) #
        #define HASH_PLUS(x) # + x
        #define CAT(a, b) a ## b
        #define VA(a, ...) a : __VA_ARGS__
        #define ONLYVA(...) __VA_ARGS__
        #if defined X && (X + 1) == 2
        CAT(ma, in) ADD(1, 2) ZERO()
        #elif 1
        skipped
        #else
        skipped
        #endif
        #undef X
        #ifndef X
        STR(hello   world)
        HASH_TAIL(a)
        HASH_PLUS(a)
        VA(x, y, z)
        ONLYVA()
        #endif
        #if 0
        #error skipped
        #else
        ok
        #endif
        #if '\'' == 39 && '\0' == 0 && '\z' == 122
        chars
        #endif
        #if 'A' == 65 && '' == 0
        char_edges
        #endif
        #define VEMPTY(a, ...) a __VA_ARGS__
        VEMPTY(edge)
    "#;
    let out = run_with(src, &[("hdr.h", "from_hdr\n"), ("angle.h", "from_angle\n")]);
    assert!(
        !out.has_errors,
        "unexpected diagnostics: {:#?}",
        out.diagnostics
    );
    assert!(out.tokens.contains("from_hdr from_angle"));
    assert!(out.tokens.contains("main 1 + 2 zero"));
    assert!(out.tokens.contains("\"hello world\""));
    assert!(out.tokens.contains("# # + a"));
    assert!(out.tokens.contains("x : y , z"));
    assert!(out.tokens.ends_with("ok chars char_edges edge"));
}

#[test]
fn directive_edges_expand_in_each_integration_crate() {
    assert_expands(
        "#define X 1\n#if 0\nno\n#elif defined(X)\nyes\n#else\nno\n#endif",
        "yes",
    );
    assert_expands_with(
        "#define H \"outer.h\"\n#include H\n#pragma once\n#line 12\nok",
        &[
            ("outer.h", "#include <inner.h>\nouter\n"),
            ("inner.h", "inner\n"),
        ],
        "inner outer ok",
    );
}

#[test]
fn directive_errors_report_in_each_integration_crate() {
    let out = run("#error boom\n#unknown\n# 123\n#else\n#endif\n#define ONE(a) a\nONE()\n");
    assert!(out.has_errors, "expected directive diagnostics");
    assert!(
        out.diagnostics
            .iter()
            .any(|message| message.contains("#error boom")),
        "missing #error diagnostic: {:#?}",
        out.diagnostics
    );
    assert!(
        out.diagnostics
            .iter()
            .any(|message| message.contains("unknown preprocessing directive")),
        "missing unknown-directive diagnostic: {:#?}",
        out.diagnostics
    );
}

#[test]
fn preprocessor_error_edges_run_in_each_integration_crate() {
    for src in [
        "#undef\n",
        "#ifdef\n#endif\n",
        "#elif 1\n",
        "#if 0\n#else\n#elif 1\n#endif\n",
        "#if 0\n#else\n#else\n#endif\n",
        "#if defined(123)\n#endif\n",
        "#if defined(FOO + 1)\n#endif\n",
        "#if (1\n#endif\n",
        "#if BAD +\n#endif\n",
        "#include\n",
        "#include 123\n",
        "#include <missing\n",
        "#define BAD(a) a\nBAD(1\n",
        "#define BAD(a) a\nBAD()\n",
        "#define MALFORMED(\n",
    ] {
        assert_errors(src);
    }
    assert_errors_with("#include <missing header.h>\n", &[]);
}

#[test]
fn macro_paste_edges_run_in_each_integration_crate() {
    assert_expands(
        "#define PASTE_RIGHT(...) __VA_ARGS__ ## b\nPASTE_RIGHT()",
        "b",
    );
    assert_expands(
        "#define PASTE_EMPTY(a, ...) a ## __VA_ARGS__\nPASTE_EMPTY(a)",
        "a",
    );
}
