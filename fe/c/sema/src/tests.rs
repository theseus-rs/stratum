//! Unit tests for the semantic-analysis pass.

use crate::alloc_prelude::*;
use crate::{SemaResult, SymbolKind, analyze};
use stratum_arena::Interner;
use stratum_arena::Symbol;
use stratum_c_ast::CAst;
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Parses `src` into a `CAst`, returning the AST.
fn build(src: &str) -> TestResult<CAst> {
    let mut map = SourceMap::new();
    let file = map.add_root("test.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;
    Ok(parsed.ast)
}

fn interned(ast: &CAst, name: &str) -> TestResult<Symbol> {
    ast.interner()
        .get(name)
        .ok_or_else(|| std::io::Error::other(format!("{name} was not interned")).into())
}

fn symbol_kind(sema: &SemaResult, sym: Symbol) -> TestResult<SymbolKind> {
    Ok(sema
        .symbols
        .lookup(sym)
        .ok_or_else(|| std::io::Error::other("symbol was not defined"))?
        .kind)
}

#[test]
fn collects_global_variable() {
    let ast = build("int x;").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "x").unwrap();
    assert_eq!(symbol_kind(&sema, sym).unwrap(), SymbolKind::Variable);
}

#[test]
fn collects_typedef() {
    let ast = build("typedef int myint;").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "myint").unwrap();
    assert_eq!(symbol_kind(&sema, sym).unwrap(), SymbolKind::Typedef);
}

#[test]
fn collects_function() {
    let ast = build("int main(void) { return 0; }").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "main").unwrap();
    assert_eq!(symbol_kind(&sema, sym).unwrap(), SymbolKind::Function);
}

#[test]
fn function_prototype_is_function() {
    let ast = build("int f(int a);").unwrap();
    let sema = analyze(&ast);
    let sym = interned(&ast, "f").unwrap();
    assert_eq!(symbol_kind(&sema, sym).unwrap(), SymbolKind::Function);
}

#[test]
fn parameters_are_scoped_to_body() {
    let ast = build("int f(int a) { return a; }").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    // After analysis the function scope is popped, so the parameter is not visible globally.
    let sym = interned(&ast, "a").unwrap();
    assert!(sema.symbols.lookup(sym).is_none());
}

#[test]
fn enum_constants_get_sequential_values() {
    let ast = build("enum Color { Red, Green, Blue };").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    for (name, expected) in [("Red", 0), ("Green", 1), ("Blue", 2)] {
        let sym = interned(&ast, name).unwrap();
        assert_eq!(
            symbol_kind(&sema, sym).unwrap(),
            SymbolKind::EnumConstant(expected)
        );
    }
}

#[test]
fn enum_explicit_value_resets_sequence() {
    let ast = build("enum E { A = 5, B, C = 10, D };").unwrap();
    let sema = analyze(&ast);
    for (name, expected) in [("A", 5), ("B", 6), ("C", 10), ("D", 11)] {
        let sym = interned(&ast, name).unwrap();
        assert_eq!(
            symbol_kind(&sema, sym).unwrap(),
            SymbolKind::EnumConstant(expected)
        );
    }
}

#[test]
fn enum_non_literal_value_uses_sequence_fallback() {
    let ast = build("enum E { A = 1 + 2, B };").unwrap();
    let sema = analyze(&ast);
    let a = interned(&ast, "A").unwrap();
    let b = interned(&ast, "B").unwrap();
    assert_eq!(symbol_kind(&sema, a).unwrap(), SymbolKind::EnumConstant(0));
    assert_eq!(symbol_kind(&sema, b).unwrap(), SymbolKind::EnumConstant(1));
}

#[test]
fn walks_control_flow_bodies_without_errors() {
    let ast = build(
        "
        void f(int x) {
            if (x) { int t; } else { int e; }
            while (x) { int w; }
            do { int d; } while (x);
            switch (x) { case 1: { int c; } default: { int e; } }
            label: { int l; }
            for (int i = 0; x; x = x) { int body; }
        }
        ",
    )
    .unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
}

#[test]
fn conflicting_redeclaration_is_reported() {
    let ast = build("typedef int t; int t;").unwrap();
    let sema = analyze(&ast);
    assert!(sema.has_errors());
}

#[test]
fn compatible_redeclaration_is_allowed() {
    let ast = build("int f(int a); int f(int a) { return a; }").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
}

#[test]
fn empty_translation_unit_is_clean() {
    let ast = build("").unwrap();
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    assert!(sema.symbols.globals().is_empty());
}
