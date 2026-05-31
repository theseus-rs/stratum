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
fn collects_global_variable() -> TestResult {
    let ast = build("int x;")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "x")?;
    assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::Variable);
    Ok(())
}

#[test]
fn collects_typedef() -> TestResult {
    let ast = build("typedef int myint;")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "myint")?;
    assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::Typedef);
    Ok(())
}

#[test]
fn collects_function() -> TestResult {
    let ast = build("int main(void) { return 0; }")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    let sym = interned(&ast, "main")?;
    assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::Function);
    Ok(())
}

#[test]
fn function_prototype_is_function() -> TestResult {
    let ast = build("int f(int a);")?;
    let sema = analyze(&ast);
    let sym = interned(&ast, "f")?;
    assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::Function);
    Ok(())
}

#[test]
fn parameters_are_scoped_to_body() -> TestResult {
    let ast = build("int f(int a) { return a; }")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    // After analysis the function scope is popped, so the parameter is not visible globally.
    let sym = interned(&ast, "a")?;
    assert!(sema.symbols.lookup(sym).is_none());
    Ok(())
}

#[test]
fn enum_constants_get_sequential_values() -> TestResult {
    let ast = build("enum Color { Red, Green, Blue };")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    for (name, expected) in [("Red", 0), ("Green", 1), ("Blue", 2)] {
        let sym = interned(&ast, name)?;
        assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::EnumConstant(expected));
    }
    Ok(())
}

#[test]
fn enum_explicit_value_resets_sequence() -> TestResult {
    let ast = build("enum E { A = 5, B, C = 10, D };")?;
    let sema = analyze(&ast);
    for (name, expected) in [("A", 5), ("B", 6), ("C", 10), ("D", 11)] {
        let sym = interned(&ast, name)?;
        assert_eq!(symbol_kind(&sema, sym)?, SymbolKind::EnumConstant(expected));
    }
    Ok(())
}

#[test]
fn enum_non_literal_value_uses_sequence_fallback() -> TestResult {
    let ast = build("enum E { A = 1 + 2, B };")?;
    let sema = analyze(&ast);
    let a = interned(&ast, "A")?;
    let b = interned(&ast, "B")?;
    assert_eq!(symbol_kind(&sema, a)?, SymbolKind::EnumConstant(0));
    assert_eq!(symbol_kind(&sema, b)?, SymbolKind::EnumConstant(1));
    Ok(())
}

#[test]
fn walks_control_flow_bodies_without_errors() -> TestResult {
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
    )?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    Ok(())
}

#[test]
fn conflicting_redeclaration_is_reported() -> TestResult {
    let ast = build("typedef int t; int t;")?;
    let sema = analyze(&ast);
    assert!(sema.has_errors());
    Ok(())
}

#[test]
fn compatible_redeclaration_is_allowed() -> TestResult {
    let ast = build("int f(int a); int f(int a) { return a; }")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    Ok(())
}

#[test]
fn empty_translation_unit_is_clean() -> TestResult {
    let ast = build("")?;
    let sema = analyze(&ast);
    assert!(!sema.has_errors());
    assert!(sema.symbols.globals().is_empty());
    Ok(())
}
