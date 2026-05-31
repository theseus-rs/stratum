//! Unit tests for the C preprocessor.

use crate::alloc_prelude::*;
use crate::preprocessor::PreprocessResult;
use crate::{IncludeResolver, MapIncludeResolver, preprocess};
use stratum_arena::Interner;
use stratum_c_lexer::{PpToken, PpTokenKind};
use stratum_diagnostics::SourceMap;

/// Preprocesses `src` against a resolver and returns rendered token spellings + the result.
fn run_with<R: IncludeResolver>(src: &str, resolver: &mut R) -> (Vec<String>, PreprocessResult) {
    let mut map = SourceMap::new();
    let file = map.add_root("main.c", src).unwrap();
    let mut interner = Interner::new();
    let result = preprocess(file, src, &mut interner, &mut map, resolver);
    let rendered = result.tokens.iter().map(|t| render(t, &interner)).collect();
    (rendered, result)
}

fn run(src: &str) -> Vec<String> {
    let mut resolver = MapIncludeResolver::new();
    run_with(src, &mut resolver).0
}

fn render(token: &PpToken, interner: &Interner) -> String {
    match token.kind {
        PpTokenKind::Identifier(s)
        | PpTokenKind::Number(s)
        | PpTokenKind::CharConst(s)
        | PpTokenKind::StringLit(s) => interner.resolve(s).unwrap().to_string(),
        PpTokenKind::Punct(p) => p.spelling().to_string(),
        PpTokenKind::Newline => "\\n".to_string(),
        PpTokenKind::Other(c) => c.to_string(),
    }
}

#[test]
fn object_macro_expands() {
    assert_eq!(
        run("#define N 42\nint x = N;\n"),
        ["int", "x", "=", "42", ";"]
    );
}

#[test]
fn object_macro_recursion_is_painted() {
    assert_eq!(run("#define A A\nA\n"), ["A"]);
}

#[test]
fn function_macro_substitutes_arguments() {
    let out = run("#define ADD(a, b) ((a) + (b))\nADD(1, 2)\n");
    assert_eq!(out, ["(", "(", "1", ")", "+", "(", "2", ")", ")"]);
}

#[test]
fn function_macro_without_parens_is_left_alone() {
    assert_eq!(run("#define F(x) x\nF + 1\n"), ["F", "+", "1"]);
}

#[test]
fn argument_is_macro_expanded_before_substitution() {
    let out = run("#define ONE 1\n#define ID(x) x\nID(ONE)\n");
    assert_eq!(out, ["1"]);
}

#[test]
fn stringize_operator() {
    let out = run("#define STR(x) #x\nSTR(a b)\n");
    assert_eq!(out, ["\"a b\""]);
}

#[test]
fn token_paste_operator() {
    let out = run("#define CAT(a, b) a ## b\nCAT(foo, bar)\n");
    assert_eq!(out, ["foobar"]);
}

#[test]
fn undef_removes_macro() {
    let out = run("#define N 1\n#undef N\nN\n");
    assert_eq!(out, ["N"]);
}

#[test]
fn ifdef_selects_branch() {
    let out = run("#define ON\n#ifdef ON\nyes\n#else\nno\n#endif\n");
    assert_eq!(out, ["yes"]);
}

#[test]
fn ifndef_selects_branch() {
    let out = run("#ifndef OFF\nyes\n#else\nno\n#endif\n");
    assert_eq!(out, ["yes"]);
}

#[test]
fn if_expression_with_arithmetic() {
    let out = run("#if 2 + 3 > 4\nbig\n#else\nsmall\n#endif\n");
    assert_eq!(out, ["big"]);
}

#[test]
fn elif_chain() {
    let src = "#if 0\na\n#elif 1\nb\n#else\nc\n#endif\n";
    assert_eq!(run(src), ["b"]);
}

#[test]
fn defined_operator() {
    let out = run("#define X\n#if defined(X) && !defined(Y)\nok\n#endif\n");
    assert_eq!(out, ["ok"]);
}

#[test]
fn nested_inactive_conditionals_are_skipped() {
    let src = "#if 0\n#if 1\na\n#endif\nb\n#endif\nc\n";
    assert_eq!(run(src), ["c"]);
}

#[test]
fn include_is_expanded_inline() {
    let mut resolver = MapIncludeResolver::new().with_file("hdr.h", "int from_header;\n");
    let (out, result) = run_with("#include \"hdr.h\"\nint main;\n", &mut resolver);
    assert!(!result.has_errors());
    assert_eq!(out, ["int", "from_header", ";", "int", "main", ";"]);
}

#[test]
fn macro_defined_in_header_is_visible() {
    let mut resolver = MapIncludeResolver::new().with_file("def.h", "#define HALF 21\n");
    let (out, _) = run_with("#include \"def.h\"\nint x = HALF * 2;\n", &mut resolver);
    assert_eq!(out, ["int", "x", "=", "21", "*", "2", ";"]);
}

#[test]
fn angle_include_resolves() {
    let mut resolver = MapIncludeResolver::new().with_file("sys.h", "long sys;\n");
    let (out, result) = run_with("#include <sys.h>\n", &mut resolver);
    assert!(!result.has_errors());
    assert_eq!(out, ["long", "sys", ";"]);
}

#[test]
fn missing_include_is_an_error() {
    let mut resolver = MapIncludeResolver::new();
    let (_, result) = run_with("#include \"nope.h\"\n", &mut resolver);
    assert!(result.has_errors());
}

#[test]
fn error_directive_reports() {
    let mut resolver = MapIncludeResolver::new();
    let (_, result) = run_with("#error something broke\n", &mut resolver);
    assert!(result.has_errors());
}

#[test]
fn variadic_macro_collects_rest() {
    let out = run("#define CALL(f, ...) f(__VA_ARGS__)\nCALL(g, 1, 2, 3)\n");
    assert_eq!(out, ["g", "(", "1", ",", "2", ",", "3", ")"]);
}

#[test]
fn nested_function_macro_rescan() {
    let src = "#define A(x) B(x)\n#define B(x) (x)\nA(5)\n";
    assert_eq!(run(src), ["(", "5", ")"]);
}

#[test]
fn wrong_argument_count_is_an_error() {
    let mut resolver = MapIncludeResolver::new();
    let (_, result) = run_with("#define F(a, b) a\nF(1)\n", &mut resolver);
    assert!(result.has_errors());
}
