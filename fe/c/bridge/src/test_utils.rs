//! Shared helpers for lowering tests.

use crate::alloc_prelude::*;
use crate::lower::lower;
use stratum_arena::Interner;
use stratum_c_ast::CAst;
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Parses `src` into a C AST.
pub(crate) fn build(src: &str) -> TestResult<CAst> {
    let mut map = SourceMap::new();
    let file = map.add_root("test.c", src)?;
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner)?;
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner)?;
    Ok(parsed.ast)
}

/// Lowers `src` and returns the HIR dump of the module root.
pub(crate) fn dump(src: &str) -> TestResult<String> {
    let ast = build(src)?;
    let result = lower(&ast)?;
    assert!(
        !result.has_errors(),
        "unexpected lowering errors: {:?}",
        result.diagnostics
    );
    Ok(result.hir.dump_root())
}
