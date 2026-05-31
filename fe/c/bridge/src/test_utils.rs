//! Shared helpers for lowering tests.

use crate::alloc_prelude::*;
use crate::lower::lower;
use stratum_arena::Interner;
use stratum_c_ast::CAst;
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;

/// Parses `src` into a C AST.
pub(crate) fn build(src: &str) -> CAst {
    let mut map = SourceMap::new();
    let file = map.add_root("test.c", src).expect("test source is valid");
    let mut interner = Interner::new();
    let lexed = lex(src, file, &mut interner).expect("test source lexes");
    let finalized = finalize(&lexed.tokens, &mut interner);
    let parsed = parse(&finalized.tokens, interner).expect("test source parses");
    parsed.ast
}

/// Lowers `src` and returns the HIR dump of the module root.
pub(crate) fn dump(src: &str) -> String {
    let ast = build(src);
    let result = lower(&ast).expect("test source lowers");
    assert!(
        !result.has_errors(),
        "unexpected lowering errors: {:?}",
        result.diagnostics
    );
    result.hir.dump_root()
}
