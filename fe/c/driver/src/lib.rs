#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[doc(hidden)]
pub mod alloc_prelude {
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

use crate::alloc_prelude::*;
#[cfg(feature = "std")]
use std::path::PathBuf;
#[cfg(feature = "std")]
use std::{eprint, eprintln, print};

use stratum_arena::Interner;
use stratum_c_lexer::{Keyword, Punctuator, Token, TokenKind};
use stratum_c_parser::{finalize, parse};
#[cfg(feature = "std")]
use stratum_c_preprocessor::FsIncludeResolver;
use stratum_c_preprocessor::{IncludeResolver, preprocess};
use stratum_diagnostics::{Diagnostic, Severity, SourceMap};

mod error;
mod render;

pub use error::{Error, Result};

/// The pipeline stage to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emit {
    /// Preprocessing tokens (post-expansion).
    PpTokens,
    /// finalized tokens.
    Tokens,
    /// The parsed C AST (S-expression form).
    Ast,
    /// The lowered HIR (default).
    Hir,
}

impl Emit {
    #[cfg(feature = "std")]
    fn from_str(value: &str) -> core::result::Result<Self, String> {
        match value {
            "pptokens" => Ok(Emit::PpTokens),
            "tokens" => Ok(Emit::Tokens),
            "ast" => Ok(Emit::Ast),
            "hir" => Ok(Emit::Hir),
            other => Err(format!(
                "unknown --emit stage `{other}` (expected pptokens, tokens, ast, or hir)"
            )),
        }
    }
}

/// Parsed command-line options.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Options {
    /// The input C source file.
    pub input: PathBuf,
    /// The stage to print.
    pub emit: Emit,
    /// Additional `#include` search directories (from `-I`).
    pub include_dirs: Vec<PathBuf>,
}

/// Parses command-line arguments (excluding the program name).
///
/// # Errors
///
/// Returns a human-readable message if the arguments are malformed or `--help` is requested.
#[cfg(feature = "std")]
pub fn parse_args(args: &[String]) -> core::result::Result<Options, String> {
    let mut emit = Emit::Hir;
    let mut include_dirs = Vec::new();
    let mut input: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Err(usage()),
            "--emit" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--emit requires an argument".to_string())?;
                emit = Emit::from_str(value)?;
            }
            "-I" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "-I requires a directory argument".to_string())?;
                include_dirs.push(PathBuf::from(value));
            }
            other if other.starts_with("--emit=") => {
                emit = Emit::from_str(&other["--emit=".len()..])?;
            }
            other if other.starts_with("-I") => {
                include_dirs.push(PathBuf::from(&other[2..]));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}`"));
            }
            other => {
                if input.replace(PathBuf::from(other)).is_some() {
                    return Err("only one input file is supported".to_string());
                }
            }
        }
    }
    let input = input.ok_or_else(|| format!("no input file given\n\n{}", usage()))?;
    Ok(Options {
        input,
        emit,
        include_dirs,
    })
}

/// Returns the usage string.
#[must_use]
#[cfg(feature = "std")]
pub fn usage() -> String {
    "usage: stratum-c [--emit pptokens|tokens|ast|hir] [-I <dir>]... <file.c>".to_string()
}

/// The outcome of compiling a single source string.
#[derive(Debug)]
pub struct CompileOutput {
    /// The rendered stage output.
    pub output: String,
    /// All diagnostics collected across stages, already rendered to text.
    pub diagnostics: String,
    /// Whether any error-severity diagnostic was produced.
    pub had_errors: bool,
}

/// Runs the full pipeline on an in-memory source string and renders `emit`.
///
/// `include_dirs` supplies the angle/quote `#include` search path.
///
/// # Errors
///
/// Returns an error if source registration, parsing, symbol rendering, or lowering fails.
#[cfg(feature = "std")]
pub fn compile_source(
    name: &str,
    source: &str,
    emit: Emit,
    include_dirs: &[PathBuf],
) -> Result<CompileOutput> {
    let mut resolver = FsIncludeResolver::new(include_dirs.to_vec());
    compile_source_with_resolver(name, source, emit, &mut resolver)
}

/// Runs the full pipeline on an in-memory source string using a caller-supplied include resolver.
///
/// # Errors
///
/// Returns an error if source registration, parsing, symbol rendering, or lowering fails.
pub fn compile_source_with_resolver<R: IncludeResolver>(
    name: &str,
    source: &str,
    emit: Emit,
    resolver: &mut R,
) -> Result<CompileOutput> {
    let mut interner = Interner::new();
    let mut source_map = SourceMap::new();
    let file = source_map.add_root(name, source)?;
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    let pp = preprocess(file, source, &mut interner, &mut source_map, resolver);
    diagnostics.extend(pp.diagnostics);
    if emit == Emit::PpTokens {
        let output = render::pp_tokens(&pp.tokens, &interner)?;
        return Ok(finish(output, &diagnostics, &source_map));
    }

    let finalized = finalize(&pp.tokens, &mut interner);
    diagnostics.extend(finalized.diagnostics);
    if emit == Emit::Tokens {
        let output = render_tokens(&finalized.tokens, &interner)?;
        return Ok(finish(output, &diagnostics, &source_map));
    }

    let parsed = parse(&finalized.tokens, interner)?;
    diagnostics.extend(parsed.diagnostics);
    if emit == Emit::Ast {
        let output = format!("{}\n", parsed.ast.dump_root());
        return Ok(finish(output, &diagnostics, &source_map));
    }

    let sema = stratum_c_sema::analyze(&parsed.ast);
    diagnostics.extend(sema.diagnostics);

    let lowered = stratum_c_bridge::lower(&parsed.ast)?;
    diagnostics.extend(lowered.diagnostics);
    let output = lowered.hir.dump_root();
    Ok(finish(output, &diagnostics, &source_map))
}

fn finish(output: String, diagnostics: &[Diagnostic], source_map: &SourceMap) -> CompileOutput {
    let had_errors = diagnostics.iter().any(|d| d.severity() == Severity::Error);
    let rendered: String = diagnostics.iter().map(|d| d.render(source_map)).collect();
    CompileOutput {
        output,
        diagnostics: rendered,
        had_errors,
    }
}

fn render_tokens(tokens: &[Token], interner: &Interner) -> Result<String> {
    use core::fmt::Write as _;
    let mut out = String::new();
    for token in tokens {
        let line = match token.kind {
            TokenKind::Keyword(kw) => format!("keyword {}", Keyword::spelling(kw)),
            TokenKind::Identifier(sym) => format!("ident {}", interner.resolve(sym)?),
            TokenKind::Integer { value, unsigned } => {
                format!("int {value}{}", if unsigned { "u" } else { "" })
            }
            TokenKind::Float(sym) => format!("float {}", interner.resolve(sym)?),
            TokenKind::Char(value) => format!("char {value}"),
            TokenKind::String(sym) => format!("string {:?}", interner.resolve(sym)?),
            TokenKind::Punct(p) => format!("punct {}", Punctuator::spelling(p)),
            TokenKind::Eof => "<eof>".to_string(),
        };
        let _ = writeln!(out, "{line}");
    }
    Ok(out)
}

/// Reads `options.input`, runs the pipeline, and prints the result.
///
/// Returns a process exit code: `0` on success, `1` if diagnostics contained errors, `2` for
/// I/O failures.
#[must_use]
#[cfg(feature = "std")]
pub fn run(options: &Options) -> i32 {
    let source = match std::fs::read_to_string(&options.input) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", options.input.display());
            return 2;
        }
    };
    let name = options.input.to_string_lossy().into_owned();
    emit_run_result(compile_source(
        &name,
        &source,
        options.emit,
        &options.include_dirs,
    ))
}

#[cfg(feature = "std")]
fn emit_run_result(result: Result<CompileOutput>) -> i32 {
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            eprintln!("error: {err}");
            return 2;
        }
    };
    print!("{}", result.output);
    if !result.diagnostics.is_empty() {
        eprint!("{}", result.diagnostics);
    }
    i32::from(result.had_errors)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{
        CompileOutput, Emit, Error, Options, compile_source, emit_run_result, parse_args,
        render_tokens, run,
    };
    use crate::alloc_prelude::*;
    use std::path::PathBuf;
    use stratum_arena::Interner;
    use stratum_c_lexer::{Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};

    #[test]
    fn parses_all_argument_forms() {
        let args = [
            "--emit".to_string(),
            "tokens".to_string(),
            "-Iinclude".to_string(),
            "-I".to_string(),
            "more".to_string(),
            "input.c".to_string(),
        ];
        let options = parse_args(&args).unwrap();
        assert_eq!(options.emit, Emit::Tokens);
        assert_eq!(options.input, PathBuf::from("input.c"));
        assert_eq!(
            options.include_dirs,
            vec![PathBuf::from("include"), PathBuf::from("more")]
        );
    }

    #[test]
    fn parse_args_reports_malformed_arguments() {
        let cases: &[&[&str]] = &[
            &["--help"],
            &["--emit"],
            &["--emit=bad"],
            &["-I"],
            &["--bad"],
            &["a.c", "b.c"],
            &[],
        ];
        for case in cases {
            let args: Vec<String> = case.iter().map(|arg| (*arg).to_string()).collect();
            assert!(parse_args(&args).is_err());
        }
    }

    #[test]
    fn compile_source_emits_all_stages_and_diagnostics() {
        for emit in [Emit::PpTokens, Emit::Tokens, Emit::Ast, Emit::Hir] {
            let output = compile_source("t.c", "int x = 1;\n", emit, &[]).unwrap();
            assert!(!output.output.is_empty());
            assert!(!output.had_errors);
        }

        let bad = compile_source("bad.c", "int f(){ return 0 }", Emit::Hir, &[]).unwrap();
        assert!(bad.had_errors);
        assert!(!bad.diagnostics.is_empty());
    }

    #[test]
    fn render_tokens_covers_all_token_kinds() {
        let mut interner = Interner::new();
        let ident = interner.intern("name").unwrap();
        let float = interner.intern("1.0").unwrap();
        let string = interner.intern("text").unwrap();
        let span = Span::point(FileId::from_raw(0), 0);
        let tokens = [
            Token {
                kind: TokenKind::Keyword(stratum_c_lexer::Keyword::Int),
                span,
            },
            Token {
                kind: TokenKind::Identifier(ident),
                span,
            },
            Token {
                kind: TokenKind::Integer {
                    value: 1,
                    unsigned: true,
                },
                span,
            },
            Token {
                kind: TokenKind::Float(float),
                span,
            },
            Token {
                kind: TokenKind::Char(65),
                span,
            },
            Token {
                kind: TokenKind::String(string),
                span,
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span,
            },
            Token {
                kind: TokenKind::Eof,
                span,
            },
        ];
        let rendered = render_tokens(&tokens, &interner).unwrap();
        assert!(rendered.contains("keyword int"));
        assert!(rendered.contains("ident name"));
        assert!(rendered.contains("int 1u"));
        assert!(rendered.contains("float 1.0"));
        assert!(rendered.contains("char 65"));
        assert!(rendered.contains("string \"text\""));
        assert!(rendered.contains("punct ;"));
        assert!(rendered.contains("<eof>"));
    }

    #[test]
    fn run_reports_missing_input() {
        let options = Options {
            input: PathBuf::from("__definitely_missing__.c"),
            emit: Emit::Hir,
            include_dirs: Vec::new(),
        };
        assert_eq!(run(&options), 2);
    }

    #[test]
    fn emit_run_result_maps_diagnostics_and_errors_to_exit_codes() {
        let result = CompileOutput {
            output: String::new(),
            diagnostics: "diagnostic\n".to_string(),
            had_errors: true,
        };
        assert_eq!(emit_run_result(Ok(result)), 1);

        let err = Error::from(stratum_arena::Error::ArenaFull);
        assert_eq!(emit_run_result(Err(err)), 2);
    }
}
