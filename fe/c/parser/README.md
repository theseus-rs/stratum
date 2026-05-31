# stratum-c-parser

Token finalisation plus a recursive-descent C89/C99 parser for Stratum.

This crate performs the last two steps before a C AST exists:

1. **Token finalisation** (translation phases 5–6) — converts preprocessing tokens into final
   tokens (keywords distinguished from identifiers, numeric and character constants decoded)
   and concatenates adjacent string literals.
2. **Parsing** — a recursive-descent parser over the finalized token stream that produces a
   `CAst` translation unit, resolving typedef names through a scoped symbol table (the "lexer
   hack" handled here, not in the lexer).

Type and symbol *resolution* beyond the typedef table is deliberately left to later stages:
the parser emits unresolved names.

It depends on `stratum-arena`, `stratum-diagnostics`, `stratum-c-ast`, and `stratum-c-lexer` —
**not** on the preprocessor. The driver orchestrates lex → preprocess → finalize → parse.

## What it provides

- **`finalize`** — pp-tokens → final tokens (returns a `FinalizeResult`).
- **`parse`** — final tokens → `CAst` (returns a `Result<ParseResult>` with diagnostics).

## Example

```rust
use stratum_arena::Interner;
use stratum_c_lexer::lex;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;

let src = "int main(void) { return 0; }";
let mut map = SourceMap::new();
let file = map.add_root("main.c", src).unwrap();
let mut interner = Interner::new();
let lexed = lex(src, file, &mut interner).unwrap();
let finalized = finalize(&lexed.tokens, &mut interner);
let parsed = parse(&finalized.tokens, interner).unwrap();
assert!(!parsed.has_errors());
```

## Testing and benchmarks

- Integration tests under `tests/` are grouped by concern (`declarations`, `expressions`,
  `statements`, `initializers`, `types`, `diagnostics`).
- `cargo bench -p stratum-c-parser` runs the Criterion `parsing` benchmark, measuring the
  `lex`, `finalize`, `parse`, and full-`pipeline` stages independently.

## License

Licensed under either of Apache-2.0 or MIT at your option.
