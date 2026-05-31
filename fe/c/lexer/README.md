# stratum-c-lexer

The dialect-aware C lexer for Stratum (early translation phases).

This crate turns raw source text into a stream of **preprocessing tokens** (`PpToken`),
performing only the earliest translation phases: line splicing (`\`-newline), comment removal,
and pp-tokenization. It deliberately stops short of distinguishing keywords from identifiers,
parsing numeric values, or concatenating adjacent string literals, those steps belong *after*
preprocessing and are handled during token finalization in the parser.

The lexer is entirely **context-free**: it knows nothing about `#include`, macros, or the C
grammar. The "typedef lexer hack" is resolved later, in the parser. Keyword classification is
dialect-gated for C89/C90, C99, C11, C17/C18, and C23 during finalization.

## What it provides

- **`PpToken` / `PpTokenKind`**: identifiers, pp-numbers, char/string-literal spellings,
  punctuators, newline markers, and stray characters, each with a `Span` and whitespace
  context.
- The finalized **`TokenKind` / `Keyword` / `Punctuator`** vocabularies that later stages use.
- **`lex`**: the entry point producing a `LexResult`.

## Example

```rust
use stratum_arena::Interner;
use stratum_c_lexer::lex;
use stratum_diagnostics::SourceMap;

let src = "int x = 1;";
let mut map = SourceMap::new();
let file = map.add_root("main.c", src).unwrap();
let mut interner = Interner::new();

let lexed = lex(src, file, &mut interner).unwrap();
assert!(!lexed.has_errors());
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
