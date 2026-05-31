# stratum-c-preprocessor

The C preprocessor for Stratum (translation phase 4).

This crate executes the C preprocessor over the preprocessing-token stream produced by
[`stratum-c-lexer`](../lexer). It is decoupled from the filesystem through the
`IncludeResolver` trait, so it can be exercised entirely in memory, and it knows nothing about
the C grammar: its output is an expanded preprocessing-token stream that the parser finalizes.

## Coverage

- **Macros**: object- and function-like, including `#` (stringize), `##` (paste), rescanning,
  and blue painting via per-token hide sets; variadic macros (`...` / `__VA_ARGS__`); `#undef`.
- **Conditionals**: the full `#if`/`#ifdef`/`#ifndef`/`#elif`/`#else`/`#endif` family with a
  constant-expression evaluator (arithmetic, bitwise, shifts, comparisons, logical operators,
  the ternary operator, `defined`, and character constants).
- **Inclusion**: `#include` with quoted, angled, and computed (macro-expanded) header names,
  recorded in the source map for provenance.
- **Other directives**: `#error` (diagnostic), and `#line` / `#pragma` (accepted and ignored).

## What it provides

- **`preprocess`**: the entry point, returning a `PreprocessResult { tokens, diagnostics }`.
- **`IncludeResolver`** with `MapIncludeResolver` (in-memory) and `FsIncludeResolver`
  (filesystem) implementations, plus `ResolvedInclude`.

## Example

```rust
use stratum_arena::Interner;
use stratum_c_preprocessor::{preprocess, MapIncludeResolver};
use stratum_diagnostics::SourceMap;

let src = "#define N 2\nint a[N];\n";
let mut map = SourceMap::new();
let file = map.add_root("main.c", src).unwrap();
let mut interner = Interner::new();
let mut resolver = MapIncludeResolver::new();
let result = preprocess(file, src, &mut interner, &mut map, &mut resolver);
assert!(!result.has_errors());
```

## Testing

Integration tests under `tests/` are grouped by concern `object_macros`, `function_macros`,
`conditionals`, `includes`, and `directives`; asserts on the rendered, expanded token
stream.

## License

Licensed under either of Apache-2.0 or MIT at your option.
