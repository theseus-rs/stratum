# stratum-diagnostics

Uniform source locations and diagnostics for every Stratum frontend.

All frontends emit the same `Span` type and report problems through the same `Diagnostic`
type, so the rendering and source-mapping logic is shared regardless of which language
produced an error.

## What it provides

- **`FileId` / `Span`**: a compact `(file, byte-range)` location used identically by every
  frontend.
- **`SourceMap`**: provenance-aware from the outset: alongside ordinary physical files it
  records `#include` stacks and macro-expansion origins, and resolves byte offsets to
  line/column positions.
- **`Diagnostic` / `Severity` / `Label`**: structured compiler messages.
- A plain-text, compiler-style **renderer**.

The provenance model means the C preprocessor can attribute generated tokens back to both
their point of use and their point of definition without a later redesign.

This crate has **no dependencies** and is free of any IR- or language-specific concepts.

## Example

```rust
use stratum_diagnostics::{Diagnostic, Label, SourceMap};

let mut map = SourceMap::new();
let file = map.add_root("main.c", "int x = ;\n").unwrap();
let diag = Diagnostic::error("expected an expression")
    .with_label(Label::new(stratum_diagnostics::Span::new(file, 8, 9), "here"));
assert_eq!(diag.severity(), stratum_diagnostics::Severity::Error);
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
