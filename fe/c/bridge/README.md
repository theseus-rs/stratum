# stratum-c-bridge

The **bidirectional bridge** between the private C AST and the shared, language-neutral
[HIR](../../../hir).

This crate is the **convergence seam** of the C frontend: in the forward direction it consumes
the `CAst` (and the symbols collected by [`stratum-c-sema`](../sema)) and emits `HirNode`s into
a `HirContext`; in the reverse direction it raises that HIR back into equivalent C source.
After the forward step nothing downstream needs to know the code originated from C.

## Total, faithful lowering

Because the HIR has a dedicated representation for every C89/C99 construct, lowering is **total
and structure-preserving**; it never drops a construct or emits an "unsupported construct"
diagnostic:

- `while`, `do`/`while`, and `for` each lower to the matching HIR loop (no break-guard
  rewriting); `switch`/`case`/`default`, labels, and `goto` are preserved.
- `if`/`else` becomes a `Conditional`.
- Subscripting, member access, casts, `sizeof`, the conditional and comma operators, compound
  assignment, and pre/post increment all map to dedicated HIR nodes, nothing is desugared
  away.
- C99 designated initializers and compound literals are preserved as structured initializer
  trees.

The C AST and the `HirContext` own *separate* string interners, so every name is re-interned
through a single helper as it crosses the boundary.

## What it provides

- **`lower`**: the forward entry point, returning a `LowerResult { hir, diagnostics }`.
- **`raise`**: the reverse entry point, rendering C source from a populated `HirContext`.
- **`CBridge`**: a zero-sized marker implementing the HIR `HirBridge` contract in both
  directions.
- **`CLowering`**: the lowering driver that `CBridge`'s forward direction delegates to.

## Testing

In addition to unit tests asserting faithful HIR output, `tests/roundtrip.rs` proves
`source ↔ HIR` losslessness: each fixture is lowered to HIR, raised back to C, and lowered
again, and the two HIR dumps must be identical.

## Example

```rust
use stratum_arena::Interner;
use stratum_c_lexer::lex;
use stratum_c_bridge::lower;
use stratum_c_parser::{finalize, parse};
use stratum_diagnostics::SourceMap;
use stratum_hir::HirNode;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let src = "int main(void) { return 0; }";
let mut map = SourceMap::new();
let file = map.add_root("main.c", src)?;
let mut interner = Interner::new();
let lexed = lex(src, file, &mut interner)?;
let finalized = finalize(&lexed.tokens, &mut interner);
let parsed = parse(&finalized.tokens, interner)?;
let result = lower(&parsed.ast)?;
assert!(!result.has_errors());
let root = result.hir.root().expect("lowering sets a module root");
assert!(matches!(result.hir.node(root), HirNode::Module(_)));
# Ok(())
# }
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
