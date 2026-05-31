# stratum-c-bridge

The **bidirectional bridge** between the private C AST and the shared, language-neutral
[HIR](../../../hir).

This crate is the **convergence seam** of the C frontend: in the forward direction it consumes
the unresolved `CAst` and emits `HirNode`s into a `HirContext`; in the reverse direction it
raises that HIR back into equivalent C source for the modeled HIR surface. The driver runs
[`stratum-c-sema`](../sema) before lowering to collect diagnostics, but the current bridge does
not consume sema's symbol table yet. After the forward step nothing downstream needs to know
the code originated from C.

## Structure-preserving lowering

Because the HIR has dedicated representation for the C89/C99 core, lowering is
structure-preserving for that surface:

- `while`, `do`/`while`, and `for` each lower to the matching HIR loop (no break-guard
  rewriting); `switch`/`case`/`default`, labels, and `goto` are preserved.
- `if`/`else` becomes a `Conditional`.
- Subscripting, member access, casts, `sizeof`, the conditional and comma operators, compound
  assignment, and pre/post increment all map to dedicated HIR nodes, nothing is desugared
  away.
- C99 designated initializers and compound literals are preserved as structured initializer
  trees.

Some newer dialect constructs currently reuse existing HIR nodes instead of dedicated
semantic forms: boolean constants and `nullptr` lower to integer literals, `_Alignof` /
`alignof` reuse `sizeof` nodes, and `_Generic` lowers to a selected expression according to the
current bridge implementation.

The C AST and the `HirContext` own *separate* string interners, so every name is re-interned
through a single helper as it crosses the boundary.

## What it provides

- **`lower`**: the forward entry point, returning a `LowerResult { hir, diagnostics }`.
- **`raise`**: the reverse entry point, rendering C source from a populated `HirContext`.
- **`CBridge`**: a zero-sized marker implementing the HIR `HirBridge` contract in both
  directions.
- **`CLowering`**: the lowering driver that `CBridge`'s forward direction delegates to.

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
