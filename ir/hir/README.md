# stratum-hir

The shared **High-level Intermediate Representation (HIR)** for Stratum.

The HIR is the *universal language* of the compiler frontend: every source language lowers
its private AST into this single representation, after which the middle- and back-ends (MIR,
LIR, ASM, …) never need to know which language the code came from.

## Faithful, not lossy

Compared with a raw syntax tree the HIR drops concrete syntax and keywords, yet it keeps a
**faithful, structured representation of the C89/C99 core that the current bridge models**:

- control flow keeps its original shapes `While`, `DoWhile`, `For`, `Conditional`,
  `Switch`/`Case`/`Default`, `Label`/`Goto`, `Break`/`Continue`/`Return`;
- expressions retain casts, `sizeof`, member access (`.`/`->`), subscripting, the conditional
  and comma operators, compound assignment, and pre/post increment;
- declarations carry storage classes, qualifiers, aggregates, enumerations, `typedef`s,
  bit-fields, and designated initializers and compound literals.

The C frontend accepts dialects through C23. Some newer constructs currently reuse existing
HIR shapes instead of having dedicated nodes: boolean constants and `nullptr` lower as integer
literals, `_Alignof` / `alignof` reuse the `sizeof` nodes, and `_Generic` is lowered by the
current bridge to a selected expression rather than a typed selection node.

It stays **high-level**: named bindings, lexical blocks, and high-level types survive, and
symbol/type *resolution* is deliberately deferred; names appear as `HirNode::Name` and source
type names as `HirType::Named`.

## What it provides

- **`HirContext`**: arenas for `HirNode`s and `HirType`s plus a parallel span array and a
  string interner.
- **`HirNode` / `HirType`**: the node and type vocabularies.
- **`HirBridge`**: the bidirectional trait each language frontend implements: `lower`
  converges its private AST here, and `raise` reconstructs equivalent source text from HIR.
- A deterministic textual **dumper** (`dump_root`) used as the snapshot format in tests.

Depends only on `stratum-arena` and `stratum-diagnostics`.

## Example

```rust
use stratum_hir::{HirContext, HirNode};
use stratum_diagnostics::{SourceMap, Span};

let mut map = SourceMap::new();
let file = map.add_root("t.c", "1").unwrap();
let mut hir = HirContext::new();
let lit = hir.alloc(HirNode::IntLiteral(1), Span::new(file, 0, 1)).unwrap();
assert_eq!(hir.node(lit), &HirNode::IntLiteral(1));
```

## License

Licensed under either of Apache-2.0 or MIT at your option.
