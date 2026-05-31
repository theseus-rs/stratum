# stratum-c-ast

The data-oriented C abstract syntax tree for Stratum.

This crate defines the C frontend's **private** AST. It is private in the architectural sense:
only the C lexer, parser, semantic analyzer, and lowering touch it, and it makes no attempt to
be a "universal" tree, that role belongs to [`stratum-hir`](../../../hir). Following Stratum's
data-oriented design, nodes are stored in a flat `CAst` arena and referenced by `CNodeId`.

The tree records *syntax*, not *meaning*: names are unresolved `Symbol`s and numbers keep their
raw spellings. Resolution and typing happen later, in the semantic analyzer and lowering.

## What it provides

- **`CNode` / `CNodeId`**: the C node vocabulary (declarations, declarators with derivations,
  type specifiers, the full expression set, statements, external declarations, and C99
  designated initializers / compound literals) in a flat arena with a parallel span array.
- **`CAst`**: the container, with a node count and a root.
- A stable **S-expression dumper** (`dump_root`) used by parser tests.

## License

Licensed under either of Apache-2.0 or MIT at your option.
