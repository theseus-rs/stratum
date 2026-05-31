# stratum

Experimental, multi-language compiler tools built around a unified intermediate
representation. Stratum is designed so that several source languages can converge on a
single, language-neutral **High-level Intermediate Representation (HIR)**, after which the
middle- and back-ends never need to know which language the code came from.

## Pipeline

The long-term target is the full lowering chain:

```text
Source ↔ HIR ↔ MIR (SSA + CFG) ↔ LIR (roles + layout) ↔ ASM ↔ Binary
```

This repository currently implements the **frontend convergence point**: shared
infrastructure, the shared HIR, and a **C89/C99 frontend** that lowers into HIR. The
MIR / LIR / ASM / Binary stages are intentionally deferred.

```text
   C source
      |
      v
+-------------+   pp-tokens   +------------------+   pp-tokens
|  c-lexer    | ------------> |  c-preprocessor  | ------------+
+-------------+               +------------------+             |
                                                               v
                                                     +------------------+  tokens
                                                     | finalize (parser)|
                                                     +------------------+
                                                               |
                                                               v
                                +----------+   C AST   +------------------+
                                |  c-ast   | <-------- |     c-parser     |
                                +----------+           +------------------+
                                     |
                                     v
                                +----------+   symbols  +------------------+
                                | c-sema   | ---------> |    c-bridge      |
                                +----------+            +--------+---------+
                                                                 |  HirBridge
                                                                 v
                                                          +-------------+
                                                          |     hir     |  (language-neutral)
                                                          +-------------+
```

Everything is sequenced by the `stratum-c` driver.

## Crates

| Crate                    | Responsibility                                                                                                |
|--------------------------|---------------------------------------------------------------------------------------------------------------|
| `stratum-arena`          | Index-based arenas (`Id<T>`, `Arena<T>`) and a string `Interner`. No deps.                                    |
| `stratum-diagnostics`    | `FileId`, `Span`, `SourceMap` (files + include stack + macro provenance), `Diagnostic`. No deps.              |
| `stratum-hir`            | The shared, faithful HIR: nodes, high-level types, `HirContext`, and the `HirBridge` trait.                    |
| `stratum-c-lexer`        | C89/C99 lexer producing **preprocessing tokens** plus the final token vocabulary.                             |
| `stratum-c-preprocessor` | `#include`, object/function macros (`#`/`##`, rescanning), conditionals with a constant-expression evaluator. |
| `stratum-c-ast`          | The private, data-oriented C AST (`CNode` arena) plus an S-expression dumper.                                 |
| `stratum-c-parser`       | Token finalization + a recursive-descent C parser (with the typedef "lexer hack").                            |
| `stratum-c-sema`         | Skeletal semantic layer: scoped symbol tables, typedefs, enum constants.                                      |
| `stratum-c-bridge`       | Implements `HirBridge` for C: total, faithful lowering of every construct, and raising HIR back to C source.   |
| `stratum-c-driver`       | The `stratum-c` CLI binary that runs the whole pipeline.                                                      |

See [`docs/architecture.md`](docs/architecture.md) for the design rationale (CST/AST/HIR
separation, data-oriented design, span provenance, and the lowering convergence model).

## Building and testing

The workspace is **std-only** (zero external dependencies) and uses strict lints
(`deny(warnings)`, `clippy::pedantic`, and more).

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo doc --workspace --no-deps
```

## Using the C driver

```sh
# Lower a C file all the way to HIR (the default).
cargo run -p stratum-c-driver -- path/to/file.c

# Stop after, and print, an earlier stage.
cargo run -p stratum-c-driver -- --emit pptokens path/to/file.c
cargo run -p stratum-c-driver -- --emit tokens   path/to/file.c
cargo run -p stratum-c-driver -- --emit ast      path/to/file.c
cargo run -p stratum-c-driver -- --emit hir      path/to/file.c

# Add #include search directories.
cargo run -p stratum-c-driver -- -I include -I /usr/include path/to/file.c
```

For example, this C input:

```c
int add(int a, int b) {
  return a + b;
}
```

lowers to:

```text
module
  function add(a: i32, b: i32) -> i32
    block
      return
        binary `+`
          name `a`
          name `b`
```

## Status and scope

This is an **initial project structure**, delivered with full unit and integration tests and
documentation. The C frontend provides **complete structural coverage of C89/C99**: the lexer,
preprocessor, parser, and lowering together accept every standard declaration, statement,
expression, type, and initializer form; including C99 designated initializers and compound
literals;  the **HIR represents each one faithfully** (control flow keeps its
`while`/`do`/`for`/`switch` shapes; `goto`/labels, casts, `sizeof`, member access, subscripting,
the conditional and comma operators, compound assignment, pre/post increment, and
`typedef`/aggregate/enum declarations all survive). Lowering is **total**: it never drops a
construct or emits an "unsupported construct" diagnostic, and `source ↔ HIR` round-trips are
covered by losslessness tests.

The HIR deliberately stays high-level and **unresolved**: names appear as `HirNode::Name` and
type names as `HirType::Named`. Full semantic analysis (symbol/type resolution, integer
promotions, linkage, tentative definitions), a few constructs that are represented
structurally rather than fully modeled semantically (e.g. variable-length arrays, `_Complex`,
K&R parameter lists), and the MIR/LIR/ASM/Binary back-ends are future work.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
