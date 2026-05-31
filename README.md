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
infrastructure, the shared HIR, and a dialect-aware **C frontend** that lowers into HIR. The
frontend accepts C89/C90, C99, C11, C17/C18, and C23 modes; the C89/C99 surface has the most
complete structure-preserving HIR coverage, while selected C11/C23 constructs are parsed and
carried through the current representation. The MIR / LIR / ASM / Binary stages are
intentionally deferred.

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
                                +----+-----+           +------------------+
                                     |
                         +-----------+-----------+
                         |                       |
                         v                       v
                   +-------------+          +----------+
                   | c-sema      |          | c-bridge |
                   | diagnostics |          +----+-----+
                   +-------------+               |  HirBridge
                                                 v
                                          +-------------+
                                          |     hir     |  (language-neutral)
                                          +-------------+
```

Everything is sequenced by the `stratum-c` driver.

## Crates

| Crate                    | Responsibility                                                                                                 |
|--------------------------|----------------------------------------------------------------------------------------------------------------|
| `stratum-utils`          | Shared hash-map / hash-set aliases backed by `rustc_hash` / `hashbrown`.                                       |
| `stratum-arena`          | Index-based arenas (`Id<T>`, `Arena<T>`) and a string `Interner`. Depends only on `stratum-utils`.             |
| `stratum-diagnostics`    | `FileId`, `Span`, `SourceMap` (files + include stack + macro provenance), `Diagnostic`. No crate deps.         |
| `stratum-hir`            | The shared, faithful HIR: nodes, high-level types, `HirContext`, and the `HirBridge` trait.                    |
| `stratum-c-lexer`        | Dialect-aware C lexer producing **preprocessing tokens** plus the final token vocabulary.                      |
| `stratum-c-preprocessor` | `#include`, object/function macros (`#`/`##`, rescanning), conditionals with a constant-expression evaluator.  |
| `stratum-c-ast`          | The private, data-oriented C AST (`CNode` arena) plus an S-expression dumper.                                  |
| `stratum-c-parser`       | Token finalization + a recursive-descent, dialect-gated C parser (with the typedef "lexer hack").              |
| `stratum-c-sema`         | Basic semantic layer: scoped ordinary identifiers, typedefs, functions, variables, parameters, enum constants. |
| `stratum-c-bridge`       | Implements `HirBridge` for C: structure-preserving lowering to HIR and raising HIR back to C source.           |
| `stratum-c-driver`       | The `stratum-c` CLI binary that runs the whole pipeline.                                                       |

See [`docs/architecture.md`](docs/architecture.md) for the design rationale (CST/AST/HIR
separation, data-oriented design, span provenance, and the lowering convergence model).

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

# Select an ISO C dialect (default: c23).
cargo run -p stratum-c-driver -- --std c99 path/to/file.c
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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
