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

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
