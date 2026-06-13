# stratum

[![ci](https://github.com/theseus-rs/stratum/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/theseus-rs/stratum/actions/workflows/ci.yml)
[![Documentation](https://docs.rs/stratum_hir/badge.svg)](https://docs.rs/stratum_hir)
[![Code Coverage](https://codecov.io/gh/theseus-rs/stratum/branch/main/graph/badge.svg)](https://codecov.io/gh/theseus-rs/stratum)
[![Latest version](https://img.shields.io/crates/v/stratum_hir.svg)](https://crates.io/crates/stratum_hir)
[![License](https://img.shields.io/crates/l/stratum_hir)](https://github.com/theseus-rs/stratum#license)
[![Semantic Versioning](https://img.shields.io/badge/%E2%9A%99%EF%B8%8F_SemVer-2.0.0-blue)](https://semver.org/spec/v2.0.0.html)

Experimental, multi-language compiler tools built around a unified intermediate
representation. Stratum is designed so that several source languages can converge on a
single, language-neutral **High-level Intermediate Representation (HIR)**, after which the
middle- and back-ends never need to know which language the code came from.

## Pipeline

The long-term target is the full lowering chain:

```text
Source ↔ HIR ↔ MIR (SSA + CFG) ↔ LIR (roles + layout) ↔ ASM ↔ OIR ↔ Binary
```

This repository currently implements the **frontend convergence point** and the
**binary end** of the chain: shared infrastructure, the shared HIR, a dialect-aware
**C frontend** that lowers into HIR, and a format-neutral **Object Intermediate
Representation (OIR)** with symmetric read/write codecs for ELF, Mach-O, PE/COFF,
WebAssembly, DWARF, and CodeView. The OIR crate is `stratum_oir` in the top-level
`oir/` directory; format codecs live under `be/`, and `stratum_object_driver` in
`be/driver/` provides magic-byte sniffing plus read/write dispatch. The frontend
accepts C89/C90, C99, C11, C17/C18, and C23 modes; the C89/C99 surface has the most
complete structure-preserving HIR coverage, while selected C11/C23 constructs are parsed
and carried through the current representation. The intermediate MIR / LIR / ASM stages
are intentionally deferred.

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

The **binary end** mirrors the frontend: source/HIR provenance and emitted code converge on
the format-neutral **Object Intermediate Representation (OIR)**, and every container format is
a symmetric codec behind a single `OirBridge` trait (`read` parses bytes into an
`ObjectModule`, `write` serializes an `ObjectModule` back to bytes). The `stratum_object_driver`
sniffs magic bytes and dispatches to the matching codec.

```text
   HIR / Source provenance                emitted code + target facts
  (FunctionRecord, LineRecord)        (sections, symbols, relocations,
              |                         segments, imports/exports, entry)
              |                                       |
              +-------------------+   +---------------+
                                  v   v
                          +-----------------------+
                          |          oir          |  format-neutral model
                          | ObjectModule + arenas |  + OirBridge trait
                          +-----------+-----------+
                                      |
              read(bytes) <--- OirBridge ---> write(&module)
                                      |
   +---------------+---------------+--+------------+---------------+-------------+
   v               v               v               v               v             v
+-------+      +--------+      +-------+       +--------+      +-------+    +----------+
|  elf  |      | macho  |      |  pe   |       |  wasm  |      | dwarf |    | codeview |
+---+---+      +---+----+      +---+---+       +---+----+      +---+---+    +-----+----+
    |              |               |               |               |              |
 ELF32/64      32/64-bit       PE32/PE32+      standard +    .debug_* DIEs    C13 line +
 LE/BE         load cmds       data dirs       custom name   + line program   symbol subsecs
 e_machine     ad-hoc sign     imports/exp     wasm32-wasi   (provenance)     (PE provenance)
    |              |               |               |
    +--------------+------+--------+---------------+
                          v
              +-----------------------+
              | stratum_object_driver |  magic-byte sniff + read/write dispatch
              +-----------------------+
```


## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
