# Stratum architecture

This document explains the design of the Stratum frontend and binary end: why the crates are
split the way they are, and the principles that keep multiple source languages and executable
formats cleanly converging on neutral intermediate representations.

## Goal: dissolve language uniqueness at one seam

Stratum targets the lowering chain
`Source ↔ HIR ↔ MIR (SSA + CFG) ↔ LIR (roles + layout) ↔ ASM ↔ OIR ↔ Binary`. The frontend's job
is to take wildly different source languages and funnel them into a single, language-neutral
**HIR**. Everything downstream of the HIR is deliberately ignorant of the source language.

The key architectural rule: **language uniqueness is completely dissolved at the lowering
layer.** Up to that point each language keeps its own concrete and abstract syntax; after it,
only HIR exists.

```
 Lang A source        Lang B source
      |                     |
   lexer/parser         lexer/parser
      |                     |
 Lang A AST/CST       Lang B AST/CST     (strictly private to each frontend)
      \                     /
       \                   /
        bridge (HirBridge)               (the single convergence seam)
                 |
                 v
            shared HIR                   (the universal frontend language)
```

## CST / AST vs HIR separation

- **Language AST (private).** The C AST (`stratum-c-ast`) is owned entirely by the C
  frontend. It mirrors C's grammar: declaration specifiers, declarators with derivations,
  statements, and the full C expressions. No other frontend may depend on it, and it never
  leaks past lowering. A different language would define a completely different AST.
- **Shared HIR (public).** `stratum-hir` is the entry point to the core pipeline. It is
  **faithful for the currently modeled high-level shapes**: the C89/C99 core keeps dedicated
  representations for loops, `switch`/`case`, `goto`/labels, casts, `sizeof`, member access,
  the conditional and comma operators, declarations, aggregate initializers, and related
  constructs. Dialect-gated C11/C23 syntax is accepted by the frontend, but not every newer
  construct has a dedicated HIR node yet. HIR stays **high-level** — it keeps named bindings,
  lexical blocks, and high-level types, and it deliberately leaves symbol/type *resolution* to
  a later stage (names appear as `HirNode::Name`).

This separation means the MIR/LIR/ASM/Binary back-ends can be written once, against the HIR,
and remain agnostic about whether code came from an imperative, functional, or
object-oriented source.

## Data-oriented design (index-based arenas)

Both the C AST and the HIR use **flat arenas** rather than pointer-heavy trees. Nodes live in
a contiguous `Vec` inside a context object and reference each other by small, strongly-typed
integer ids (`CNodeId`, `HirNodeId`, both `u32`-backed). Source locations live in a parallel
`spans` array indexed the same way.

Why this matters:

- **Cache locality.** Walking the arena during semantic analysis or lowering streams through
  memory sequentially instead of chasing pointers.
- **Trivial deallocation.** Dropping an entire AST or HIR is dropping a handful of vectors,
  not a recursive traversal of thousands of boxes.
- **Thread-friendliness.** Index-based references are `Copy` and contain no lifetimes, so
  subtrees can be moved across threads if parsing is parallelized per file.

The `stratum-arena` crate provides the reusable primitives: `Id<T>` (a typed index),
`Arena<T>`, and a string `Interner` that maps identifiers to `Copy` `Symbol` handles so name
comparisons are `O(1)`.

## Unified spans with provenance

Every frontend emits the **same** `Span` type: a `FileId` plus a half-open `[start, end)`
byte range. Because the type is identical everywhere, the diagnostics engine renders errors
uniformly regardless of which language produced them.

Crucially, the `SourceMap` models provenance explicitly: every `FileId` is associated with
a `FileOrigin` that says whether it's a physical file, an include expansion, or a macro
expansion. The `SourceMap` supports three operations:

- **Physical files** (`add_root`).
- **An include stack** (`add_include`), so `#include` chains can be reported.
- **Macro-expansion files** (`add_expansion`), so a span produced by macro expansion links
  back to both its expansion site and its definition.

This is why preprocessing can synthesize new token streams while still attributing every
resulting token to a meaningful source location.

## Delayed resolution

Parsers emit **unresolved** names. The C parser does not resolve variable bindings or types;
it only performs the minimal lookahead C grammar genuinely requires, the *typedef
"lexer hack"*, via a scoped name table it maintains itself. Basic symbol collection lives in
`stratum-c-sema`: it records ordinary identifiers, typedefs, functions, variables, parameters,
and enum constants, and reports simple incompatible redeclarations. Full type resolution,
linkage, promotions, and target-aware layout are future work that slot in before the HIR→MIR
transition. The HIR continues to carry unresolved `Name` nodes until then.

## The C frontend pipeline → crate mapping

The crate split follows the important C translation boundaries so the
lexer/preprocessor/parser separation stays correct:

| Stage | Work                                                                           | Crate                                 |
|-------|--------------------------------------------------------------------------------|---------------------------------------|
| 1     | Line splicing, comments → space, **pp-tokenization**                           | `stratum-c-lexer`                     |
| 2     | Directive execution, macro expansion (`#`/`##`, rescan, hide sets), `#include` | `stratum-c-preprocessor`              |
| 3     | pp-token → final token, **adjacent string-literal concatenation**              | finalize module in `stratum-c-parser` |
| 4     | Dialect-gated parsing → C AST (typedef table)                                  | `stratum-c-parser`                    |
| 5     | Symbol/type resolution                                                         | `stratum-c-sema`                      |
| 6     | Lower resolved AST → HIR (and raise HIR → C source)                            | `stratum-c-bridge`                    |

The lexer emits **preprocessing tokens**, not final tokens. Adjacent string concatenation and
the pp→final classification happen *after* preprocessing, never in the lexer, exactly as the C
standard requires.

## The bridge convergence model

The bridge is the single seam where a language's structure is translated to and from HIR. The
contract is the `HirBridge` trait:

```rust
pub trait HirBridge {
    type Ast;
    type Error;
    fn lower(&self, ast: &Self::Ast, cx: &mut HirContext) -> Result<HirNodeId, Self::Error>;
    fn raise(&self, cx: &HirContext) -> Result<String, Self::Error>;
}
```

The forward direction (`lower`) is the convergence step; the reverse direction (`raise`)
reconstructs equivalent source from HIR, which is what makes the representation *loss-checked*.
The C frontend fulfils the contract with a zero-sized `CBridge` marker whose `lower` delegates
to a `CLowering` driver that walks the C AST and writes HIR nodes into a `HirContext`. Lowering
is structure-preserving for the C89/C99 core:

- `while`, `do`/`while`, and `for` each lower to the matching HIR loop (`While`, `DoWhile`,
  `For`), with the `for` clauses preserved positionally; no break-guard rewriting occurs.
- `if`/`else` becomes a `Conditional` whose branches are `Block`s, and `switch`/`case`/
  `default`, labels, and `goto` are preserved verbatim.
- Subscripting (`a[i]`), member access (`.`/`->`), casts, `sizeof`, the conditional and comma
  operators, compound assignment, and pre/post increment each map to a dedicated HIR node —
  nothing is desugared away.
- C99 designated initializers and compound literals are preserved as structured initializer
  trees.

Selected later C constructs currently reuse existing HIR forms instead of introducing
dedicated nodes: boolean constants and `nullptr` lower to integer literals, `_Alignof` /
`alignof` lower through `SizeofExpr` / `SizeofType`, and `_Generic` lowers to the selected
expression used by the current bridge implementation.

Because the C AST and the `HirContext` own **separate** interners, every identifier is
re-interned through a single helper as it crosses the boundary; C `Symbol`s are never reused
directly in HIR.

### Faithful, loss-checked lowering

Because the HIR has dedicated representation for the C89/C99 core, lowering avoids
"unsupported construct" diagnostics for that surface. The faithfulness is verified by
`source ↔ HIR` **round-trip tests** (in `stratum-c-bridge`): a fixture is lowered to HIR,
raised back to C, and lowered again, and the two HIR dumps must be identical. Newer dialect
syntax and deeper language rules remain progressive-completion work: variable-length arrays,
`_Complex`, `_Imaginary`, `_BitInt`, `typeof`, `_Generic` type selection, K&R parameter lists,
full symbol/type resolution, promotions, linkage, and target layout are not complete semantic
models yet.

## The binary end: OIR and format codecs

The same convergence-seam philosophy that governs the frontend governs the back end. Just as
every source language converges on one neutral HIR, every executable container converges on
one neutral **Object Intermediate Representation (OIR)**: a data-oriented set of arenas
independent of any particular file format. The core crate is `stratum_oir` in the top-level
`oir/` directory; it replaced the older object-model crate name and path. The driver crate
remains `stratum_object_driver` in `be/driver/`.

OIR now models sections, optional segments, richer symbols, relocations, imports, exports, an
entry point, target facts, and debug provenance. `TargetSpec` carries `Architecture`,
`Endianness`, and `PtrWidth`, with presets plus `TargetSpec::from_triple()` for the CI ISA
families (`x86`, `x86_64`, `arm`, `aarch64`, `aarch64_be`, `riscv64`, `powerpc`,
`powerpc64`, `powerpc64le`, `s390x`, `mips`, `mipsel`, `mips64`, `mips64el`, `loongarch64`,
`sparc64`, and `wasm32`). `SymbolEntry` records size and `SymbolFlags` (`undefined`,
`imported`, `exported`), while `RelocKind`/`Relocation`, `Segment`, `Import`, and `Export`
provide neutral tables for codec fidelity. OIR does not resolve relocations or perform
linking; it records what codecs read and write.

Each format is a private, symmetric codec behind one trait, `OirBridge`, which mirrors the
frontend's `HirBridge` exactly:

```rust
pub trait OirBridge {
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule>;
    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>>;
}
```

`write` is the forward (serialize) direction; `read` is the reverse (parse) direction, which
is what makes each codec **loss-checked**. Four zero-sized markers — `Elf`, `MachO`, `Pe`,
and `Wasm` — implement the trait.

| Crate                   | Role                                                                                  |
|-------------------------|---------------------------------------------------------------------------------------|
| `stratum_oir`           | OIR arenas, `OirBridge`, `TargetSpec`, relocations, segments, imports/exports, bytes  |
| `stratum_elf`           | ELF32/64 little-/big-endian codec, `e_machine` mapping, headers, symbols, relocations |
| `stratum_macho`         | 32-/64-bit Mach-O codec, load commands, symbols, dyld metadata, ad-hoc signing        |
| `stratum_pe`            | PE32/PE32+ codec, data directories, imports/exports/base relocs, COFF symbols         |
| `stratum_wasm`          | WebAssembly codec for standard sections, custom `name`, and `wasm32-wasi` samples     |
| `stratum_dwarf`         | DWARF v5 `.debug_abbrev`/`.debug_info`/`.debug_line`/`.debug_str`/`.debug_aranges`    |
| `stratum_codeview`      | CodeView `C13` line and symbol subsections for PE provenance                          |
| `stratum_object_driver` | magic-byte format sniffing + read/write orchestration                                 |

### Codec fidelity

The ELF codec covers ELF32/64, little- and big-endian byte order, CI `e_machine` values,
program and section headers, `SHT_SYMTAB`/`SHT_STRTAB`, `SHT_REL`/`SHT_RELA`, note/dynamic
sections, and runnable Linux hello-world fixtures for `x86_64` and `aarch64`. Structural
round-trip fixtures cover 16 ELF target families.

The Mach-O codec covers 32-/64-bit `arm64`, `x86_64`, `i386`, and `arm` fixtures; load
commands for segments, symbol tables, dynamic symbols, dyld info, dylinker/dylib metadata,
build version, main entry, and code signatures; pure-Rust ad-hoc signing; and runnable signed
`arm64` plus `cfg`-gated `x86_64` macOS hello-world fixtures.

The PE/COFF codec covers PE32/PE32+, `x64`, `arm64`, `i386`, and `armnt` machine types, data
directories, import/export/base-reloc tables, COFF symbol/string tables, and runnable Windows
hello-world fixtures that are `cfg`-gated to matching runners.

The Wasm codec covers every standard WebAssembly section plus the custom `name` section, and
emits a runnable `wasm32-wasi` hello-world module that executes when `wasmtime` is present.

The DWARF codec emits real `.debug_abbrev`, `.debug_info`, `.debug_line`, `.debug_str`, and
`.debug_aranges` sections with `DW_TAG_compile_unit`, `DW_TAG_subprogram`, `DW_TAG_variable`,
and `DW_TAG_base_type` DIEs. Function provenance now lives in `DW_TAG_subprogram` DIEs; the
old non-standard `.debug_line` `FUNC` trailer is gone. The CodeView codec emits `C13`
`DEBUG_S_STRINGTABLE`, `DEBUG_S_FILECHKSMS`, `DEBUG_S_LINES`, and `DEBUG_S_SYMBOLS`
subsections with `S_GPROC32`/`S_FRAMEPROC`/`S_END` records. Full PDB type streams, rich DWARF
type modeling, variable locations, DWARF expression evaluation, and link-time relocation
resolution are explicit non-goals for this phase.

### Provenance back to HIR/Source

The neutral `DebugInfo` attached to a module records address ranges paired with `Span`s and a
function table, reusing the same `Span`/`FileId` provenance the frontend uses. `stratum_dwarf`
and `stratum_codeview` encode this table to and from real DWARF and CodeView blobs, so an
address range survives the full `Source → … → bytes → … → Source` loop and resolves back to
the originating span.

### Faithful, loss-checked round-tripping

Like the frontend's `source ↔ HIR` round-trip tests, each codec is verified by round-trip
tests: binaries the codecs *produce* are `write → read → write` **byte-idempotent**, and the
canonical `dump()` of a module must survive a parse. Native "Hello, world!" executables are
`cfg`-gated to run only on their matching CI runner (on this `arm64` macOS host, `aarch64`
Mach-O and `wasm32-wasi` actually execute); structural fixtures cover remaining ISA families.
Optional validation is gated on host tools such as `llvm-readobj`, `llvm-dwarfdump`, `otool`,
`codesign`, `wasmtime`, and `wasm-tools`.

## Dependency graph

The crate dependencies form a DAG, enforcing the boundaries above (in particular, the two
language-frontend halves know nothing about each other, the parser does not depend on the
preprocessor, the driver orchestrates them, and every binary codec depends only on the neutral
object model):

```
utils             -> hashbrown, rustc-hash
arena             -> utils
diagnostics       (no deps)
hir               -> arena, diagnostics
c-lexer           -> arena, diagnostics
c-preprocessor    -> arena, diagnostics, c-lexer, utils
c-ast             -> arena, diagnostics
c-parser          -> arena, diagnostics, c-ast, c-lexer, utils
c-sema            -> arena, diagnostics, c-ast, utils
c-bridge          -> arena, diagnostics, c-ast, hir
c-driver          -> all of the above
oir               -> arena, diagnostics, hir
dwarf             -> oir
codeview          -> oir
elf | macho | pe | wasm -> oir
object-driver     -> oir, elf, macho, pe, wasm
```

## Adding another language frontend

The architecture leaves room for new `stratum-<lang>-*` crates. New frontends provide their
own lexer/parser/AST crates, depend only on `stratum-diagnostics` (for spans) and
`stratum-hir` (for the bridge target), and implement `HirBridge`. It would share none of
its AST with other languages, and the entire existing middle/back-end would consume its HIR
without modification.
