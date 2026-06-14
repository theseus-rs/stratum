# `stratum_elf`

ELF (Executable and Linkable Format) read/write codec for the Stratum object pipeline.

`Elf` implements [`OirBridge`](stratum_oir::OirBridge): `read` parses ELF bytes into a
neutral [`ObjectModule`](stratum_oir::ObjectModule), and `write` serialises an
[`ObjectModule`](stratum_oir::ObjectModule) back into a deterministic ELF image.

Implemented coverage includes ELF32 and ELF64, little- and big-endian encodings, the full
`e_machine` table used by Stratum's CI ISA families (`x86`, `x86_64`, `arm`, `aarch64`,
`riscv64`, `powerpc`, `powerpc64`, `s390x`, `mips`, `loongarch64`, `sparc64`), program
headers, section headers, `SHT_SYMTAB`/`SHT_STRTAB`, `SHT_REL`/`SHT_RELA` relocation parsing,
`SHT_RELA` emission for module relocations, `PT_LOAD` segment mapping, and preservation of
note and dynamic sections as ordinary OIR sections.

The writer emits a canonical layout — an ELF header, loadable program headers, section
contents, section headers, a symbol/string table, and relocation sections when present — that
is byte-idempotent under `write → read → write` for images Stratum produces. Runnable Linux
samples exist for `x86_64` and `aarch64`; the native execution tests are `cfg`-gated, while
structural round-trip samples cover 16 ELF target families. Optional validation uses
`llvm-readobj` when it is available on the host.
