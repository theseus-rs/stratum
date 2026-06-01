# `stratum_pe`

A read/write codec mapping the Portable Executable / COFF container to and from the
format-neutral Stratum object model (`stratum_oir`).

The writer lays out canonical, deterministic PE32 and PE32+ images from an
[`ObjectModule`](stratum_oir::ObjectModule): a DOS stub, `PE\0\0` signature, COFF header,
optional header with data directories, section table, section bodies, and a COFF symbol table
plus string table when symbols are present. Supported machine types are `IMAGE_FILE_MACHINE_AMD64`,
`IMAGE_FILE_MACHINE_ARM64`, `IMAGE_FILE_MACHINE_I386`, and `IMAGE_FILE_MACHINE_ARMNT`.

Data-directory support covers imports, exports, and base relocations. Console "Hello, world!"
fixtures use an import table targeting `kernel32.dll` (`GetStdHandle`, `WriteFile`,
`ExitProcess`). Additional fixtures exercise PE32 imports, export-directory parsing, base-reloc
directory validation, and COFF symbol/string-table round-tripping.

The reader parses supported PE/COFF images back into an [`ObjectModule`](stratum_oir::ObjectModule),
preserving sections, entry point, imports, exports, and COFF symbols so that
`write → read → write` is byte-identical for images Stratum produces. Runnable Windows samples
exist for `x86_64` and `aarch64` fixture generation; execution is `cfg`-gated to matching Windows
runners, and optional validation uses `llvm-readobj` when present.
