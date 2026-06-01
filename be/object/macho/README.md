# `stratum_macho`

A read/write codec mapping the Mach-O container to and from the format-neutral Stratum object
model (`stratum_oir`).

The codec supports 32- and 64-bit little-endian Mach-O for `arm64`, `x86_64`, `i386`, and
32-bit `arm` structural fixtures. The writer emits segments and sections, `LC_SYMTAB`,
`LC_DYSYMTAB`, `LC_DYLD_INFO_ONLY`, `LC_LOAD_DYLINKER`, `LC_LOAD_DYLIB`, `LC_BUILD_VERSION`,
`LC_MAIN`, and `LC_CODE_SIGNATURE` load commands, plus symbol, string, dynamic-symbol, empty
Dyld-info, dylib, and relocation-table data as needed for self-emitted fixtures.

Runnable samples are dyld-loaded executables: a `__PAGEZERO` segment, a `__TEXT` segment
carrying the Mach header, load commands, and code, and a `__LINKEDIT` segment holding an
**ad-hoc code signature**. The program body issues raw BSD syscalls (`svc #0x80` on `arm64`;
`syscall` on `x86_64`) and links no `libC`, but the image still loads through `/usr/lib/dyld`
with `LC_LOAD_DYLIB` for `libSystem`. The signature (an embedded `SuperBlob` with a SHA-256
`CodeDirectory`) is computed in pure Rust so produced `arm64` binaries satisfy the macOS
signing requirement.

The reader parses matching 32-/64-bit images back into an [`ObjectModule`](stratum_oir::ObjectModule),
recovering segments, sections, the `LC_MAIN` entry point, symbols, imports, and relocations used
by Stratum's fixtures so that `write → read → write` is byte-identical. Native execution is
gated to the matching macOS runner (`arm64` on this host, `x86_64` where available); structural
tests cover the other Mach-O CPU families, with optional `otool` and `codesign` validation.
