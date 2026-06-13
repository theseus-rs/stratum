# `stratum_object_driver`

Format sniffing and read/write orchestration over the Stratum binary codecs.

`sniff` recognises a container format from its leading magic bytes: `\x7FELF`, 64-bit
little-endian Mach-O `\xCF\xFA\xED\xFE`, 32-bit little-endian Mach-O `\xCE\xFA\xED\xFE`,
`MZ`, and `\0asm`. `read` dispatches to the matching codec; `write` selects the codec from the
[`ObjectModule`]'s declared [`BinaryFormat`], giving a single neutral entry point into the ELF,
Mach-O, PE/COFF, and WebAssembly back ends.

[`ObjectModule`]: stratum_oir::ObjectModule
[`BinaryFormat`]: stratum_oir::BinaryFormat
