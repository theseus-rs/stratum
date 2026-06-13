# `stratum_dwarf`

A compact DWARF v5 provenance codec that surfaces machine-address ranges back to source
[`Span`](stratum_diagnostics::Span)s and function records — the debug seam for the ELF,
Mach-O, and Wasm codecs.

The encoder writes standard `.debug_abbrev`, `.debug_info`, `.debug_line`, `.debug_str`, and
`.debug_aranges` payloads. The emitted DIE tree contains a `DW_TAG_compile_unit`,
`DW_TAG_subprogram` DIEs for function provenance, a `DW_TAG_base_type`, and a
`DW_TAG_variable` that references that base type. Line provenance is carried by a DWARF v5
line-number program; function provenance is carried by `DW_TAG_subprogram` DIEs with
`DW_AT_name`, `DW_AT_low_pc`, and `DW_AT_high_pc`. The old non-standard private `FUNC` trailer
in `.debug_line` is gone.

`encode` and `decode` round-trip a [`DebugTable`](crate::DebugTable), and the
[`from_object`](crate::from_object)/[`apply_to_object`](crate::apply_to_object) adapters bridge
the neutral [`DebugInfo`](stratum_oir::DebugInfo) attached to an object module. Optional tests
validate the sections with `llvm-dwarfdump` when it is available.

Full DWARF expression evaluation, rich type modeling, variable locations, and lexical scopes are
intentionally out of scope until the MIR/LIR/codegen stages exist to populate them.
