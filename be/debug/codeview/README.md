# `stratum_codeview`

A compact `CodeView` line/symbol codec that surfaces PE machine-address ranges back to source
[`Span`](stratum_diagnostics::Span)s — the debug seam for the PE/COFF codec, the Windows
counterpart of `stratum_dwarf`.

The encoder writes a `CodeView` `C13` debug blob: a four-byte `CV_SIGNATURE_C13` signature
followed by four-byte-aligned, length-prefixed subsections. The emitted subsection set is
`DEBUG_S_STRINGTABLE`, `DEBUG_S_FILECHKSMS`, `DEBUG_S_LINES`, and `DEBUG_S_SYMBOLS`.
`DEBUG_S_LINES` carries address-to-source rows, while `DEBUG_S_SYMBOLS` carries function
provenance as `S_GPROC32` / `S_FRAMEPROC` / `S_END` records.

`encode` and `decode` round-trip a [`DebugTable`](crate::DebugTable), and the
[`from_object`](crate::from_object)/[`apply_to_object`](crate::apply_to_object) adapters bridge
the neutral [`DebugInfo`](stratum_oir::DebugInfo) attached to an object module.

Variable locations, a full PDB type stream, rich type records, and lexical scopes are
intentionally out of scope until the MIR/LIR/codegen stages exist to populate them.
