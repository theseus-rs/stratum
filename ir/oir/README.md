# `stratum_oir`

The **Object Intermediate Representation (OIR)**: a format-neutral, arena-based
representation of a linked executable image, plus the symmetric [`OirBridge`] read/write
seam that every concrete executable format (ELF, Mach-O, PE/COFF, WebAssembly) converges
on. The crate lives at `ir/oir/` and is named `stratum_oir`.

`OIR` is the binary-end mirror of the frontend's HIR. Where the frontend dissolves
*language* uniqueness at the `HirBridge`, the binary end dissolves *executable-format*
uniqueness here: format-private codecs read bytes into an [`ObjectModule`] and write an
[`ObjectModule`] back out.

Generic OIR tables cover sections, symbols, relocations, segments, imports, exports, entry
points, target facts, and debug provenance. When a concrete format has facts that do not fit
those tables losslessly, the module carries explicit format-private facts as well. Codecs are
expected to preserve those facts or reject inconsistent edits rather than inventing missing
entries or dropping format-specific structure.
