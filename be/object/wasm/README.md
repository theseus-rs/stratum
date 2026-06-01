# `stratum_wasm`

A read/write codec mapping a WebAssembly module to and from the format-neutral Stratum object
model (`stratum_oir`).

The writer supports `wasm32` modules. When an `ObjectModule` carries Wasm format facts, the
writer serializes those standard/custom section payloads directly after checking that generic
imports, exports, and entry metadata still agree with the preserved facts. For legacy OIR
samples without Wasm facts it can still lay out a canonical `wasm32-wasi` command module with
type, import, function, memory, export, code, and data sections.

For high-fidelity fixtures the writer also preserves raw OIR sections named for every standard
WebAssembly section: custom, type, import, function, table, memory, global, export, start,
element, code, data, and data-count. The custom `name` section is represented as
`wasm.custom.name` and maps to OIR debug-style section data.

The reader parses standard sections and custom sections back into an
[`ObjectModule`](stratum_oir::ObjectModule), recovering exact section payload facts,
import/export metadata, code/data roles, and an entry function only when the module declares a
start section or exports `_start`. Absence of an entry point is preserved. Native execution
uses `wasmtime` when available, and optional validation uses `wasm-tools`.
