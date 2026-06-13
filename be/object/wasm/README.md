# `stratum_wasm`

A read/write codec mapping a WebAssembly module to and from the format-neutral Stratum object
model (`stratum_oir`).

The writer supports `wasm32` modules. For legacy OIR samples it lays out a canonical
`wasm32-wasi` command module with type, import, function, memory, export, code, and data
sections. The single defined `_start` function issues a WASI `fd_write` to print its message,
so the module runs under a WASI runtime such as `wasmtime` with no further linking.

For high-fidelity fixtures the writer also preserves raw OIR sections named for every standard
WebAssembly section: custom, type, import, function, table, memory, global, export, start,
element, code, data, and data-count. The custom `name` section is represented as
`wasm.custom.name` and maps to OIR debug-style section data.

The reader parses standard sections and custom sections back into an
[`ObjectModule`](stratum_oir::ObjectModule), recovering section bytes, import/export metadata,
code/data roles, and the exported `_start` function index so that `write → read → write` is
byte-identical for self-emitted modules. Native execution uses `wasmtime` when available, and
optional validation uses `wasm-tools`.
