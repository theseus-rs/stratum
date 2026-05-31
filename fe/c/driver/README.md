# stratum-c-driver

The Stratum C frontend driver: orchestrates the pipeline
`source → pp-tokens → tokens → AST → HIR` and renders the requested stage.

This crate wires the C frontend crates together behind a small `std`-enabled command line
(the `stratum-c` binary). It is deliberately thin: every stage lives in its own crate, and the
driver only sequences them and formats output.

## Usage

```sh
# Lower a C file all the way to HIR (the default).
cargo run -p stratum-c-driver -- path/to/file.c

# Stop after, and print, an earlier stage.
cargo run -p stratum-c-driver -- --emit pptokens path/to/file.c
cargo run -p stratum-c-driver -- --emit tokens   path/to/file.c
cargo run -p stratum-c-driver -- --emit ast      path/to/file.c
cargo run -p stratum-c-driver -- --emit hir      path/to/file.c

# Add #include search directories.
cargo run -p stratum-c-driver -- -I include -I /usr/include path/to/file.c

# Select an ISO C dialect (default: c23).
cargo run -p stratum-c-driver -- --std c99 path/to/file.c
```

The `--emit` flag selects which stage to print:

- `pptokens`: the preprocessing-token stream after macro expansion and `#include`;
- `tokens`: the finalized token stream;
- `ast`: the C AST as an S-expression;
- `hir`: the lowered HIR (the default).

The `--std` flag accepts `c89` / `c90`, `c99`, `c11`, `c17` / `c18`, and `c23` / `c2x`.

## Library API

`compile_source(name, src, emit, include_dirs)` runs the pipeline in memory with the default
dialect. `compile_source_with_dialect` lets callers select the dialect explicitly. Both return
the rendered `output`, a `had_errors` flag, and the collected `diagnostics`, used by the
end-to-end snapshot tests under `tests/`.

## License

Licensed under either of Apache-2.0 or MIT at your option.
