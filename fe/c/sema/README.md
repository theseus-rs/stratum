# stratum-c-sema

Basic semantic analysis for the Stratum C frontend.

This crate sits between the C parser and the lowering stage. It performs a scoped walk of the
`CAst`, building a `SymbolTable` in C's ordinary-identifier namespace: it records typedefs,
variables, functions, parameters, and enumeration constants, and reports a small set of
semantic errors (such as a name being redeclared as a different kind of symbol).

It is deliberately **minimal** but occupies a real API slot. The current bridge runs after this
pass for diagnostics, but does not consume the symbol table yet. Full tag namespaces, type
checking, integer promotions, linkage, and tentative-definition handling are future work that
will grow behind this same interface.

## License

Licensed under either of Apache-2.0 or MIT at your option.
