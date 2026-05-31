# stratum-utils

Utilities and common data structures for the Stratum compiler.

This `no_std` crate provides shared hash-map and hash-set aliases backed by
`hashbrown` and `rustc_hash::FxBuildHasher`. The aliases are intended for
compiler-internal maps where the keys are trusted and fast, deterministic-ish
hashing is more useful than `HashDoS` resistance.

## What it provides

- **`HashMap<K, V>`**: `hashbrown::HashMap` using `rustc_hash`.
- **`HashSet<V>`**: `hashbrown::HashSet` using `rustc_hash`.
- **`Hasher`**: the exported Fx hasher type.

## License

Licensed under either of Apache-2.0 or MIT at your option.
