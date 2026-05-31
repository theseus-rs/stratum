# stratum-arena

Data-oriented storage primitives shared across the Stratum compiler.

Stratum favours [data-oriented design][dod]: instead of pointer-heavy trees of heap-allocated
nodes (`Box<Node>`), every intermediate representation stores its nodes in a flat arena and
refers to them with small, strongly-typed integer identifiers. This keeps traversals
cache-friendly, makes deallocation trivial (drop one `Vec`), and lets sub-trees move across
threads without lifetime gymnastics.

## What it provides

- **`Id<T>`**: a 32-bit, strongly-typed index into an `Arena<T>`. Distinct `T`s cannot be
  confused at compile time.
- **`Arena<T>`**: a flat `Vec`-backed store that hands out `Id<T>`s.
- **`Symbol` / `Interner`**: string interning, so repeated identifiers become a single
  cheap, copyable `Symbol`.

This crate is intentionally **dependency-free** and knows nothing about any particular
language frontend or IR.

## Example

```rust
use stratum_arena::{Arena, Interner};

let mut arena = Arena::new();
let a = arena.alloc(10).unwrap();
let b = arena.alloc(20).unwrap();
assert_eq!(arena[a] + arena[b], 30);

let mut interner = Interner::new();
let x = interner.intern("hello").unwrap();
let y = interner.intern("hello").unwrap();
assert_eq!(x, y); // interned once
```

[dod]: https://en.wikipedia.org/wiki/Data-oriented_design

## License

Licensed under either of Apache-2.0 or MIT at your option.
