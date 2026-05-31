# stratum-utils

Utilities and common data structures for the Stratum compiler.

This crate provides high-performance data structures and other shared
utilities used across the various components of the Stratum compiler.
In particular, it exports aliases for `HashMap` and `HashSet` that use
`rustc_hash::FxHasher`, which is significantly faster than the standard
library's default `SipHash` algorithm.
