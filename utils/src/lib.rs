#![doc = include_str!("../README.md")]
#![no_std]

/// A high-performance hash map using the Fx hashing algorithm.
///
/// This map is highly optimized for performance and is not resilient to `HashDoS`
/// attacks. It should be used in performance-critical compiler passes where
/// the keys are trusted or not exposed to attackers.
pub type HashMap<K, V> = hashbrown::HashMap<K, V, rustc_hash::FxBuildHasher>;

/// A high-performance hash set using the Fx hashing algorithm.
///
/// This set is highly optimized for performance and is not resilient to `HashDoS`
/// attacks. It should be used in performance-critical compiler passes where
/// the keys are trusted or not exposed to attackers.
pub type HashSet<V> = hashbrown::HashSet<V, rustc_hash::FxBuildHasher>;

/// The Fx hashing algorithm, a fast, non-cryptographic hash function.
pub use rustc_hash::FxHasher as Hasher;
