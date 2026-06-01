//! The symmetric read/write seam every executable format implements.

use crate::alloc_prelude::*;
use crate::error::Result;
use crate::model::ObjectModule;

/// The contract a concrete container format fulfils to join the object pipeline.
///
/// `OirBridge` is the binary-end mirror of the frontend's `HirBridge`: [`read`](Self::read)
/// is the convergence direction (format bytes → neutral [`ObjectModule`]) and
/// [`write`](Self::write) is the emit direction (neutral [`ObjectModule`] → format bytes).
///
/// Implementors are zero-sized markers (e.g. `ELF`, `MachO`, `PE`, `WASM`); the format is the
/// type, the data lives entirely in the [`ObjectModule`].
pub trait OirBridge {
    /// Parses `bytes` into a neutral [`ObjectModule`].
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` are not a valid image of this format.
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule>;

    /// Serializes `module` into this format's byte encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if `module` cannot be represented in this format.
    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>>;
}
