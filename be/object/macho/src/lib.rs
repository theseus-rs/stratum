#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

mod codesign;
pub mod consts;
mod convert;
mod read;
pub mod samples;
mod sha256;
mod write;

use stratum_oir::{ObjectModule, OirBridge, Result};

extern crate alloc;
use alloc::vec::Vec;

pub use read::read;
pub use sha256::sha256;
pub use write::write;

/// Zero-sized marker implementing [`OirBridge`] for the Mach-O format.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachO;

impl OirBridge for MachO {
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule> {
        read(bytes)
    }

    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>> {
        write(module)
    }
}

#[cfg(test)]
mod tests {
    use super::{MachO, samples};
    use stratum_oir::{BinaryFormat, OirBridge, SectionKind};

    #[test]
    fn round_trips_hello_world() {
        let module = samples::hello_world_aarch64_macos().unwrap();
        let bytes = MachO.write(&module).unwrap();
        let reparsed = MachO.read(&bytes).unwrap();
        let bytes2 = MachO.write(&reparsed).unwrap();
        assert_eq!(bytes, bytes2);
        let rereparsed = MachO.read(&bytes2).unwrap();
        assert_eq!(reparsed.dump(), rereparsed.dump());
    }

    #[test]
    fn parsed_module_has_expected_shape() {
        let module = samples::hello_world_aarch64_macos().unwrap();
        let bytes = MachO.write(&module).unwrap();
        let reparsed = MachO.read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::MachO);
        assert!(reparsed.entry().is_some());
        let (_, text) = reparsed.sections().next().unwrap();
        assert_eq!(text.kind, SectionKind::Text);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(MachO.read(&[0; 64]).is_err());
    }
}
