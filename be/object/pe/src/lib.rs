#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

mod consts;
mod read;
pub mod samples;
mod write;

use stratum_oir::{ObjectModule, OirBridge, Result};

extern crate alloc;
use alloc::vec::Vec;

pub use read::read;
pub use write::write;

/// Zero-sized marker implementing [`OirBridge`] for the PE/COFF format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pe;

impl OirBridge for Pe {
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule> {
        read(bytes)
    }

    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>> {
        write(module)
    }
}

#[cfg(test)]
mod tests {
    use super::{Pe, samples};
    use stratum_oir::{BinaryFormat, OirBridge, SectionKind};

    #[test]
    fn round_trips_hello_world() {
        let module = samples::hello_world_x86_64_windows().unwrap();
        let bytes = Pe.write(&module).unwrap();
        let reparsed = Pe.read(&bytes).unwrap();
        assert_eq!(module.dump(), reparsed.dump());
        let bytes2 = Pe.write(&reparsed).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn parsed_module_has_expected_shape() {
        let module = samples::hello_world_x86_64_windows().unwrap();
        let bytes = Pe.write(&module).unwrap();
        let reparsed = Pe.read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::Pe);
        assert_eq!(reparsed.entry(), Some(0x1000));
        assert_eq!(reparsed.section_count(), 2);
        let (_, text) = reparsed.sections().next().unwrap();
        assert_eq!(text.kind, SectionKind::Text);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(Pe.read(&[0; 64]).is_err());
    }
}
