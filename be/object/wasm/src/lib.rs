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

/// Zero-sized marker implementing [`OirBridge`] for the WebAssembly format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Wasm;

impl OirBridge for Wasm {
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule> {
        read(bytes)
    }

    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>> {
        write(module)
    }
}

#[cfg(test)]
mod tests {
    use super::{Wasm, samples};
    use stratum_oir::{BinaryFormat, OirBridge, SectionKind};

    #[test]
    fn round_trips_hello_world() {
        let module = samples::hello_world_wasm32_wasi().unwrap();
        let bytes = Wasm.write(&module).unwrap();
        let reparsed = Wasm.read(&bytes).unwrap();
        assert_eq!(module.dump(), reparsed.dump());
        let bytes2 = Wasm.write(&reparsed).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn parsed_module_has_expected_shape() {
        let module = samples::hello_world_wasm32_wasi().unwrap();
        let bytes = Wasm.write(&module).unwrap();
        let reparsed = Wasm.read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::Wasm);
        assert_eq!(reparsed.entry(), Some(1));
        let has_code = reparsed
            .sections()
            .any(|(_, section)| section.kind == SectionKind::Text);
        assert!(has_code);
    }

    #[test]
    fn full_featured_sample_round_trips() {
        let bytes = samples::full_featured_bytes().unwrap();
        let reparsed = Wasm.read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::Wasm);
        assert!(
            reparsed
                .sections()
                .any(|(_, section)| section.kind == SectionKind::Debug)
        );
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(Wasm.read(&[0; 16]).is_err());
    }
}
