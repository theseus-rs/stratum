#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

use stratum_elf::Elf;
use stratum_macho::MachO;
use stratum_oir::{BinaryFormat, Error, ObjectModule, OirBridge, Result};
use stratum_pe::Pe;
use stratum_wasm::Wasm;

/// Detects the binary container format of `bytes` from its leading magic bytes.
///
/// Returns `None` when the prefix matches none of the supported formats.
#[must_use]
pub fn sniff(bytes: &[u8]) -> Option<BinaryFormat> {
    match bytes {
        [0x7F, b'E', b'L', b'F', ..] => Some(BinaryFormat::Elf),
        [0xCF | 0xCE, 0xFA, 0xED, 0xFE, ..] => Some(BinaryFormat::MachO),
        [0x4D, 0x5A, ..] => Some(BinaryFormat::Pe),
        [0x00, b'a', b's', b'm', ..] => Some(BinaryFormat::Wasm),
        _ => None,
    }
}

/// Reads `bytes` into an [`ObjectModule`], selecting the codec via [`sniff`].
///
/// # Errors
///
/// Returns [`Error::BadMagic`] if the format cannot be recognised, or the codec's error
/// if parsing fails.
pub fn read(bytes: &[u8]) -> Result<ObjectModule> {
    match sniff(bytes).ok_or(Error::BadMagic)? {
        BinaryFormat::Elf => Elf.read(bytes),
        BinaryFormat::MachO => MachO.read(bytes),
        BinaryFormat::Pe => Pe.read(bytes),
        BinaryFormat::Wasm => Wasm.read(bytes),
    }
}

/// Writes `module` to bytes, selecting the codec from [`ObjectModule::format`].
///
/// # Errors
///
/// Returns the codec's error if serialisation fails.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    match module.format() {
        BinaryFormat::Elf => Elf.write(module),
        BinaryFormat::MachO => MachO.write(module),
        BinaryFormat::Pe => Pe.write(module),
        BinaryFormat::Wasm => Wasm.write(module),
    }
}

#[cfg(test)]
mod tests {
    use super::{read, sniff, write};
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use stratum_oir::{BinaryFormat, Error};

    #[test]
    fn sniffs_every_format() {
        assert_eq!(sniff(b"\x7FELF___"), Some(BinaryFormat::Elf));
        assert_eq!(sniff(b"\xCF\xFA\xED\xFE___"), Some(BinaryFormat::MachO));
        assert_eq!(sniff(b"\xCE\xFA\xED\xFE___"), Some(BinaryFormat::MachO));
        assert_eq!(sniff(b"MZ____"), Some(BinaryFormat::Pe));
        assert_eq!(sniff(b"\x00asm___"), Some(BinaryFormat::Wasm));
        assert_eq!(sniff(b"junk"), None);
        assert_eq!(sniff(&[]), None);
    }

    #[test]
    fn unknown_input_is_rejected() {
        assert!(read(b"not a binary").is_err());
    }

    #[test]
    fn round_trips_each_format_through_the_driver() {
        let modules = [
            stratum_elf::samples::hello_world_x86_64_linux().unwrap(),
            stratum_macho::samples::hello_world_aarch64_macos().unwrap(),
            stratum_pe::samples::hello_world_x86_64_windows().unwrap(),
            stratum_wasm::samples::hello_world_wasm32_wasi().unwrap(),
        ];
        for module in &modules {
            let bytes = write(module).unwrap();
            let reparsed = read(&bytes).unwrap();
            assert_eq!(reparsed.format(), module.format());
            let rewritten = write(&reparsed).unwrap();
            assert_eq!(bytes, rewritten);
        }
    }

    #[test]
    fn concrete_codec_surfaces_are_reachable() {
        let elf = stratum_elf::samples::hello_world_x86_64_linux().unwrap();
        let mut elf_bytes = Vec::new();
        stratum_elf::write_to(&elf, &mut elf_bytes).unwrap();
        let elf_native = stratum_elf::ElfFile::parse(&elf_bytes).unwrap();
        assert_eq!(elf_native.as_bytes(), elf_bytes.as_slice());
        assert_eq!(
            elf_native.clone().into_bytes().as_ref(),
            elf_bytes.as_slice()
        );

        let macho = stratum_macho::samples::hello_world_aarch64_macos().unwrap();
        let macho_bytes = stratum_macho::write(&macho).unwrap();
        let macho_reparsed = stratum_macho::read(&macho_bytes).unwrap();
        assert_eq!(macho_reparsed.format(), BinaryFormat::MachO);

        let pe = stratum_pe::samples::hello_world_x86_64_windows().unwrap();
        let pe_bytes = stratum_pe::write(&pe).unwrap();
        let pe_reparsed = stratum_pe::read(&pe_bytes).unwrap();
        assert_eq!(pe_reparsed.format(), BinaryFormat::Pe);

        let wasm = stratum_wasm::samples::hello_world_wasm32_wasi().unwrap();
        let wasm_bytes = stratum_wasm::write(&wasm).unwrap();
        let wasm_reparsed = stratum_wasm::read(&wasm_bytes).unwrap();
        assert_eq!(wasm_reparsed.format(), BinaryFormat::Wasm);
    }

    #[test]
    fn elf_streaming_error_surface_is_reachable() {
        let err: stratum_elf::ElfWriteError<core::convert::Infallible> =
            Error::Malformed("driver coverage").into();
        let stratum_elf::ElfWriteError::Object(inner) = err;
        assert_eq!(inner.to_string(), "malformed object: driver coverage");
    }
}
