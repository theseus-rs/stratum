#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

mod consts;
mod native;
pub mod samples;
mod write;

use stratum_oir::{ObjectModule, OirBridge, Result};

extern crate alloc;
use alloc::vec::Vec;

pub use native::{
    ElfAarch64PauthPlatform, ElfAbiVersion, ElfClass, ElfCompressionType, ElfDataEncoding,
    ElfDynamicEntry, ElfDynamicFlags, ElfDynamicSource, ElfDynamicTag, ElfFdoNote, ElfFile,
    ElfGnuAbiTag, ElfGnuProperty, ElfGroupFlags, ElfHeader, ElfHeaderFlags, ElfIdent,
    ElfIdentField, ElfMachine, ElfMipsOptionKind, ElfMipsRuntimeFlags, ElfMipsRuntimeSymbol,
    ElfNote, ElfNoteSource, ElfNoteType, ElfOsAbi, ElfProgramHeader, ElfRelocation,
    ElfRelocationGroupFlags, ElfRelocationType, ElfSection, ElfSectionFlags, ElfSectionHeader,
    ElfSectionIndex, ElfSectionType, ElfSegmentFlags, ElfSegmentType, ElfSymbol, ElfSymbolBind,
    ElfSymbolEntrySize, ElfSymbolOtherFlags, ElfSymbolType, ElfSymbolVisibility, ElfType,
    ElfVersion, ElfVersionIndex,
};
pub use write::{ElfSink, ElfWriteError};

/// Reads an ELF image into the format-neutral object model.
///
/// # Errors
///
/// Returns an error when the byte stream is not a structurally valid ELF file or cannot be
/// projected into OIR.
pub fn read(bytes: &[u8]) -> Result<ObjectModule> {
    ElfFile::parse(bytes)?.to_oir()
}

/// Serializes an OIR module as a canonical ELF image.
///
/// # Errors
///
/// Returns an error if `module` cannot be represented as ELF.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    ElfFile::from_oir(module)?.to_bytes()
}

/// Serializes an OIR module as a canonical ELF image into a caller-provided sink.
///
/// # Errors
///
/// Returns an object error if `module` cannot be represented as ELF, or a sink error if `sink`
/// cannot accept all emitted bytes.
pub fn write_to<S>(
    module: &ObjectModule,
    sink: &mut S,
) -> core::result::Result<(), ElfWriteError<S::Error>>
where
    S: ElfSink + ?Sized,
{
    write::write_to(module, sink)
}

/// Zero-sized marker implementing [`OirBridge`] for the ELF format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf;

impl OirBridge for Elf {
    fn read(&self, bytes: &[u8]) -> Result<ObjectModule> {
        read(bytes)
    }

    fn write(&self, module: &ObjectModule) -> Result<Vec<u8>> {
        write(module)
    }
}

#[cfg(test)]
mod tests {
    use super::{Elf, samples, write};
    use stratum_oir::{BinaryFormat, OirBridge, SectionKind};

    #[test]
    fn round_trips_hello_world() {
        let module = samples::hello_world_x86_64_linux().unwrap();
        let bytes = Elf.write(&module).unwrap();
        let reparsed = Elf.read(&bytes).unwrap();
        // Semantic round-trip: the dumps must match.
        assert_eq!(module.dump(), reparsed.dump());
        // Byte idempotence: writing the reparsed module reproduces the same bytes.
        let bytes2 = Elf.write(&reparsed).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn parsed_module_has_expected_shape() {
        let module = samples::hello_world_x86_64_linux().unwrap();
        let bytes = Elf.write(&module).unwrap();
        let reparsed = Elf.read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::Elf);
        assert_eq!(reparsed.entry(), Some(0x40_1000));
        let (_, text) = reparsed.sections().next().unwrap();
        assert_eq!(text.kind, SectionKind::Text);
        assert_eq!(reparsed.symbol_count(), 1);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(
            Elf.read(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .is_err()
        );
    }

    #[test]
    fn public_write_reports_unsupported_targets() {
        use stratum_oir::{ObjectModule, TargetSpec};

        let module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::wasm32());
        assert!(write(&module).is_err());
    }

    #[test]
    fn writes_program_headers_from_sections_without_segments() {
        use stratum_oir::{
            ObjectModule, Section, SectionFlags, SectionKind, SymbolBinding, SymbolEntry,
            SymbolFlags, SymbolKind, TargetSpec,
        };
        extern crate alloc;
        use alloc::vec;

        // A module with allocated sections but no explicit segments exercises the
        // section-derived program-header path (`section_to_phdr`).
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        module.set_entry(0x40_1000);
        let text_name = module.intern(".text").unwrap();
        let text = module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x40_1000,
                align: 0x1000,
                flags: SectionFlags::code(),
                data: vec![0x90, 0xc3],
                size: 2,
            })
            .unwrap();
        let rodata_name = module.intern(".rodata").unwrap();
        module
            .add_section(Section {
                name: rodata_name,
                kind: SectionKind::ReadOnlyData,
                address: 0x40_2000,
                align: 0x1000,
                flags: SectionFlags::read_only(),
                data: vec![1, 2, 3, 4],
                size: 4,
            })
            .unwrap();
        let start = module.intern("_start").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: start,
                value: 0x40_1000,
                size: 2,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::exported(),
            })
            .unwrap();

        assert!(module.segments().is_empty());
        // The writer synthesizes PT_LOAD program headers from the allocated sections, so the
        // reparsed module gains segments the source lacked. Assert byte-idempotence rather than
        // dump equality with the original.
        let bytes = Elf.write(&module).unwrap();
        let reparsed = Elf.read(&bytes).unwrap();
        assert!(!reparsed.segments().is_empty());
        let bytes2 = Elf.write(&reparsed).unwrap();
        assert_eq!(bytes, bytes2);
    }
}
