//! Round-trip fidelity tests for the ELF codec.

mod support;

use stratum_elf::{Elf, read, samples, write};
use stratum_oir::{
    BinaryFormat, ObjectModule, OirBridge, RelocKind, Relocation, Section, SectionFlags,
    SectionKind, Segment, SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};

#[test]
fn public_api_surface_is_covered() {
    support::exercise_public_api_surface();
}

fn assert_round_trip(module: &ObjectModule) -> stratum_oir::Result<()> {
    let first = write(module)?;
    let reparsed = read(&first)?;
    if module.dump() != reparsed.dump() {
        return Err(stratum_oir::Error::Malformed("round-tripped dump changed"));
    }
    let second = write(&reparsed)?;
    if first != second {
        return Err(stratum_oir::Error::Malformed("round-tripped bytes changed"));
    }
    Ok(())
}

#[test]
fn hello_world_write_read_write_is_byte_idempotent() {
    let module = samples::hello_world_x86_64_linux().unwrap();
    assert_round_trip(&module).unwrap();
}

#[test]
fn structural_samples_cover_all_elf_families() {
    let samples = samples::structural_samples().unwrap();
    assert_eq!(samples.len(), 16);
    for (name, module) in &samples {
        assert_round_trip(module).unwrap();
        let bytes = write(module).unwrap();
        let parsed = Elf.read(&bytes).unwrap();
        assert_eq!(
            module.target(),
            parsed.target(),
            "target mismatch for {name}"
        );
        assert!(parsed.section_count() >= 6, "sections for {name}");
        assert!(parsed.symbol_count() >= 3, "symbols for {name}");
        assert_eq!(parsed.relocation_count(), 1, "relocations for {name}");
        assert_eq!(parsed.segments().len(), 4, "segments for {name}");
    }
}

#[test]
fn entry_zero_round_trips_as_absent_entry() {
    let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    let text_name = module.intern(".text").unwrap();
    let text = module
        .add_section(Section {
            name: text_name,
            kind: SectionKind::Text,
            address: 0x40_1000,
            align: 0x1000,
            flags: SectionFlags::code(),
            data: vec![0xc3],
            size: 1,
        })
        .unwrap();
    let segment_name = module.intern("PT_LOAD").unwrap();
    module.add_segment(Segment {
        name: segment_name,
        address: 0x40_1000,
        vm_size: 1,
        flags: SectionFlags::code(),
        sections: vec![text],
    });

    let bytes = write(&module).unwrap();
    let parsed = read(&bytes).unwrap();
    assert_eq!(parsed.entry(), None);
    assert_round_trip(&module).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "rich ELF fixture keeps sections, symbols, segments, and relocations together"
)]
fn rich_symbol_and_relocation_module_round_trips() {
    let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    let text_name = module.intern(".text").unwrap();
    let text = module
        .add_section(Section {
            name: text_name,
            kind: SectionKind::Text,
            address: 0x40_1000,
            align: 0x1000,
            flags: SectionFlags::code(),
            data: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            size: 16,
        })
        .unwrap();
    let data_name = module.intern(".data").unwrap();
    let data = module
        .add_section(Section {
            name: data_name,
            kind: SectionKind::Data,
            address: 0x40_2000,
            align: 0x1000,
            flags: SectionFlags::data(),
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            size: 8,
        })
        .unwrap();
    let start_name = module.intern("_start").unwrap();
    let start = module
        .add_symbol(SymbolEntry {
            name: start_name,
            value: 0x40_1000,
            size: 16,
            section: Some(text),
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::none(),
        })
        .unwrap();
    let object_name = module.intern("global_object").unwrap();
    let object = module
        .add_symbol(SymbolEntry {
            name: object_name,
            value: 0x40_2000,
            size: 8,
            section: Some(data),
            kind: SymbolKind::Object,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::none(),
        })
        .unwrap();
    let import_name = module.intern("extern_func").unwrap();
    let import = module
        .add_symbol(SymbolEntry {
            name: import_name,
            value: 0,
            size: 0,
            section: None,
            kind: SymbolKind::None,
            binding: SymbolBinding::Global,
            flags: SymbolFlags {
                undefined: true,
                imported: false,
                exported: false,
            },
        })
        .unwrap();
    module
        .add_relocation(Relocation {
            section: text,
            offset: 0,
            symbol: object,
            kind: RelocKind::Absolute64,
            addend: 0,
        })
        .unwrap();
    module
        .add_relocation(Relocation {
            section: text,
            offset: 8,
            symbol: import,
            kind: RelocKind::Relative32,
            addend: -4,
        })
        .unwrap();
    let segment_name = module.intern("PT_LOAD").unwrap();
    module.add_segment(Segment {
        name: segment_name,
        address: 0x40_1000,
        vm_size: 16,
        flags: SectionFlags::code(),
        sections: vec![text],
    });
    module.add_segment(Segment {
        name: segment_name,
        address: 0x40_2000,
        vm_size: 8,
        flags: SectionFlags {
            read: false,
            write: true,
            execute: false,
        },
        sections: vec![data],
    });
    module.set_entry(0x40_1000);
    let _ = start;

    assert_round_trip(&module).unwrap();
    let bytes = write(&module).unwrap();
    let parsed = read(&bytes).unwrap();
    assert_eq!(parsed.symbol_count(), 3);
    assert_eq!(parsed.relocation_count(), 2);
}

#[test]
fn rejects_truncated_header() {
    let module = samples::hello_world_x86_64_linux().unwrap();
    let bytes = write(&module).unwrap();
    let head = bytes.get(..8).unwrap();
    assert!(read(head).is_err());
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = write(&samples::hello_world_x86_64_linux().unwrap()).unwrap();
    *bytes.first_mut().unwrap() = 0x00;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_unknown_class() {
    let mut bytes = write(&samples::hello_world_x86_64_linux().unwrap()).unwrap();
    *bytes.get_mut(4).unwrap() = 9;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_unknown_data_encoding() {
    let mut bytes = write(&samples::hello_world_x86_64_linux().unwrap()).unwrap();
    *bytes.get_mut(5).unwrap() = 9;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_empty_input() {
    assert!(read(&[]).is_err());
}

#[test]
fn rejects_truncated_body() {
    let bytes = write(&samples::hello_world_x86_64_linux().unwrap()).unwrap();
    let half = bytes.len() / 2;
    let partial = bytes.get(..half).unwrap();
    assert!(read(partial).is_err());
}
