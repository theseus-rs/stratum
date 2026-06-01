//! Round-trip fidelity tests for the Mach-O codec.

use stratum_macho::{MachO, read, samples, write};
use stratum_oir::{
    BinaryFormat, Import, ObjectModule, OirBridge, RelocKind, Relocation, Section, SectionFlags,
    SectionKind, SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(
        bytes.get(offset..end).and_then(|s| s.try_into().ok())?,
    ))
}

fn self_round_trip(module: &ObjectModule) -> TestResult {
    let first = write(module)?;
    let reparsed = read(&first)?;
    let second = write(&reparsed)?;
    if first != second {
        return Err(std::io::Error::other("round-tripped bytes changed").into());
    }
    let rereparsed = read(&second)?;
    if reparsed.dump() != rereparsed.dump() {
        return Err(std::io::Error::other("round-tripped dump changed").into());
    }
    Ok(())
}

fn rich_x86_64_module() -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86_64());
    let text_name = module.intern("__text")?;
    let data_name = module.intern("__data")?;
    let bss_name = module.intern("__bss")?;
    let text = module.add_section(Section {
        name: text_name,
        kind: SectionKind::Text,
        address: 0,
        align: 4,
        flags: SectionFlags::code(),
        data: vec![0xC3],
        size: 1,
    })?;
    let data = module.add_section(Section {
        name: data_name,
        kind: SectionKind::Data,
        address: 0,
        align: 8,
        flags: SectionFlags::data(),
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        size: 8,
    })?;
    module.add_section(Section {
        name: bss_name,
        kind: SectionKind::Bss,
        address: 0,
        align: 8,
        flags: SectionFlags::data(),
        data: Vec::new(),
        size: 16,
    })?;
    let start_name = module.intern("_start")?;
    let data_sym_name = module.intern("_global_data")?;
    let puts_name = module.intern("_puts")?;
    let lib_name = module.intern("/usr/lib/libSystem.B.dylib")?;
    let start = module.add_symbol(SymbolEntry {
        name: start_name,
        value: 0,
        size: 1,
        section: Some(text),
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::exported(),
    })?;
    let data_sym = module.add_symbol(SymbolEntry {
        name: data_sym_name,
        value: 0,
        size: 8,
        section: Some(data),
        kind: SymbolKind::Object,
        binding: SymbolBinding::Local,
        flags: SymbolFlags::none(),
    })?;
    module.add_symbol(SymbolEntry {
        name: puts_name,
        value: 0,
        size: 0,
        section: None,
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::imported(),
    })?;
    module.add_import(Import {
        library: lib_name,
        name: puts_name,
        ordinal: None,
        hint: None,
    });
    module.add_relocation(Relocation {
        section: data,
        offset: 0,
        symbol: data_sym,
        kind: RelocKind::Absolute64,
        addend: 0,
    })?;
    module.add_relocation(Relocation {
        section: text,
        offset: 0,
        symbol: start,
        kind: RelocKind::Relative32,
        addend: 0,
    })?;
    Ok(module)
}

#[test]
fn write_read_write_is_byte_idempotent() {
    let module = samples::hello_world_aarch64_macos().unwrap();
    self_round_trip(&module).unwrap();
}

#[test]
fn semantic_dump_stabilises_after_round_trip() {
    let module = samples::hello_world_aarch64_macos().unwrap();
    let bytes = MachO.write(&module).unwrap();
    let reparsed = MachO.read(&bytes).unwrap();
    let bytes2 = MachO.write(&reparsed).unwrap();
    let rereparsed = MachO.read(&bytes2).unwrap();
    assert_eq!(reparsed.dump(), rereparsed.dump());
}

#[test]
fn all_self_emitted_samples_are_byte_idempotent() {
    self_round_trip(&samples::hello_world_aarch64_macos().unwrap()).unwrap();
    self_round_trip(&samples::hello_world_x86_64_macos().unwrap()).unwrap();
    self_round_trip(&samples::empty_i386_macos().unwrap()).unwrap();
    self_round_trip(&samples::empty_arm_macos().unwrap()).unwrap();
}

#[test]
fn x86_section_image_round_trips() {
    let mut module = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86());
    let text_name = module.intern("__text").unwrap();
    module
        .add_section(Section {
            name: text_name,
            kind: SectionKind::Text,
            address: 0,
            align: 4,
            flags: SectionFlags::code(),
            data: vec![0xC3],
            size: 1,
        })
        .unwrap();

    self_round_trip(&module).unwrap();
}

#[test]
fn rich_module_preserves_symbols_imports_relocations_and_sections() {
    let first = write(&rich_x86_64_module().unwrap()).unwrap();
    let parsed = read(&first).unwrap();
    assert_eq!(parsed.section_count(), 3);
    assert_eq!(parsed.symbol_count(), 3);
    assert_eq!(parsed.relocation_count(), 2);
    assert_eq!(parsed.imports().len(), 1);
    assert_eq!(parsed.exports().len(), 1);
    let second = write(&parsed).unwrap();
    assert_eq!(first, second);
}

#[test]
fn public_reader_covers_section_and_relocation_variants() {
    let mut module = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86_64());
    let text_name = module.intern("__text").unwrap();
    let text = module
        .add_section(Section {
            name: text_name,
            kind: SectionKind::Text,
            address: 0,
            align: 4,
            flags: SectionFlags::code(),
            data: vec![0xC3],
            size: 1,
        })
        .unwrap();
    let const_name = module.intern("__const").unwrap();
    let const_section = module
        .add_section(Section {
            name: const_name,
            kind: SectionKind::ReadOnlyData,
            address: 0,
            align: 4,
            flags: SectionFlags::read_only(),
            data: vec![0; 32],
            size: 32,
        })
        .unwrap();
    let debug_name = module.intern("__debug_info").unwrap();
    module
        .add_section(Section {
            name: debug_name,
            kind: SectionKind::Debug,
            address: 0,
            align: 4,
            flags: SectionFlags::read_only(),
            data: vec![1, 2, 3, 4],
            size: 4,
        })
        .unwrap();
    let custom_name = module.intern("__custom").unwrap();
    module
        .add_section(Section {
            name: custom_name,
            kind: SectionKind::Other,
            address: 0,
            align: 4,
            flags: SectionFlags::read_only(),
            data: vec![5, 6, 7, 8],
            size: 4,
        })
        .unwrap();
    let target_name = module.intern("_target").unwrap();
    let target = module
        .add_symbol(SymbolEntry {
            name: target_name,
            value: 0,
            size: 1,
            section: Some(text),
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::exported(),
        })
        .unwrap();
    for (offset, kind) in [
        (0, RelocKind::Absolute32),
        (4, RelocKind::Relative64),
        (12, RelocKind::GotRelative),
        (20, RelocKind::Other(7)),
    ] {
        module
            .add_relocation(Relocation {
                section: const_section,
                offset,
                symbol: target,
                kind,
                addend: 0,
            })
            .unwrap();
    }

    let parsed = read(&write(&module).unwrap()).unwrap();
    let kinds = parsed
        .sections()
        .map(|(_, section)| section.kind)
        .collect::<Vec<_>>();
    let reloc_kinds = parsed
        .relocations()
        .map(|(_, relocation)| relocation.kind)
        .collect::<Vec<_>>();

    assert!(kinds.contains(&SectionKind::ReadOnlyData));
    assert!(kinds.contains(&SectionKind::Debug));
    assert!(kinds.contains(&SectionKind::Other));
    assert!(reloc_kinds.contains(&RelocKind::Absolute32));
    assert!(reloc_kinds.contains(&RelocKind::Relative64));
    assert!(reloc_kinds.contains(&RelocKind::GotRelative));
    assert!(reloc_kinds.contains(&RelocKind::Other(7)));
}

#[test]
fn required_load_commands_are_present() {
    let bytes = write(&rich_x86_64_module().unwrap()).unwrap();
    let ncmds = read_u32(&bytes, 16).unwrap();
    let sizeofcmds = read_u32(&bytes, 20).unwrap();
    let mut offset = 32_usize;
    let commands_end = offset
        .checked_add(usize::try_from(sizeofcmds).unwrap())
        .unwrap();
    let mut commands = Vec::new();
    for _ in 0..ncmds {
        let cmd = read_u32(&bytes, offset).unwrap();
        let cmdsize = read_u32(&bytes, offset + 4).unwrap();
        commands.push(cmd);
        offset = offset
            .checked_add(usize::try_from(cmdsize).unwrap())
            .unwrap();
    }
    assert_eq!(offset, commands_end);
    for required in [
        0x19_u32,
        0x2,
        0xB,
        0x8000_0022,
        0xE,
        0xC,
        0x32,
        0x8000_0028,
        0x1D,
    ] {
        assert!(
            commands.contains(&required),
            "missing load command {required:#x}"
        );
    }
}

#[test]
fn rejects_truncated_header() {
    let module = samples::hello_world_aarch64_macos().unwrap();
    let bytes = write(&module).unwrap();
    let head = bytes.get(..8).unwrap();
    assert!(read(head).is_err());
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = write(&samples::hello_world_aarch64_macos().unwrap()).unwrap();
    *bytes.first_mut().unwrap() = 0x00;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_empty_input() {
    assert!(read(&[]).is_err());
}

#[test]
fn rejects_truncated_body() {
    let bytes = write(&samples::hello_world_aarch64_macos().unwrap()).unwrap();
    let partial = bytes.get(..200).unwrap();
    assert!(read(partial).is_err());
}

#[test]
fn rejects_malformed_load_command_size() {
    let mut bytes = write(&samples::hello_world_aarch64_macos().unwrap()).unwrap();
    let size_field = bytes.get_mut(36..40).unwrap();
    size_field.copy_from_slice(&0_u32.to_le_bytes());
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_load_command_string_offset_at_command_end() {
    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0xFEED_FACF);
    push_u32(&mut bytes, 0x0100_0007);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 2);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0xC);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);

    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_segment_with_inconsistent_section_count() {
    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0xFEED_FACF);
    push_u32(&mut bytes, 0x0100_0007);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 2);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 72);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x19);
    push_u32(&mut bytes, 72);
    let mut segname = [0u8; 16];
    segname.get_mut(..6).unwrap().copy_from_slice(b"__TEXT");
    bytes.extend_from_slice(&segname);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u32(&mut bytes, 5);
    push_u32(&mut bytes, 5);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 0);

    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_symbol_string_index_at_string_table_end() {
    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0xFEED_FACF);
    push_u32(&mut bytes, 0x0100_0007);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 2);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x2);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 56);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 72);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 1);
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    push_u64(&mut bytes, 0);
    bytes.push(0);

    assert!(read(&bytes).is_err());
}
