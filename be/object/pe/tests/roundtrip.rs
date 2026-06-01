//! Round-trip fidelity tests for the PE codec.

use std::path::Path;
use stratum_oir::{
    Architecture, BinaryFormat, ObjectModule, OirBridge, Section, SectionFlags, SectionKind,
    SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};
use stratum_pe::{Pe, read, samples, write};

fn assert_idempotent(module: &ObjectModule) -> stratum_oir::Result<()> {
    let first = write(module)?;
    let reparsed = read(&first)?;
    let second = write(&reparsed)?;
    if first != second {
        return Err(stratum_oir::Error::Malformed("round-tripped bytes changed"));
    }
    Ok(())
}

#[test]
fn all_sample_builders_are_reachable_in_this_binary() {
    for module in [
        samples::hello_world_aarch64_windows().unwrap(),
        samples::pe32_import_fixture().unwrap(),
        samples::directory_fixture().unwrap(),
    ] {
        assert_idempotent(&module).unwrap();
    }
    assert_ne!(samples::image_base64(), 0);
}

#[test]
fn write_read_write_is_byte_idempotent() {
    let module = samples::hello_world_x86_64_windows().unwrap();
    assert_idempotent(&module).unwrap();
}

#[test]
fn semantic_dump_survives_round_trip() {
    let module = samples::hello_world_x86_64_windows().unwrap();
    let bytes = Pe.write(&module).unwrap();
    let reparsed = Pe.read(&bytes).unwrap();
    assert_eq!(module.dump(), reparsed.dump());
}

#[test]
fn all_supported_machines_round_trip() {
    for arch in [
        Architecture::X86,
        Architecture::Arm,
        Architecture::X86_64,
        Architecture::Aarch64,
    ] {
        let module = samples::machine_fixture(arch).unwrap();
        assert_idempotent(&module).unwrap();
        let bytes = write(&module).unwrap();
        let parsed = read(&bytes).unwrap();
        assert_eq!(parsed.target().arch, arch);
    }
}

#[test]
fn pe32_import_table_round_trips() {
    let module = samples::pe32_import_fixture().unwrap();
    let bytes = write(&module).unwrap();
    let parsed = read(&bytes).unwrap();
    assert_eq!(parsed.target().arch, Architecture::X86);
    assert_eq!(parsed.imports().len(), 3);
    assert_idempotent(&parsed).unwrap();
}

#[test]
fn import_export_and_reloc_directories_are_validated() {
    let module = samples::directory_fixture().unwrap();
    let bytes = write(&module).unwrap();
    let parsed = read(&bytes).unwrap();
    assert_eq!(parsed.imports().len(), 3);
    assert_eq!(parsed.exports().len(), 1);
    assert_idempotent(&parsed).unwrap();
}

#[test]
fn rejects_truncated_header() {
    let module = samples::hello_world_x86_64_windows().unwrap();
    let bytes = write(&module).unwrap();
    let head = bytes.get(..2).unwrap();
    assert!(read(head).is_err());
}

#[test]
fn rejects_bad_dos_magic() {
    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    *bytes.first_mut().unwrap() = 0x00;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_empty_input() {
    assert!(read(&[]).is_err());
}

#[test]
fn rejects_truncated_body() {
    let bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let half = bytes.len() / 2;
    let partial = bytes.get(..half).unwrap();
    assert!(read(partial).is_err());
}

#[test]
fn rejects_unterminated_import_descriptors() {
    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe_off = pe_header_offset(&bytes).unwrap();
    let import_size_off = pe_off + 4 + 20 + 112 + 8 + 4;
    bytes
        .get_mut(import_size_off..import_size_off + 4)
        .unwrap()
        .copy_from_slice(&20u32.to_le_bytes());
    assert!(read(&bytes).is_err());
}

#[test]
fn llvm_readobj_accepts_self_emitted_image_when_available() {
    let tool = Path::new("/opt/homebrew/opt/llvm/bin/llvm-readobj");
    if !tool.exists() {
        return;
    }
    let bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let dir = std::env::current_dir().unwrap().join("target");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("stratum-pe-readobj-test.exe");
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new(tool)
        .arg("--coff-imports")
        .arg("--coff-exports")
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(output.status.success(), "llvm-readobj rejected PE fixture");
}

fn pe_header_offset(bytes: &[u8]) -> Option<usize> {
    let raw: [u8; 4] = bytes
        .get(0x3C..0x40)
        .and_then(|slice| slice.try_into().ok())?;
    usize::try_from(u32::from_le_bytes(raw)).ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.checked_add(2)?)
        .and_then(|slice| slice.try_into().ok())?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.checked_add(4)?)
        .and_then(|slice| slice.try_into().ok())?;
    Some(u32::from_le_bytes(raw))
}

fn rva_to_file_offset(bytes: &[u8], rva: u32) -> Option<usize> {
    let pe = pe_header_offset(bytes)?;
    let section_count = usize::from(read_u16(bytes, pe + 4 + 2)?);
    let optional_size = usize::from(read_u16(bytes, pe + 4 + 16)?);
    let section_table = pe + 4 + 20 + optional_size;
    for index in 0..section_count {
        let section = section_table + index.checked_mul(40)?;
        let virtual_size = read_u32(bytes, section + 8)?;
        let virtual_address = read_u32(bytes, section + 12)?;
        let raw_size = read_u32(bytes, section + 16)?;
        let raw_ptr = read_u32(bytes, section + 20)?;
        let span = virtual_size.max(raw_size).max(1);
        if rva >= virtual_address && rva < virtual_address.saturating_add(span) {
            return usize::try_from(raw_ptr.saturating_add(rva - virtual_address)).ok();
        }
    }
    None
}

fn section_table_offset(bytes: &[u8]) -> Option<usize> {
    let pe = pe_header_offset(bytes)?;
    let optional_size: [u8; 2] = bytes
        .get(pe + 4 + 16..pe + 4 + 18)
        .and_then(|slice| slice.try_into().ok())?;
    Some(pe + 4 + 20 + usize::from(u16::from_le_bytes(optional_size)))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Option<()> {
    bytes
        .get_mut(offset..offset.checked_add(2)?)
        .map(|slot| slot.copy_from_slice(&value.to_le_bytes()))
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    bytes
        .get_mut(offset..offset.checked_add(4)?)
        .map(|slot| slot.copy_from_slice(&value.to_le_bytes()))
}

#[test]
fn malformed_images_are_rejected_or_written() {
    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u32(&mut bytes, pe, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4 + 20, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4 + 16, 2).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4, 0xffff).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4, 0x014c).unwrap();
    assert!(read(&bytes).is_err());

    let unsupported = ObjectModule::new(BinaryFormat::Pe, TargetSpec::wasm32());
    assert!(write(&unsupported).is_err());

    let mut long_name = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let name = long_name.intern(".too-long").unwrap();
    long_name
        .add_section(Section {
            name,
            kind: SectionKind::Text,
            address: 0x1000,
            align: 1,
            flags: SectionFlags::code(),
            data: std::vec![0xC3],
            size: 1,
        })
        .unwrap();
    assert!(write(&long_name).is_err());
}

#[test]
fn symbol_table_edges_round_trip_through_public_reader() {
    let mut symbols = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let section_name = symbols.intern(".data").unwrap();
    let section = symbols
        .add_section(Section {
            name: section_name,
            kind: SectionKind::Data,
            address: 0x1000,
            align: 1,
            flags: SectionFlags::data(),
            data: std::vec![1, 2, 3],
            size: 3,
        })
        .unwrap();
    let symbol_name = symbols.intern("very_long_local_symbol").unwrap();
    symbols
        .add_symbol(SymbolEntry {
            name: symbol_name,
            value: 1,
            size: 0,
            section: Some(section),
            kind: SymbolKind::Object,
            binding: SymbolBinding::Local,
            flags: SymbolFlags::none(),
        })
        .unwrap();
    let section_symbol_name = symbols.intern(".data").unwrap();
    symbols
        .add_symbol(SymbolEntry {
            name: section_symbol_name,
            value: 0,
            size: 0,
            section: Some(section),
            kind: SymbolKind::Section,
            binding: SymbolBinding::Local,
            flags: SymbolFlags::none(),
        })
        .unwrap();
    let local_absolute = symbols.intern("local_absolute_symbol").unwrap();
    symbols
        .add_symbol(SymbolEntry {
            name: local_absolute,
            value: 0,
            size: 0,
            section: None,
            kind: SymbolKind::None,
            binding: SymbolBinding::Local,
            flags: SymbolFlags::none(),
        })
        .unwrap();
    let imported = symbols.intern("global_imported_symbol").unwrap();
    symbols
        .add_symbol(SymbolEntry {
            name: imported,
            value: 0,
            size: 0,
            section: None,
            kind: SymbolKind::None,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::imported(),
        })
        .unwrap();
    let parsed = read(&write(&symbols).unwrap()).unwrap();
    let mut saw_object = false;
    let mut saw_section = false;
    let mut saw_local_absolute = false;
    let mut saw_imported = false;
    for (_, symbol) in parsed.symbols() {
        match parsed.resolve(symbol.name).unwrap() {
            "very_long_local_symbol" => {
                saw_object = symbol.kind == SymbolKind::Object;
            }
            ".data" => {
                saw_section = symbol.kind == SymbolKind::Section;
            }
            "local_absolute_symbol" => {
                saw_local_absolute =
                    symbol.kind == SymbolKind::None && symbol.binding == SymbolBinding::Local;
            }
            "global_imported_symbol" => {
                saw_imported = symbol.kind == SymbolKind::None && symbol.flags.imported;
            }
            _ => {}
        }
    }
    assert!(saw_object);
    assert!(saw_section);
    assert!(saw_local_absolute);
    assert!(saw_imported);
}

#[test]
fn reads_zero_virtual_size_and_empty_raw_sections() {
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let data_name = module.intern(".data").unwrap();
    module
        .add_section(Section {
            name: data_name,
            kind: SectionKind::Data,
            address: 0x1000,
            align: 0x1000,
            flags: SectionFlags::data(),
            data: std::vec![0xAA],
            size: 1,
        })
        .unwrap();
    let empty_name = module.intern(".empty").unwrap();
    module
        .add_section(Section {
            name: empty_name,
            kind: SectionKind::Data,
            address: 0x2000,
            align: 0x1000,
            flags: SectionFlags::read_only(),
            data: std::vec![],
            size: 0,
        })
        .unwrap();

    let mut bytes = write(&module).unwrap();
    let first_section = section_table_offset(&bytes).unwrap();
    put_u32(&mut bytes, first_section + 8, 0).unwrap();

    let parsed = read(&bytes).unwrap();

    assert_eq!(parsed.section_count(), 2);
}

#[test]
fn bss_debug_and_bad_import_rva_are_read_through_public_api() {
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let bss_name = module.intern(".bss").unwrap();
    module
        .add_section(Section {
            name: bss_name,
            kind: SectionKind::Bss,
            address: 0x1000,
            align: 0x1000,
            flags: SectionFlags::data(),
            data: Vec::new(),
            size: 16,
        })
        .unwrap();
    let debug_name = module.intern(".debug").unwrap();
    module
        .add_section(Section {
            name: debug_name,
            kind: SectionKind::Debug,
            address: 0x2000,
            align: 0x1000,
            flags: SectionFlags::read_only(),
            data: std::vec![1],
            size: 1,
        })
        .unwrap();

    let parsed = read(&write(&module).unwrap()).unwrap();

    assert!(
        parsed
            .sections()
            .any(|(_, section)| section.kind == SectionKind::Bss)
    );
    assert!(
        parsed
            .sections()
            .any(|(_, section)| section.kind == SectionKind::Debug)
    );

    let mut bytes = write(&samples::hello_world_x86_64_windows().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u32(&mut bytes, pe + 4 + 20 + 112 + 8, 0xffff_0000).unwrap();
    assert!(read(&bytes).is_err());
}

#[test]
fn ordinal_import_uses_first_thunk_when_lookup_table_is_absent() {
    let mut bytes = write(&samples::pe32_import_fixture().unwrap()).unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    let optional_magic = read_u16(&bytes, pe + 4 + 20).unwrap();
    let directories = if optional_magic == 0x20b {
        pe + 4 + 20 + 112
    } else {
        pe + 4 + 20 + 96
    };
    let import_rva = read_u32(&bytes, directories + 8).unwrap();
    let import = rva_to_file_offset(&bytes, import_rva).unwrap();
    put_u32(&mut bytes, import, 0).unwrap();
    let first_thunk = read_u32(&bytes, import + 16).unwrap();
    let thunk = rva_to_file_offset(&bytes, first_thunk).unwrap();
    put_u32(&mut bytes, thunk, 0x8000_0007).unwrap();

    let parsed = read(&bytes).unwrap();

    assert!(
        parsed
            .imports()
            .iter()
            .any(|import| import.ordinal == Some(7))
    );
}
