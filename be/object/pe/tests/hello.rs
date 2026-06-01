//! Host-aware "Hello, world!" integration test for the PE codec.
//!
//! On `windows + x86_64` the produced executable is run and its stdout is checked. On every
//! other host the bytes are validated structurally only, so the suite passes everywhere.

use stratum_oir::{
    BinaryFormat, ObjectModule, Section, SectionFlags, SectionKind, SymbolBinding, SymbolEntry,
    SymbolFlags, SymbolKind, TargetSpec,
};
use stratum_pe::{read, samples, write};

fn build_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_x86_64_windows()?;
    write(&module)
}

#[test]
fn all_sample_builders_are_reachable_in_this_binary() {
    for module in [
        samples::hello_world_aarch64_windows().unwrap(),
        samples::pe32_import_fixture().unwrap(),
        samples::directory_fixture().unwrap(),
    ] {
        let bytes = write(&module).unwrap();
        let reparsed = read(&bytes).unwrap();
        assert_eq!(reparsed.format(), BinaryFormat::Pe);
    }
    assert_ne!(samples::image_base64(), 0);
}

#[test]
fn pe_is_structurally_valid() {
    let bytes = build_bytes().unwrap();
    assert_eq!(bytes.get(0..2), Some(b"MZ".as_slice()), "DOS magic");
    let e_lfanew = u32::from_le_bytes(
        bytes
            .get(0x3C..0x40)
            .and_then(|s| s.try_into().ok())
            .unwrap(),
    );
    let pe_off = usize::try_from(e_lfanew).unwrap();
    assert_eq!(
        bytes.get(pe_off..pe_off + 4),
        Some(b"PE\0\0".as_slice()),
        "PE signature"
    );
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[test]
fn pe_runs_and_prints_hello() {
    use std::io::Write;

    let bytes = build_bytes().unwrap();
    let dir = std::env::current_dir().unwrap().join("target");
    let path = dir.join(format!("stratum_hello_{}.exe", std::process::id()));
    {
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&bytes).unwrap();
    }

    let output = std::process::Command::new(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "process exited with failure: {:?}",
        output.status
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
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

#[test]
fn malformed_images_are_rejected_or_written() {
    for arch in [
        stratum_oir::Architecture::X86,
        stratum_oir::Architecture::Arm,
        stratum_oir::Architecture::X86_64,
        stratum_oir::Architecture::Aarch64,
    ] {
        let module = samples::machine_fixture(arch).unwrap();
        let bytes = write(&module).unwrap();
        assert_eq!(read(&bytes).unwrap().target().arch, arch);
    }
    assert!(samples::machine_fixture(stratum_oir::Architecture::Wasm32).is_err());

    let mut bytes = build_bytes().unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u32(&mut bytes, pe, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = build_bytes().unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4 + 20, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = build_bytes().unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4 + 16, 2).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = build_bytes().unwrap();
    let pe = pe_header_offset(&bytes).unwrap();
    put_u16(&mut bytes, pe + 4, 0xffff).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = build_bytes().unwrap();
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

    let mut bytes = build_bytes().unwrap();
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
