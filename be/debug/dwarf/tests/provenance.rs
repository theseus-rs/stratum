//! End-to-end provenance: synthetic HIR/Source spans survive a DWARF round trip attached to
//! an object module.

use std::{fs, path::Path, process::Command};

use stratum_diagnostics::{FileId, Span};
use stratum_dwarf::{
    DwarfSections, apply_to_object, decode, decode_sections, encode, encode_sections, from_object,
};
use stratum_oir::{BinaryFormat, FunctionRecord, LineRecord, ObjectModule, TargetSpec};

fn build_module_with_debug() -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    let start = module.intern("_start")?;
    // Three machine ranges mapped to source byte spans, as a front end would lower them.
    module.debug_mut().add_line(LineRecord {
        address: 0x40_1000,
        length: 7,
        span: Span::new(FileId::from_raw(0), 0, 13),
    });
    module.debug_mut().add_line(LineRecord {
        address: 0x40_1007,
        length: 5,
        span: Span::new(FileId::from_raw(0), 13, 27),
    });
    module.debug_mut().add_line(LineRecord {
        address: 0x40_100c,
        length: 2,
        span: Span::new(FileId::from_raw(2), 40, 55),
    });
    module.debug_mut().add_function(FunctionRecord {
        name: start,
        address: 0x40_1000,
        length: 14,
    });
    Ok(module)
}

#[test]
fn spans_survive_dwarf_round_trip() {
    let module = build_module_with_debug().unwrap();
    let table = from_object(&module).unwrap();
    let bytes = encode(&table).unwrap();
    let decoded = decode(&bytes).unwrap();

    let mut rebuilt = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    apply_to_object(&mut rebuilt, &decoded).unwrap();

    // Line provenance matches exactly.
    assert_eq!(module.debug().lines(), rebuilt.debug().lines());

    // Address lookups resolve back to the original source spans.
    assert_eq!(
        rebuilt.debug().span_at(0x40_1003),
        Some(Span::new(FileId::from_raw(0), 0, 13)),
    );
    assert_eq!(
        rebuilt.debug().span_at(0x40_100c),
        Some(Span::new(FileId::from_raw(2), 40, 55)),
    );

    // Function provenance survives, including the interned name.
    let original = module.debug().functions().first().unwrap();
    let restored = rebuilt.debug().functions().first().unwrap();
    assert_eq!(restored.address, original.address);
    assert_eq!(restored.length, original.length);
    assert_eq!(rebuilt.resolve(restored.name).unwrap(), "_start");
}

#[test]
fn function_provenance_lives_in_info_not_line_trailer() {
    let module = build_module_with_debug().unwrap();
    let table = from_object(&module).unwrap();
    let sections = encode_sections(&table).unwrap();

    assert!(!contains_bytes(&sections.line, b"FUNC"));
    assert!(contains_bytes(&sections.strings, b"_start"));
    assert!(contains_bytes(&sections.abbrev, &[0x2e]));

    let decoded = decode_sections(&sections).unwrap();
    assert_eq!(decoded, table);
}

#[test]
fn malformed_die_string_offset_is_rejected() {
    let module = build_module_with_debug().unwrap();
    let table = from_object(&module).unwrap();
    let mut sections = encode_sections(&table).unwrap();
    sections.strings.clear();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn emitted_sections_pass_llvm_dwarfdump_when_available() {
    let dwarfdump = Path::new("/opt/homebrew/opt/llvm/bin/llvm-dwarfdump");
    if !dwarfdump.exists() {
        return;
    }

    let module = build_module_with_debug().unwrap();
    let table = from_object(&module).unwrap();
    let sections = encode_sections(&table).unwrap();
    let object = elf_object(&sections).unwrap();
    let path = Path::new("target/stratum-dwarf-verify.o");
    fs::create_dir_all("target").unwrap();
    fs::write(path, object).unwrap();

    let output = Command::new(dwarfdump)
        .arg("--verify")
        .arg("--error-display=summary")
        .arg(path)
        .output()
        .unwrap();
    fs::remove_file(path).unwrap();

    assert!(
        output.status.success(),
        "llvm-dwarfdump failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn elf_object(sections: &DwarfSections) -> Result<Vec<u8>, &'static str> {
    let shstrtab = ShStrTab::new()?;
    let mut out = Vec::new();
    write_elf_header(&mut out, ShStrTab::section_count(), ShStrTab::index())?;

    let payloads = [
        shstrtab.bytes.as_slice(),
        sections.abbrev.as_slice(),
        sections.info.as_slice(),
        sections.line.as_slice(),
        sections.strings.as_slice(),
        sections.aranges.as_slice(),
    ];
    let mut offsets = Vec::new();
    for payload in payloads {
        align_to(&mut out, 1);
        offsets.push(u64::try_from(out.len()).map_err(|_| "offset")?);
        out.extend_from_slice(payload);
    }
    align_to(&mut out, 8);
    let shoff = u64::try_from(out.len()).map_err(|_| "section offset")?;
    patch_u64(&mut out, 40, shoff)?;

    write_null_section(&mut out);
    write_section(
        &mut out,
        shstrtab.name_offset(".shstrtab")?,
        3,
        offsets.first().copied().ok_or("shstr offset")?,
        shstrtab.bytes.len(),
    )?;
    write_section(
        &mut out,
        shstrtab.name_offset(".debug_abbrev")?,
        1,
        *offsets.get(1).ok_or("abbrev offset")?,
        sections.abbrev.len(),
    )?;
    write_section(
        &mut out,
        shstrtab.name_offset(".debug_info")?,
        1,
        *offsets.get(2).ok_or("info offset")?,
        sections.info.len(),
    )?;
    write_section(
        &mut out,
        shstrtab.name_offset(".debug_line")?,
        1,
        *offsets.get(3).ok_or("line offset")?,
        sections.line.len(),
    )?;
    write_section(
        &mut out,
        shstrtab.name_offset(".debug_str")?,
        3,
        *offsets.get(4).ok_or("str offset")?,
        sections.strings.len(),
    )?;
    write_section(
        &mut out,
        shstrtab.name_offset(".debug_aranges")?,
        1,
        *offsets.get(5).ok_or("aranges offset")?,
        sections.aranges.len(),
    )?;
    Ok(out)
}

struct ShStrTab {
    bytes: Vec<u8>,
    names: Vec<(&'static str, u32)>,
}

impl ShStrTab {
    fn new() -> Result<Self, &'static str> {
        let mut tab = Self {
            bytes: vec![0],
            names: Vec::new(),
        };
        for name in [
            ".shstrtab",
            ".debug_abbrev",
            ".debug_info",
            ".debug_line",
            ".debug_str",
            ".debug_aranges",
        ] {
            tab.add(name)?;
        }
        Ok(tab)
    }

    fn add(&mut self, name: &'static str) -> Result<(), &'static str> {
        let offset = u32::try_from(self.bytes.len()).map_err(|_| "name offset")?;
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.names.push((name, offset));
        Ok(())
    }

    fn name_offset(&self, name: &str) -> Result<u32, &'static str> {
        self.names
            .iter()
            .find_map(|(candidate, offset)| (*candidate == name).then_some(*offset))
            .ok_or("section name")
    }

    const fn section_count() -> u16 {
        7
    }

    const fn index() -> u16 {
        1
    }
}

fn write_elf_header(out: &mut Vec<u8>, shnum: u16, shstrndx: u16) -> Result<(), &'static str> {
    out.extend_from_slice(b"\x7fELF");
    out.extend_from_slice(&[2, 1, 1, 0, 0]);
    out.extend_from_slice(&[0; 7]);
    write_u16(out, 1);
    write_u16(out, 62);
    write_u32(out, 1);
    write_u64(out, 0);
    write_u64(out, 0);
    write_u64(out, 0);
    write_u32(out, 0);
    write_u16(out, 64);
    write_u16(out, 0);
    write_u16(out, 0);
    write_u16(out, 64);
    write_u16(out, shnum);
    write_u16(out, shstrndx);
    if out.len() == 64 {
        Ok(())
    } else {
        Err("elf header length")
    }
}

fn write_null_section(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0; 64]);
}

fn write_section(
    out: &mut Vec<u8>,
    name: u32,
    section_type: u32,
    offset: u64,
    len: usize,
) -> Result<(), &'static str> {
    write_u32(out, name);
    write_u32(out, section_type);
    write_u64(out, 0);
    write_u64(out, 0);
    write_u64(out, offset);
    write_u64(out, u64::try_from(len).map_err(|_| "section length")?);
    write_u32(out, 0);
    write_u32(out, 0);
    write_u64(out, 1);
    write_u64(out, 0);
    Ok(())
}

fn align_to(out: &mut Vec<u8>, align: usize) {
    let rem = out.len() % align;
    if rem != 0 {
        out.resize(out.len().saturating_add(align - rem), 0);
    }
}

fn patch_u64(out: &mut [u8], offset: usize, value: u64) -> Result<(), &'static str> {
    let end = offset.checked_add(8).ok_or("patch overflow")?;
    let range = out.get_mut(offset..end).ok_or("patch range")?;
    range.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
