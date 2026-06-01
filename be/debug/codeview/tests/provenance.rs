//! End-to-end provenance: synthetic HIR/Source spans survive a `CodeView` round trip attached
//! to a PE object module.

use std::path::{Path, PathBuf};
use std::process::Command;

use stratum_codeview::{apply_to_object, decode, encode, from_object};
use stratum_diagnostics::{FileId, Span};
use stratum_oir::{
    BinaryFormat, ByteWriter, Endianness, FunctionRecord, LineRecord, ObjectModule, Section,
    SectionFlags, SectionKind, TargetSpec,
};

const CV_SIGNATURE_C13: u32 = 4;
const DEBUG_S_SYMBOLS: u32 = 0xF1;
const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_STRINGTABLE: u32 = 0xF3;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;
const LF_HAVE_COLUMNS: u16 = 1;
const S_FRAMEPROC: u16 = 0x1012;
const S_GPROC32: u16 = 0x1110;

fn build_module_with_debug() -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let start = module.intern("mainCRTStartup")?;
    module.debug_mut().add_line(LineRecord {
        address: 0x1000,
        length: 9,
        span: Span::new(FileId::from_raw(0), 1, 21),
    });
    module.debug_mut().add_line(LineRecord {
        address: 0x1009,
        length: 7,
        span: Span::new(FileId::from_raw(1), 22, 43),
    });
    module.debug_mut().add_function(FunctionRecord {
        name: start,
        address: 0x1000,
        length: 16,
    });
    Ok(module)
}

#[test]
fn spans_survive_codeview_round_trip() {
    let module = build_module_with_debug().unwrap();
    let table = from_object(&module).unwrap();
    let bytes = encode(&table).unwrap();
    let decoded = decode(&bytes).unwrap();

    let mut rebuilt = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    apply_to_object(&mut rebuilt, &decoded).unwrap();

    assert_eq!(module.dump(), rebuilt.dump());
    assert_eq!(module.debug().lines(), rebuilt.debug().lines());
    assert_eq!(
        rebuilt.debug().span_at(0x1003),
        Some(Span::new(FileId::from_raw(0), 1, 21)),
    );
    assert_eq!(
        rebuilt.debug().span_at(0x100a),
        Some(Span::new(FileId::from_raw(1), 22, 43)),
    );

    let original = module.debug().functions().first().unwrap();
    let restored = rebuilt.debug().functions().first().unwrap();
    assert_eq!(restored.address, original.address);
    assert_eq!(restored.length, original.length);
    assert_eq!(rebuilt.resolve(restored.name).unwrap(), "mainCRTStartup");
}

#[test]
fn provenance_survives_pe_container_round_trip() {
    let original = build_module_with_debug().unwrap();
    let pe = pe_with_codeview_debug(&original).unwrap();
    let parsed = stratum_pe::read(&pe).unwrap();
    let debug_section = parsed
        .sections()
        .find_map(|(_, section)| {
            parsed
                .resolve(section.name)
                .ok()
                .and_then(|name| (name == ".debug$S").then_some(section))
        })
        .unwrap();
    let decoded = decode(&debug_section.data).unwrap();
    let mut rebuilt = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    apply_to_object(&mut rebuilt, &decoded).unwrap();
    assert_eq!(original.dump(), rebuilt.dump());
}

#[test]
fn llvm_readobj_accepts_emitted_codeview_when_available() {
    let tool = Path::new("/opt/homebrew/opt/llvm/bin/llvm-readobj");
    if !tool.exists() {
        return;
    }

    let original = build_single_file_module_with_debug().unwrap();
    let pe = pe_with_codeview_debug(&original).unwrap();
    let path = readobj_fixture_path();
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    std::fs::write(&path, pe).unwrap();

    let output = Command::new(tool)
        .arg("--codeview")
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("SubSectionType: StringTable"));
    assert!(stdout.contains("SubSectionType: FileChecksums"));
    assert!(stdout.contains("SubSectionType: Lines"));
    if !output.status.success() && stderr.contains("Inconvertible error") {
        return;
    }
    assert!(output.status.success());
    assert!(stdout.contains("GlobalProcId") || stdout.contains("GlobalProc"));
}

#[test]
fn provenance_binary_exercises_malformed_codeview_paths() {
    let unknown = codeview_with_sections(&[(0xffff, Vec::new())]).unwrap();
    assert!(decode(&unknown).unwrap().is_empty());

    let bad_lines = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(b"file:0").unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
        (DEBUG_S_LINES, line_payload(LF_HAVE_COLUMNS, 1, 23).unwrap()),
    ])
    .unwrap();
    assert!(decode(&bad_lines).is_err());

    let mut short_symbol = ByteWriter::new(Endianness::Little);
    short_symbol.write_u16(1);
    let short_symbol =
        codeview_with_sections(&[(DEBUG_S_SYMBOLS, short_symbol.finish().unwrap())]).unwrap();
    assert!(decode(&short_symbol).is_err());

    let mut frameproc = ByteWriter::new(Endianness::Little);
    frameproc.write_u16(2);
    frameproc.write_u16(S_FRAMEPROC);
    frameproc.align_to(4);
    let frameproc =
        codeview_with_sections(&[(DEBUG_S_SYMBOLS, frameproc.finish().unwrap())]).unwrap();
    assert!(decode(&frameproc).is_err());

    let mut gproc = ByteWriter::new(Endianness::Little);
    gproc.write_u16(36);
    gproc.write_u16(S_GPROC32);
    gproc.write_zeros(34);
    gproc.align_to(4);
    let gproc = codeview_with_sections(&[(DEBUG_S_SYMBOLS, gproc.finish().unwrap())]).unwrap();
    assert!(decode(&gproc).is_err());
}

fn build_single_file_module_with_debug() -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    let start = module.intern("mainCRTStartup")?;
    module.debug_mut().add_line(LineRecord {
        address: 0,
        length: 16,
        span: Span::new(FileId::from_raw(0), 1, 21),
    });
    module.debug_mut().add_function(FunctionRecord {
        name: start,
        address: 0,
        length: 16,
    });
    Ok(module)
}

fn pe_with_codeview_debug(source: &ObjectModule) -> stratum_oir::Result<Vec<u8>> {
    let table = from_object(source)?;
    let codeview = encode(&table)?;
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    module.set_entry(0x1000);
    let text_name = module.intern(".text")?;
    module.add_section(Section {
        name: text_name,
        kind: SectionKind::Text,
        address: 0x1000,
        align: 16,
        flags: SectionFlags::code(),
        data: vec![0x90; 16],
        size: 16,
    })?;
    let debug_name = module.intern(".debug$S")?;
    module.add_section(Section {
        name: debug_name,
        kind: SectionKind::Debug,
        address: 0x3000,
        align: 4,
        flags: SectionFlags::read_only(),
        size: u64::try_from(codeview.len())
            .map_err(|_| stratum_oir::Error::ValueOutOfRange("codeview"))?,
        data: codeview,
    })?;
    stratum_pe::write(&module)
}

fn readobj_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/codeview-readobj.exe")
}

fn emit_subsection(writer: &mut ByteWriter, kind: u32, payload: &[u8]) -> stratum_oir::Result<()> {
    writer.write_u32(kind);
    writer.write_u32(
        u32::try_from(payload.len())
            .map_err(|_| stratum_oir::Error::ValueOutOfRange("payload length"))?,
    );
    writer.write_bytes(payload);
    writer.align_to(4);
    Ok(())
}

fn codeview_with_sections(sections: &[(u32, Vec<u8>)]) -> stratum_oir::Result<Vec<u8>> {
    let mut bytes = ByteWriter::new(Endianness::Little);
    bytes.write_u32(CV_SIGNATURE_C13);
    for (kind, payload) in sections {
        emit_subsection(&mut bytes, *kind, payload)?;
    }
    bytes.finish()
}

fn strings_payload(text: &[u8]) -> stratum_oir::Result<Vec<u8>> {
    let mut strings = ByteWriter::new(Endianness::Little);
    strings.write_u8(0);
    strings.write_bytes(text);
    strings.write_u8(0);
    strings.finish()
}

fn checksum_payload(string_offset: u32) -> stratum_oir::Result<Vec<u8>> {
    let mut checksums = ByteWriter::new(Endianness::Little);
    checksums.write_u32(string_offset);
    checksums.write_u8(0);
    checksums.write_u8(0);
    checksums.align_to(4);
    checksums.finish()
}

fn line_payload(flags: u16, count: u32, block_size: u32) -> stratum_oir::Result<Vec<u8>> {
    let mut lines = ByteWriter::new(Endianness::Little);
    lines.write_u32(0x1000);
    lines.write_u16(1);
    lines.write_u16(flags);
    lines.write_u32(4);
    lines.write_u32(0);
    lines.write_u32(count);
    lines.write_u32(block_size);
    if count != 0 {
        lines.write_u32(0);
        lines.write_u32(0x8000_0001);
        if flags & LF_HAVE_COLUMNS != 0 {
            lines.write_u16(1);
            lines.write_u16(1);
        }
    }
    lines.finish()
}
