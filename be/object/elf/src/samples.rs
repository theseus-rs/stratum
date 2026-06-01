//! Freestanding and structural sample modules used by integration tests.

use crate::consts::{LOAD_BASE, PAGE_SIZE};
use stratum_oir::{
    Architecture, BinaryFormat, Endianness, Error, ObjectModule, PtrWidth, RelocKind, Relocation,
    Result, Section, SectionFlags, SectionKind, Segment, Symbol, SymbolBinding, SymbolEntry,
    SymbolFlags, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// The exact bytes the sample programs print to standard output.
pub const HELLO_MESSAGE: &str = "Hello, world!\n";

/// Builds a freestanding `x86_64` Linux executable module that writes [`HELLO_MESSAGE`] to
/// stdout via the `write` syscall and exits cleanly via `exit`.
///
/// # Errors
///
/// Returns an error if the message length does not fit a 32-bit immediate or an arena fills.
pub fn hello_world_x86_64_linux() -> Result<ObjectModule> {
    let message = HELLO_MESSAGE.as_bytes();
    let base = LOAD_BASE + PAGE_SIZE;
    let code_len: u64 = 39;
    let msg_addr = base + code_len;
    let len = u32_len(message.len(), "message too long")?;

    let mut text: Vec<u8> = Vec::new();
    text.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x48, 0xbe]);
    text.extend_from_slice(&msg_addr.to_le_bytes());
    text.push(0xba);
    text.extend_from_slice(&len.to_le_bytes());
    text.extend_from_slice(&[0x0f, 0x05]);
    text.extend_from_slice(&[0xb8, 0x3c, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0xbf, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x0f, 0x05]);
    text.extend_from_slice(message);

    executable_with_text(TargetSpec::x86_64(), base, text, code_len)
}

/// Builds a freestanding `aarch64` Linux executable module that writes [`HELLO_MESSAGE`] to
/// stdout via raw syscalls and exits cleanly.
///
/// # Errors
///
/// Returns an error if an arena fills.
pub fn hello_world_aarch64_linux() -> Result<ObjectModule> {
    let base = LOAD_BASE + PAGE_SIZE;
    let text: Vec<u8> = vec![
        0x21, 0x00, 0x80, 0xd2, 0xe2, 0x01, 0x80, 0xd2, 0x03, 0x01, 0x00, 0x10, 0x08, 0x08, 0x80,
        0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00,
        0x00, 0xd4, b'H', b'e', b'l', b'l', b'o', b',', b' ', b'w', b'o', b'r', b'l', b'd', b'!',
        b'\n',
    ];
    executable_with_text(TargetSpec::aarch64(), base, text, 32)
}

fn executable_with_text(
    target: TargetSpec,
    base: u64,
    text: Vec<u8>,
    code_len: u64,
) -> Result<ObjectModule> {
    let size = u64_len(text.len());
    let mut module = ObjectModule::new(BinaryFormat::Elf, target);
    let name = intern(&mut module, ".text")?;
    let text_section = Section {
        name,
        kind: SectionKind::Text,
        address: base,
        align: PAGE_SIZE,
        flags: SectionFlags::code(),
        data: text,
        size,
    };
    let section = add_section(&mut module, text_section)?;
    let segment_name = intern(&mut module, "PT_LOAD")?;
    module.add_segment(Segment {
        name: segment_name,
        address: base,
        vm_size: size,
        flags: SectionFlags::code(),
        sections: vec![section],
    });
    let start_name = intern(&mut module, "_start")?;
    let start_symbol = SymbolEntry {
        name: start_name,
        value: base,
        size: code_len,
        section: Some(section),
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::none(),
    };
    let _ = add_symbol(&mut module, start_symbol)?;
    module.set_entry(base);
    Ok(module)
}

/// Returns structural samples for every ELF target family supported by the codec.
///
/// # Errors
///
/// Returns an error if any sample cannot be built.
pub fn structural_samples() -> Result<Vec<(String, ObjectModule)>> {
    let specs = [
        ("x86_64", TargetSpec::x86_64()),
        ("aarch64", TargetSpec::aarch64()),
        ("aarch64_be", TargetSpec::aarch64_be()),
        ("arm", TargetSpec::arm()),
        ("i386", TargetSpec::x86()),
        ("riscv64", TargetSpec::riscv64()),
        ("powerpc", TargetSpec::powerpc()),
        ("powerpc64", TargetSpec::powerpc64()),
        ("powerpc64le", TargetSpec::powerpc64le()),
        ("s390x", TargetSpec::s390x()),
        ("mips", TargetSpec::mips()),
        ("mipsel", TargetSpec::mipsel()),
        ("mips64", TargetSpec::mips64()),
        ("mips64el", TargetSpec::mips64el()),
        ("loongarch64", TargetSpec::loongarch64()),
        ("sparcv9", TargetSpec::sparc64()),
    ];
    let mut out = Vec::new();
    for (name, spec) in specs {
        out.push((name.to_string(), structural_sample(name, spec)?));
    }
    Ok(out)
}

#[expect(
    clippy::too_many_lines,
    reason = "sample construction keeps section, symbol, and segment fixtures in one readable flow"
)]
fn structural_sample(name: &str, target: TargetSpec) -> Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Elf, target);
    let text_addr = LOAD_BASE + PAGE_SIZE;
    let ro_addr = LOAD_BASE + (PAGE_SIZE * 2);
    let data_addr = LOAD_BASE + (PAGE_SIZE * 3);
    let bss_addr = LOAD_BASE + (PAGE_SIZE * 4);

    let text_name = intern(&mut module, ".text")?;
    let text_section = Section {
        name: text_name,
        kind: SectionKind::Text,
        address: text_addr,
        align: PAGE_SIZE,
        flags: SectionFlags::code(),
        data: sample_text(target),
        size: 16,
    };
    let text = add_section(&mut module, text_section)?;
    let rodata_bytes = format_bytes(name.as_bytes(), target);
    let rodata_size = u64_len(rodata_bytes.len());
    let rodata_name = intern(&mut module, ".rodata")?;
    let rodata_section = Section {
        name: rodata_name,
        kind: SectionKind::ReadOnlyData,
        address: ro_addr,
        align: PAGE_SIZE,
        flags: SectionFlags::read_only(),
        size: rodata_size,
        data: rodata_bytes,
    };
    let rodata = add_section(&mut module, rodata_section)?;
    let data_bytes = format_bytes(&[1, 2, 3, 4, 5, 6, 7, 8], target);
    let data_size = u64_len(data_bytes.len());
    let data_name = intern(&mut module, ".data")?;
    let data_section = Section {
        name: data_name,
        kind: SectionKind::Data,
        address: data_addr,
        align: PAGE_SIZE,
        flags: SectionFlags::data(),
        size: data_size,
        data: data_bytes,
    };
    let data = add_section(&mut module, data_section)?;
    let bss_name = intern(&mut module, ".bss")?;
    let bss_section = Section {
        name: bss_name,
        kind: SectionKind::Bss,
        address: bss_addr,
        align: PAGE_SIZE,
        flags: SectionFlags::data(),
        data: Vec::new(),
        size: 32,
    };
    let bss = add_section(&mut module, bss_section)?;
    add_other_sections(&mut module, name)?;
    let segment_name = intern(&mut module, "PT_LOAD")?;
    add_load_segment(
        &mut module,
        segment_name,
        text_addr,
        16,
        SectionFlags::code(),
        text,
    );
    add_load_segment(
        &mut module,
        segment_name,
        ro_addr,
        rodata_size,
        SectionFlags::read_only(),
        rodata,
    );
    add_load_segment(
        &mut module,
        segment_name,
        data_addr,
        data_size,
        SectionFlags::data(),
        data,
    );
    add_load_segment(
        &mut module,
        segment_name,
        bss_addr,
        32,
        SectionFlags::data(),
        bss,
    );

    let start_name = intern(&mut module, "_start")?;
    let start_symbol = SymbolEntry {
        name: start_name,
        value: text_addr,
        size: 16,
        section: Some(text),
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::none(),
    };
    let start = add_symbol(&mut module, start_symbol)?;
    let object_name = intern(&mut module, "sample_object")?;
    let object_symbol = SymbolEntry {
        name: object_name,
        value: data_addr,
        size: data_size,
        section: Some(data),
        kind: SymbolKind::Object,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::none(),
    };
    let object = add_symbol(&mut module, object_symbol)?;
    let ro_symbol_name = intern(&mut module, "local_rodata")?;
    let ro_symbol = SymbolEntry {
        name: ro_symbol_name,
        value: ro_addr,
        size: rodata_size,
        section: Some(rodata),
        kind: SymbolKind::Object,
        binding: SymbolBinding::Local,
        flags: SymbolFlags::none(),
    };
    let _ = add_symbol(&mut module, ro_symbol)?;
    let relocation = Relocation {
        section: text,
        offset: 4,
        symbol: object,
        kind: relocation_kind(target),
        addend: 0,
    };
    add_relocation(&mut module, relocation)?;
    module.set_entry(text_addr);
    let _ = start;
    Ok(module)
}

fn add_other_sections(module: &mut ObjectModule, name: &str) -> Result<()> {
    let note = note_bytes(name.as_bytes(), module.target())?;
    let note_name = intern(module, ".note.stratum")?;
    let note_section = Section {
        name: note_name,
        kind: SectionKind::Other,
        address: 0,
        align: 4,
        flags: SectionFlags {
            read: false,
            write: false,
            execute: false,
        },
        size: u64_len(note.len()),
        data: note,
    };
    let _ = add_section(module, note_section)?;
    let dynamic = vec![0; usize::from(module.target().ptr_width.bytes()) * 2];
    let dynamic = format_bytes(&dynamic, module.target());
    let dynamic_name = intern(module, ".dynamic")?;
    let dynamic_section = Section {
        name: dynamic_name,
        kind: SectionKind::Other,
        address: 0,
        align: u64::from(module.target().ptr_width.bytes()),
        flags: SectionFlags {
            read: false,
            write: false,
            execute: false,
        },
        size: u64_len(dynamic.len()),
        data: dynamic,
    };
    let _ = add_section(module, dynamic_section)?;
    Ok(())
}

fn note_bytes(description: &[u8], target: TargetSpec) -> Result<Vec<u8>> {
    let note_name = b"stratum\0";
    let mut out = Vec::new();
    push_u32(&mut out, target, u32_len(note_name.len(), "note name")?);
    push_u32(&mut out, target, u32_len(description.len(), "note desc")?);
    push_u32(&mut out, target, 1);
    out.extend_from_slice(note_name);
    pad_note(&mut out);
    out.extend_from_slice(description);
    pad_note(&mut out);
    Ok(out)
}

fn push_u32(out: &mut Vec<u8>, target: TargetSpec, value: u32) {
    match target.endian {
        Endianness::Little => out.extend_from_slice(&value.to_le_bytes()),
        Endianness::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn pad_note(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn u32_len(len: usize, what: &'static str) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::ValueOutOfRange(what))
}

fn u64_len(len: usize) -> u64 {
    len as u64
}

fn intern(module: &mut ObjectModule, text: &str) -> Result<Symbol> {
    module.intern(text)
}

fn add_section(module: &mut ObjectModule, section: Section) -> Result<stratum_oir::SectionId> {
    module.add_section(section)
}

fn add_symbol(module: &mut ObjectModule, symbol: SymbolEntry) -> Result<stratum_oir::SymbolId> {
    module.add_symbol(symbol)
}

fn add_relocation(module: &mut ObjectModule, relocation: Relocation) -> Result<()> {
    module.add_relocation(relocation).map(|_| ())
}

fn add_load_segment(
    module: &mut ObjectModule,
    segment_name: Symbol,
    address: u64,
    vm_size: u64,
    flags: SectionFlags,
    section: stratum_oir::SectionId,
) {
    module.add_segment(Segment {
        name: segment_name,
        address,
        vm_size,
        flags,
        sections: vec![section],
    });
}

fn sample_text(target: TargetSpec) -> Vec<u8> {
    match (target.ptr_width, target.endian) {
        (_, Endianness::Little) => vec![
            0x90, 0x90, 0x90, 0x90, 0, 0, 0, 0, 0xc3, 0, 0, 0, 0, 0, 0, 0,
        ],
        (PtrWidth::W32, Endianness::Big) => {
            vec![0x60, 0, 0, 0, 0, 0, 0, 0, 0x4e, 0x80, 0, 0x20, 0, 0, 0, 0]
        }
        (PtrWidth::W64, Endianness::Big) => {
            vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0x4e, 0x80, 0, 0x20, 0, 0, 0, 0]
        }
    }
}

fn format_bytes(bytes: &[u8], target: TargetSpec) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if target.endian == Endianness::Big {
        out.reverse();
    }
    out
}

fn relocation_kind(target: TargetSpec) -> RelocKind {
    if matches!(target.ptr_width, PtrWidth::W64)
        && !matches!(target.arch, Architecture::PowerPc | Architecture::Mips)
    {
        RelocKind::Absolute64
    } else {
        RelocKind::Absolute32
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn sample_helpers_cover_remaining_paths() {
        assert!(u32_len(usize::MAX, "too large").is_err());
        assert_eq!(u64_len(usize::MAX), usize::MAX as u64);

        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        add_other_sections(&mut module, "coverage").unwrap();
        let name = module.intern(".text").unwrap();
        let section = module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: LOAD_BASE,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: Vec::new(),
                size: 0,
            })
            .unwrap();
        let segment_name = module.intern("PT_LOAD").unwrap();
        add_load_segment(
            &mut module,
            segment_name,
            LOAD_BASE,
            0,
            SectionFlags::code(),
            section,
        );
    }
}
