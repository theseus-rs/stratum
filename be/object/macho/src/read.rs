//! Mach-O reader for the canonical images emitted by this crate and common little-endian Mach-O
//! files using the same core load commands.

use crate::consts::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64, LC_ID_DYLIB, LC_LAZY_LOAD_DYLIB,
    LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB, LC_SEGMENT,
    LC_SEGMENT_64, LC_SYMTAB, LC_THREAD, LC_UNIXTHREAD, MH_MAGIC, MH_MAGIC_64, N_EXT, N_TYPE,
    N_UNDF, NLIST_32_SIZE, NLIST_64_SIZE, S_TEXT_FLAGS, S_ZEROFILL, SECTION_32_SIZE, SECTION_64_SIZE,
    SEGMENT_COMMAND_32_SIZE, SEGMENT_COMMAND_64_SIZE,
};
use crate::convert::{u64_from_usize, usize_from_u32, usize_from_u64};
use stratum_oir::{
    Architecture, BinaryFormat, ByteReader, Endianness, Error, Export, Import, ObjectModule,
    RelocKind, Relocation, Result, Section, SectionFlags, SectionId, SectionKind, Segment, Symbol,
    SymbolBinding, SymbolEntry, SymbolFlags, SymbolId, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    W32,
    W64,
}

impl Width {
    const fn is_64(self) -> bool {
        matches!(self, Self::W64)
    }

    const fn section_size(self) -> u32 {
        match self {
            Self::W32 => SECTION_32_SIZE,
            Self::W64 => SECTION_64_SIZE,
        }
    }

    const fn nlist_size(self) -> u32 {
        match self {
            Self::W32 => NLIST_32_SIZE,
            Self::W64 => NLIST_64_SIZE,
        }
    }
}

#[derive(Debug, Clone)]
struct SectionRecord {
    sectname: String,
    segname: String,
    addr: u64,
    size: u64,
    offset: u32,
    align_exp: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
}

#[derive(Debug, Clone)]
struct SegmentRecord {
    name: String,
    addr: u64,
    size: u64,
    flags: SectionFlags,
    first_section: usize,
    section_count: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct Symtab {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

#[derive(Debug, Clone)]
struct Parsed {
    width: Width,
    target: TargetSpec,
    entry: Option<u64>,
    sections: Vec<SectionRecord>,
    segments: Vec<SegmentRecord>,
    dylibs: Vec<String>,
    symtab: Option<Symtab>,
}

/// Parses a little-endian Mach-O image into an [`ObjectModule`].
///
/// # Errors
///
/// Returns an error for unsupported magic/architectures, malformed load commands, out-of-bounds
/// table references, or invalid UTF-8 names.
pub fn read(bytes: &[u8]) -> Result<ObjectModule> {
    let parsed = parse_load_commands(bytes)?;
    let mut module = ObjectModule::new(BinaryFormat::MachO, parsed.target);
    let mut section_ids = Vec::new();
    for section in &parsed.sections {
        section_ids.push(add_section(&mut module, bytes, section)?);
    }
    for segment in &parsed.segments {
        add_segment(&mut module, segment, &section_ids)?;
    }
    if let Some(entry) = parsed.entry {
        module.set_entry(entry);
    }
    let symbol_ids = if let Some(symtab) = parsed.symtab {
        read_symbols(
            &mut module,
            bytes,
            parsed.width,
            symtab,
            &section_ids,
            &parsed.dylibs,
        )?
    } else {
        Vec::new()
    };
    read_parsed_relocations(&mut module, bytes, &parsed, &section_ids, &symbol_ids)?;
    Ok(module)
}

fn parse_header(bytes: &[u8]) -> Result<(ByteReader<'_>, Width, TargetSpec, usize, u32)> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    let magic = r.read_u32()?;
    let width = match magic {
        MH_MAGIC => Width::W32,
        MH_MAGIC_64 => Width::W64,
        _ => return Err(Error::Unsupported("not a little-endian Mach-O image")),
    };
    let cputype = r.read_u32()?;
    let _cpusubtype = r.read_u32()?;
    let _filetype = r.read_u32()?;
    let ncmds = r.read_u32()?;
    let sizeofcmds = r.read_u32()?;
    let _flags = r.read_u32()?;
    if width.is_64() {
        r.skip(4)?;
    }
    let target = target_for(cputype, width)?;
    let commands_start = r.position();
    let command_bytes = usize_from_u32(sizeofcmds);
    let commands_end = commands_start.saturating_add(command_bytes);
    Ok((r, width, target, commands_end, ncmds))
}

fn parse_load_commands(bytes: &[u8]) -> Result<Parsed> {
    let (mut r, width, target, commands_end, ncmds) = parse_header(bytes)?;

    let mut sections = Vec::new();
    let mut segments = Vec::new();
    let mut dylibs = Vec::new();
    let mut symtab = None;
    let mut entryoff = None;
    let mut thread_entry = None;
    let mut text_vmaddr = None;

    for _ in 0..ncmds {
        let command_offset = r.position();
        if command_offset >= commands_end {
            return Err(Error::Malformed("load command count exceeds sizeofcmds"));
        }
        let cmd = r.read_u32()?;
        let cmdsize = r.read_u32()?;
        let command_alignment = if width.is_64() { 8 } else { 4 };
        if cmdsize < 8 || cmdsize % command_alignment != 0 {
            return Err(Error::Malformed("invalid Mach-O load-command size"));
        }
        let cmd_end = command_offset.saturating_add(usize_from_u32(cmdsize));
        if cmd_end > commands_end {
            return Err(Error::Malformed("load command extends past command area"));
        }
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                if (cmd == LC_SEGMENT_64) != width.is_64() {
                    return Err(Error::Malformed("segment command width mismatch"));
                }
                parse_segment(
                    &mut r,
                    bytes,
                    width,
                    cmdsize,
                    &mut sections,
                    &mut segments,
                    &mut text_vmaddr,
                )?;
            }
            LC_SYMTAB => {
                symtab = Some(Symtab {
                    symoff: r.read_u32()?,
                    nsyms: r.read_u32()?,
                    stroff: r.read_u32()?,
                    strsize: r.read_u32()?,
                });
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => dylibs.push(read_command_string(
                bytes,
                command_offset,
                cmdsize,
                r.read_u32()?,
            )?),
            LC_MAIN => {
                entryoff = Some(r.read_u64()?);
                r.read_u64()?;
            }
            LC_THREAD | LC_UNIXTHREAD => {
                if let Some(value) = parse_thread_entry(&mut r, width, target.arch, cmd_end)? {
                    thread_entry = Some(value);
                }
            }
            _ => {}
        }
        r.seek(cmd_end)?;
    }
    if r.position() != commands_end {
        return Err(Error::Malformed("load commands do not match sizeofcmds"));
    }
    let entry = match (entryoff, text_vmaddr, thread_entry) {
        (Some(off), Some(base), _) => {
            Some(base.checked_add(off).ok_or(Error::ValueOutOfRange("entry"))?)
        }
        (_, _, Some(value)) => Some(value),
        _ => None,
    };
    Ok(Parsed {
        width,
        target,
        entry,
        sections,
        segments,
        dylibs,
        symtab,
    })
}

fn target_for(cputype: u32, width: Width) -> Result<TargetSpec> {
    let spec = match (cputype, width) {
        (CPU_TYPE_ARM64, Width::W64) => TargetSpec::aarch64(),
        (CPU_TYPE_X86_64, Width::W64) => TargetSpec::x86_64(),
        (CPU_TYPE_I386, Width::W32) => TargetSpec::x86(),
        (CPU_TYPE_ARM, Width::W32) => TargetSpec::arm(),
        _ => return Err(Error::Unsupported("unsupported Mach-O architecture")),
    };
    Ok(spec)
}

/// The zero-based register index of the program counter within a `*_THREAD_STATE` for `arch`.
const fn pc_register_index(arch: Architecture) -> u32 {
    match arch {
        Architecture::X86_64 => 16,
        Architecture::Aarch64 => 32,
        Architecture::X86 => 10,
        // Arm and any other 32-bit target keep the PC in r15.
        _ => 15,
    }
}

/// Extracts the entry-point address from an `LC_THREAD`/`LC_UNIXTHREAD` command.
///
/// Returns `Ok(None)` when the thread state is too short to hold the program counter, so a
/// truncated or unfamiliar thread flavor is skipped gracefully rather than rejected.
fn parse_thread_entry(
    r: &mut ByteReader<'_>,
    width: Width,
    arch: Architecture,
    cmd_end: usize,
) -> Result<Option<u64>> {
    let _flavor = r.read_u32()?;
    let _count = r.read_u32()?;
    let reg_size = if width.is_64() { 8_u64 } else { 4 };
    let pc_offset = usize_from_u64(u64::from(pc_register_index(arch)) * reg_size);
    let pc_start = r.position().saturating_add(pc_offset);
    let pc_end = pc_start.saturating_add(usize_from_u64(reg_size));
    if pc_end > cmd_end {
        return Ok(None);
    }
    r.skip(pc_offset)?;
    Ok(Some(read_addr(r, width)?))
}

fn parse_segment(
    r: &mut ByteReader<'_>,
    bytes: &[u8],
    width: Width,
    cmdsize: u32,
    sections: &mut Vec<SectionRecord>,
    segments: &mut Vec<SegmentRecord>,
    text_vmaddr: &mut Option<u64>,
) -> Result<()> {
    let segname = fixed_name(r.read_bytes(16)?)?;
    let vmaddr = read_addr(r, width)?;
    let vmsize = read_addr(r, width)?;
    let _fileoff = read_addr(r, width)?;
    let _filesize = read_addr(r, width)?;
    let _maxprot = r.read_u32()?;
    let initprot = r.read_u32()?;
    let nsects = r.read_u32()?;
    let _flags = r.read_u32()?;
    if segname == "__TEXT" {
        *text_vmaddr = Some(vmaddr);
    }
    let expected = width
        .section_size()
        .checked_mul(nsects)
        .and_then(|value| {
            value.checked_add(if width.is_64() {
                SEGMENT_COMMAND_64_SIZE
            } else {
                SEGMENT_COMMAND_32_SIZE
            })
        })
        .ok_or(Error::ValueOutOfRange("segment command"))?;
    if cmdsize != expected {
        return Err(Error::Malformed(
            "segment command has inconsistent section count",
        ));
    }
    let first_section = sections.len();
    for _ in 0..nsects {
        sections.push(parse_section(r, bytes, width)?);
    }
    segments.push(SegmentRecord {
        name: segname,
        addr: vmaddr,
        size: vmsize,
        flags: flags_from_prot(initprot),
        first_section,
        section_count: usize_from_u32(nsects),
    });
    Ok(())
}

fn read_addr(r: &mut ByteReader<'_>, width: Width) -> Result<u64> {
    match width {
        Width::W32 => Ok(u64::from(r.read_u32()?)),
        Width::W64 => r.read_u64(),
    }
}

fn parse_section(r: &mut ByteReader<'_>, bytes: &[u8], width: Width) -> Result<SectionRecord> {
    let sectname = fixed_name(r.read_bytes(16)?)?;
    let segname = fixed_name(r.read_bytes(16)?)?;
    let addr = read_addr(r, width)?;
    let size = read_addr(r, width)?;
    let offset = r.read_u32()?;
    let align_exp = r.read_u32()?;
    let reloff = r.read_u32()?;
    let nreloc = r.read_u32()?;
    let flags = r.read_u32()?;
    r.read_u32()?;
    r.read_u32()?;
    let _reserved3 = width.is_64().then(|| r.read_u32()).transpose()?;
    if nreloc != 0 {
        let reloc_bytes = u64::from(nreloc) * 8;
        check_range(bytes, u64::from(reloff), reloc_bytes)?;
    }
    Ok(SectionRecord {
        sectname,
        segname,
        addr,
        size,
        offset,
        align_exp,
        reloff,
        nreloc,
        flags,
    })
}

fn add_section(
    module: &mut ObjectModule,
    bytes: &[u8],
    record: &SectionRecord,
) -> Result<SectionId> {
    let name = module.intern(&record.sectname)?;
    let kind = section_kind(record);
    let file_size = if kind == SectionKind::Bss {
        0
    } else {
        record.size
    };
    let data = if file_size == 0 {
        Vec::new()
    } else {
        bytes_at(bytes, u64::from(record.offset), file_size)?.to_vec()
    };
    module.add_section(Section {
        name,
        kind,
        address: record.addr,
        align: 1_u64.checked_shl(record.align_exp).unwrap_or(0),
        flags: section_flags(record),
        data,
        size: record.size,
    })
}

fn add_segment(
    module: &mut ObjectModule,
    segment: &SegmentRecord,
    ids: &[SectionId],
) -> Result<()> {
    let name = module.intern(&segment.name)?;
    let end = segment
        .first_section
        .checked_add(segment.section_count)
        .ok_or(Error::ValueOutOfRange("segment sections"))?;
    let mut sections = Vec::new();
    let slice = ids
        .get(segment.first_section..end)
        .ok_or(Error::Malformed("segment section range"))?;
    sections.extend_from_slice(slice);
    module.add_segment(Segment {
        name,
        address: segment.addr,
        vm_size: segment.size,
        flags: segment.flags,
        sections,
    });
    Ok(())
}

fn read_parsed_relocations(
    module: &mut ObjectModule,
    bytes: &[u8],
    parsed: &Parsed,
    section_ids: &[SectionId],
    symbol_ids: &[SymbolId],
) -> Result<()> {
    read_relocations(
        module,
        bytes,
        parsed.target.arch,
        &parsed.sections,
        section_ids,
        symbol_ids,
    )
}

fn read_symbols(
    module: &mut ObjectModule,
    bytes: &[u8],
    width: Width,
    symtab: Symtab,
    section_ids: &[SectionId],
    dylibs: &[String],
) -> Result<Vec<SymbolId>> {
    let entry_size = width.nlist_size();
    check_range(
        bytes,
        u64::from(symtab.symoff),
        u64::from(symtab.nsyms) * u64::from(entry_size),
    )?;
    check_range(bytes, u64::from(symtab.stroff), u64::from(symtab.strsize))?;
    let mut ids = Vec::new();
    let symbol_bytes_len = u64::from(symtab.nsyms) * u64::from(entry_size);
    let symbol_bytes = bytes_at(bytes, u64::from(symtab.symoff), symbol_bytes_len)?;
    let mut r = ByteReader::new(symbol_bytes, Endianness::Little);
    for _ in 0..symtab.nsyms {
        let strx = r.read_u32()?;
        let n_type = r.read_u8()?;
        let sect = r.read_u8()?;
        let desc = r.read_u16()?;
        let value = read_addr(&mut r, width)?;
        let name_text = string_at(bytes, symtab.stroff, symtab.strsize, strx)?;
        let name = module.intern(&name_text)?;
        let undefined = n_type & N_TYPE == N_UNDF;
        let imported = undefined && desc >> 8 != 0;
        let section = if sect == 0 {
            None
        } else {
            section_ids.get(usize::from(sect) - 1).copied()
        };
        let flags = SymbolFlags {
            undefined,
            imported,
            exported: n_type & N_EXT != 0 && !undefined,
        };
        let binding = if n_type & N_EXT == 0 {
            SymbolBinding::Local
        } else {
            SymbolBinding::Global
        };
        let entry = SymbolEntry {
            name,
            value,
            size: 0,
            section,
            kind: SymbolKind::None,
            binding,
            flags,
        };
        let id = module.add_symbol(entry)?;
        if imported {
            let ordinal = usize::from(desc >> 8);
            let library = (ordinal != 0)
                .then(|| ordinal - 1)
                .and_then(|index| dylibs.get(index));
            library.map_or(Ok(()), |library| add_import(module, library, name))?;
        }
        if flags.exported {
            module.add_export(Export {
                name,
                address: value,
                ordinal: None,
            });
        }
        ids.push(id);
    }
    Ok(ids)
}

fn add_import(module: &mut ObjectModule, library: &str, name: Symbol) -> Result<()> {
    let library = module.intern(library)?;
    module.add_import(Import {
        library,
        name,
        ordinal: None,
        hint: None,
    });
    Ok(())
}

fn read_relocations(
    module: &mut ObjectModule,
    bytes: &[u8],
    arch: Architecture,
    records: &[SectionRecord],
    section_ids: &[SectionId],
    symbol_ids: &[SymbolId],
) -> Result<()> {
    for (index, record) in records.iter().enumerate() {
        if record.nreloc == 0 {
            continue;
        }
        let section = section_ids
            .get(index)
            .copied()
            .ok_or(Error::Malformed("relocation section"))?;
        let mut r = ByteReader::new(
            bytes_at(
                bytes,
                u64::from(record.reloff),
                u64::from(record.nreloc) * 8,
            )?,
            Endianness::Little,
        );
        for _ in 0..record.nreloc {
            let address = r.read_u32()?;
            let word = r.read_u32()?;
            let symbol_num = word & 0x00FF_FFFF;
            let pcrel = (word >> 24) & 1 != 0;
            let len = (word >> 25) & 0x3;
            let extern_bit = (word >> 27) & 1 != 0;
            let rtype = (word >> 28) & 0xF;
            if !extern_bit {
                continue;
            }
            let symbol_index = usize_from_u32(symbol_num);
            let symbol = symbol_ids
                .get(symbol_index)
                .copied()
                .ok_or(Error::Malformed("relocation references missing symbol"))?;
            let relocation = Relocation {
                section,
                offset: u64::from(address),
                symbol,
                kind: reloc_kind(arch, pcrel, len, rtype),
                addend: 0,
            };
            module.add_relocation(relocation)?;
        }
    }
    Ok(())
}

fn reloc_kind(arch: Architecture, pcrel: bool, len: u32, rtype: u32) -> RelocKind {
    if pcrel && len == 2 && (rtype == 2 || arch == Architecture::Aarch64) {
        RelocKind::Relative32
    } else if !pcrel && len == 3 && rtype == 0 {
        RelocKind::Absolute64
    } else if !pcrel && len == 2 && rtype == 0 {
        RelocKind::Absolute32
    } else if pcrel && len == 3 && rtype == 0 {
        RelocKind::Relative64
    } else if pcrel && (rtype == 4 || rtype == 5) {
        RelocKind::GotRelative
    } else {
        RelocKind::Other(rtype)
    }
}

fn section_kind(record: &SectionRecord) -> SectionKind {
    if record.flags & S_ZEROFILL == S_ZEROFILL {
        SectionKind::Bss
    } else if record.sectname == "__text" || record.flags & S_TEXT_FLAGS == S_TEXT_FLAGS {
        SectionKind::Text
    } else if record.segname == "__DATA" {
        SectionKind::Data
    } else if record.sectname == "__const" || record.sectname == "__cstring" {
        SectionKind::ReadOnlyData
    } else if record.sectname.starts_with("__debug") {
        SectionKind::Debug
    } else {
        SectionKind::Other
    }
}

fn section_flags(record: &SectionRecord) -> SectionFlags {
    match section_kind(record) {
        SectionKind::Text => SectionFlags::code(),
        SectionKind::Data | SectionKind::Bss => SectionFlags::data(),
        SectionKind::ReadOnlyData | SectionKind::Debug | SectionKind::Other => {
            SectionFlags::read_only()
        }
    }
}

fn flags_from_prot(prot: u32) -> SectionFlags {
    SectionFlags {
        read: prot & 0x1 != 0,
        write: prot & 0x2 != 0,
        execute: prot & 0x4 != 0,
    }
}

fn fixed_name(bytes: &[u8]) -> Result<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let text = core::str::from_utf8(bytes.split_at(end).0)
        .map_err(|_| Error::Malformed("invalid UTF-8 Mach-O name"))?;
    Ok(text.into())
}

fn read_command_string(
    bytes: &[u8],
    command_start: usize,
    cmdsize: u32,
    offset: u32,
) -> Result<String> {
    if offset >= cmdsize {
        return Err(Error::Malformed("load-command string offset"));
    }
    let start = command_start.saturating_add(usize_from_u32(offset));
    let end_limit = command_start.saturating_add(usize_from_u32(cmdsize));
    let slice = bytes
        .get(start..end_limit)
        .ok_or(Error::Malformed("load-command string"))?;
    let nul = slice
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated load-command string"))?;
    let text = core::str::from_utf8(slice.split_at(nul).0)
        .map_err(|_| Error::Malformed("invalid UTF-8 load-command string"))?;
    Ok(text.into())
}

fn string_at(bytes: &[u8], stroff: u32, strsize: u32, strx: u32) -> Result<String> {
    if strx >= strsize {
        return Err(Error::Malformed("string-table index out of bounds"));
    }
    let base = u64::from(stroff) + u64::from(strx);
    let remaining = strsize - strx;
    let slice = bytes_at(bytes, base, u64::from(remaining))?;
    let nul = slice
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated string-table entry"))?;
    let text = core::str::from_utf8(slice.split_at(nul).0)
        .map_err(|_| Error::Malformed("invalid UTF-8 string-table entry"))?;
    Ok(text.into())
}

fn bytes_at(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or(Error::ValueOutOfRange("range"))?;
    let start = usize_from_u64(offset);
    let end = usize_from_u64(end);
    bytes.get(start..end).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: usize_from_u64(size),
        len: bytes.len(),
    })
}

fn check_range(bytes: &[u8], offset: u64, size: u64) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or(Error::ValueOutOfRange("range"))?;
    if end > u64_from_usize(bytes.len()) {
        return Err(Error::UnexpectedEof {
            offset: usize_from_u64(offset),
            needed: usize_from_u64(size),
            len: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{LC_LOAD_DYLINKER, MAIN_COMMAND_SIZE, N_SECT, S_REGULAR};
    use alloc::{vec, vec::Vec};
    use stratum_oir::{PtrWidth, RelocKind, Symbol};

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_name(buf: &mut Vec<u8>, value: &[u8]) {
        let start = buf.len();
        buf.resize(start + 16, 0);
        let end = start + value.len();
        buf.get_mut(start..end).unwrap().copy_from_slice(value);
    }

    fn header(magic: u32, cputype: u32, ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, magic);
        push_u32(&mut buf, cputype);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 2);
        push_u32(&mut buf, ncmds);
        push_u32(&mut buf, sizeofcmds);
        push_u32(&mut buf, 0);
        if magic == MH_MAGIC_64 {
            push_u32(&mut buf, 0);
        }
        buf
    }

    fn empty_module() -> ObjectModule {
        ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86_64())
    }

    fn symbol_name(module: &mut ObjectModule, name: &str) -> Symbol {
        module.intern(name).unwrap()
    }

    #[test]
    fn empty_and_unknown_commands_parse() {
        let mut buf = header(MH_MAGIC, CPU_TYPE_I386, 1, 8);
        push_u32(&mut buf, 0x8000_1234);
        push_u32(&mut buf, 8);

        let module = read(&buf).unwrap();
        assert_eq!(module.target().arch, Architecture::X86);
        assert_eq!(module.entry(), None);
        assert_eq!(module.symbol_count(), 0);
        assert_eq!(module.relocation_count(), 0);
    }

    #[test]
    fn malformed_load_commands_are_rejected() {
        assert!(read(&header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, 0)).is_err());

        let mut past_area = header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, 8);
        push_u32(&mut past_area, LC_SYMTAB);
        push_u32(&mut past_area, 16);
        assert!(read(&past_area).is_err());

        let mut width_mismatch = header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, 56);
        push_u32(&mut width_mismatch, LC_SEGMENT);
        push_u32(&mut width_mismatch, 56);
        width_mismatch.resize(width_mismatch.len() + 48, 0);
        assert!(read(&width_mismatch).is_err());

        let mut bad_segment = header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, 72);
        push_u32(&mut bad_segment, LC_SEGMENT_64);
        push_u32(&mut bad_segment, 72);
        push_name(&mut bad_segment, b"__TEXT");
        push_u64(&mut bad_segment, 0);
        push_u64(&mut bad_segment, 0);
        push_u64(&mut bad_segment, 0);
        push_u64(&mut bad_segment, 0);
        push_u32(&mut bad_segment, 7);
        push_u32(&mut bad_segment, 5);
        push_u32(&mut bad_segment, 1);
        push_u32(&mut bad_segment, 0);
        assert!(read(&bad_segment).is_err());

        let mut bad_dylib = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, 24);
        push_u32(&mut bad_dylib, LC_LOAD_DYLIB);
        push_u32(&mut bad_dylib, 24);
        push_u32(&mut bad_dylib, 24);
        bad_dylib.resize(bad_dylib.len() + 12, 0);
        assert!(read(&bad_dylib).is_err());

        let mut dylinker_padding = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, 16);
        push_u32(&mut dylinker_padding, LC_LOAD_DYLINKER);
        push_u32(&mut dylinker_padding, 16);
        push_u32(&mut dylinker_padding, 12);
        dylinker_padding.extend_from_slice(b"/x\0");
        dylinker_padding.push(0);
        assert!(read(&dylinker_padding).is_ok());

        let mut bad_symtab = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, 24);
        push_u32(&mut bad_symtab, LC_SYMTAB);
        push_u32(&mut bad_symtab, 24);
        push_u32(&mut bad_symtab, 56);
        push_u32(&mut bad_symtab, 1);
        push_u32(&mut bad_symtab, 56);
        push_u32(&mut bad_symtab, 1);
        assert!(read(&bad_symtab).is_err());

        let mut mismatched_size = header(MH_MAGIC_64, CPU_TYPE_X86_64, 0, 8);
        mismatched_size.resize(mismatched_size.len() + 8, 0);
        assert!(read(&mismatched_size).is_err());

        let mut bad_relocs = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, 152);
        push_u32(&mut bad_relocs, LC_SEGMENT_64);
        push_u32(&mut bad_relocs, 152);
        push_name(&mut bad_relocs, b"__TEXT");
        push_u64(&mut bad_relocs, 0);
        push_u64(&mut bad_relocs, 0);
        push_u64(&mut bad_relocs, 0);
        push_u64(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 7);
        push_u32(&mut bad_relocs, 5);
        push_u32(&mut bad_relocs, 1);
        push_u32(&mut bad_relocs, 0);
        push_name(&mut bad_relocs, b"__text");
        push_name(&mut bad_relocs, b"__TEXT");
        push_u64(&mut bad_relocs, 0);
        push_u64(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 999);
        push_u32(&mut bad_relocs, 1);
        push_u32(&mut bad_relocs, S_REGULAR);
        push_u32(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 0);
        push_u32(&mut bad_relocs, 0);
        assert!(read(&bad_relocs).is_err());
    }

    #[test]
    fn target_mapping_covers_supported_and_unknown_cpus() {
        assert_eq!(
            target_for(CPU_TYPE_ARM, Width::W32).unwrap().arch,
            Architecture::Arm
        );
        assert_eq!(
            target_for(CPU_TYPE_ARM64, Width::W64).unwrap().ptr_width,
            PtrWidth::W64
        );
        assert_eq!(
            target_for(CPU_TYPE_X86_64, Width::W64).unwrap().arch,
            Architecture::X86_64
        );
        assert_eq!(
            target_for(CPU_TYPE_I386, Width::W32).unwrap().ptr_width,
            PtrWidth::W32
        );
        assert!(target_for(0xFFFF, Width::W32).is_err());

        assert_eq!(
            reloc_kind(Architecture::X86_64, true, 2, 5),
            RelocKind::GotRelative
        );
    }

    #[test]
    fn section_helpers_cover_variants() {
        let data = b"abcdefghij";
        let mut command = Vec::new();
        push_name(&mut command, b"__const");
        push_name(&mut command, b"__TEXT");
        push_u64(&mut command, 0x1000);
        push_u64(&mut command, 3);
        push_u32(&mut command, 2);
        push_u32(&mut command, 0);
        push_u32(&mut command, 0);
        push_u32(&mut command, 0);
        push_u32(&mut command, S_REGULAR);
        push_u32(&mut command, 0);
        push_u32(&mut command, 0);
        push_u32(&mut command, 0);
        let mut reader = ByteReader::new(&command, Endianness::Little);
        let record = parse_section(&mut reader, data, Width::W64).unwrap();
        assert_eq!(record.sectname, "__const");
        assert_eq!(record.offset, 2);
        assert_eq!(section_kind(&record), SectionKind::ReadOnlyData);

        let text = SectionRecord {
            sectname: "__text".into(),
            segname: "__TEXT".into(),
            addr: 0,
            size: 0,
            offset: 0,
            align_exp: 0,
            reloff: 0,
            nreloc: 0,
            flags: S_TEXT_FLAGS,
        };
        assert_eq!(section_kind(&text), SectionKind::Text);
        assert_eq!(section_flags(&text), SectionFlags::code());
        let bss = SectionRecord {
            sectname: "__bss".into(),
            segname: "__DATA".into(),
            flags: S_ZEROFILL,
            ..text.clone()
        };
        assert_eq!(section_kind(&bss), SectionKind::Bss);
        assert_eq!(section_flags(&bss), SectionFlags::data());
        let debug = SectionRecord {
            sectname: "__debug_info".into(),
            segname: "__DWARF".into(),
            flags: 0,
            ..text.clone()
        };
        assert_eq!(section_kind(&debug), SectionKind::Debug);
        let ro = SectionRecord {
            sectname: "__cstring".into(),
            segname: "__TEXT".into(),
            flags: 0,
            ..text.clone()
        };
        assert_eq!(section_kind(&ro), SectionKind::ReadOnlyData);
        assert_eq!(section_flags(&ro), SectionFlags::read_only());
        let data_record = SectionRecord {
            sectname: "__mystery".into(),
            segname: "__DATA".into(),
            flags: 0,
            ..text.clone()
        };
        assert_eq!(section_kind(&data_record), SectionKind::Data);
        let other = SectionRecord {
            sectname: "__custom".into(),
            segname: "__OTHER".into(),
            flags: 0,
            ..text.clone()
        };
        assert_eq!(section_kind(&other), SectionKind::Other);
    }

    #[test]
    fn segment_helpers_cover_variants() {
        let data = b"abcdefghij";
        let mut bad = Vec::new();
        push_name(&mut bad, b"__bad");
        push_name(&mut bad, b"__TEXT");
        push_u64(&mut bad, 0);
        push_u64(&mut bad, 8);
        push_u32(&mut bad, 0);
        push_u32(&mut bad, 0);
        push_u32(&mut bad, 999);
        push_u32(&mut bad, 1);
        push_u32(&mut bad, S_REGULAR);
        bad.resize(80, 0);
        let mut bad_reader = ByteReader::new(&bad, Endianness::Little);
        assert!(parse_section(&mut bad_reader, data, Width::W64).is_err());

        let mut segment = Vec::new();
        push_name(&mut segment, b"__TEXT");
        push_u32(&mut segment, 0x1000);
        push_u32(&mut segment, 0x20);
        push_u32(&mut segment, 0);
        push_u32(&mut segment, 0);
        push_u32(&mut segment, 7);
        push_u32(&mut segment, 5);
        push_u32(&mut segment, 0);
        push_u32(&mut segment, 0);
        let mut reader = ByteReader::new(&segment, Endianness::Little);
        let mut sections = Vec::new();
        let mut segments = Vec::new();
        let mut text_vmaddr = None;
        parse_segment(
            &mut reader,
            data,
            Width::W32,
            SEGMENT_COMMAND_32_SIZE,
            &mut sections,
            &mut segments,
            &mut text_vmaddr,
        )
        .unwrap();
        assert_eq!(text_vmaddr, Some(0x1000));
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn symbol_table_imports_exports_and_errors() {
        let mut module = empty_module();
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 1);
        bytes.push(N_EXT | N_UNDF);
        bytes.push(0);
        bytes.extend_from_slice(&(u16::try_from(1_u32 << 8).unwrap()).to_le_bytes());
        push_u64(&mut bytes, 0);
        bytes.extend_from_slice(b"\0_import\0");
        let symbol_ids = read_symbols(
            &mut module,
            &bytes,
            Width::W64,
            Symtab {
                symoff: 0,
                nsyms: 1,
                stroff: 16,
                strsize: 9,
            },
            &[],
            &["/usr/lib/libSystem.B.dylib".into()],
        )
        .unwrap();
        assert_eq!(symbol_ids.len(), 1);
        assert_eq!(module.imports().len(), 1);

        let mut exported = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86());
        let text_name = symbol_name(&mut exported, "__text");
        let text = exported
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x20,
                align: 1,
                flags: SectionFlags::code(),
                data: vec![1, 2, 3],
                size: 3,
            })
            .unwrap();
        let mut sym = Vec::new();
        push_u32(&mut sym, 0);
        sym.push(N_EXT | N_SECT);
        sym.push(1);
        sym.extend_from_slice(&0_u16.to_le_bytes());
        push_u32(&mut sym, 0x20);
        sym.extend_from_slice(b"_exp\0");
        let ids = read_symbols(
            &mut exported,
            &sym,
            Width::W32,
            Symtab {
                symoff: 0,
                nsyms: 1,
                stroff: 12,
                strsize: 5,
            },
            &[text],
            &[],
        )
        .unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(exported.exports().len(), 1);

        let mut bad = Vec::new();
        push_u32(&mut bad, 100);
        bad.resize(12, 0);
        assert!(
            read_symbols(
                &mut empty_module(),
                &bad,
                Width::W32,
                Symtab {
                    symoff: 0,
                    nsyms: 1,
                    stroff: 12,
                    strsize: 1
                },
                &[],
                &[],
            )
            .is_err()
        );
        assert!(
            read_symbols(
                &mut empty_module(),
                &[],
                Width::W32,
                Symtab {
                    symoff: 0,
                    nsyms: 1,
                    stroff: 0,
                    strsize: 0
                },
                &[],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "rich fixture exercises symbols, imports, exports, sections, and relocations together"
    )]
    fn self_emitted_rich_image_exercises_full_read_pipeline() {
        let mut module = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86_64());
        let text_name = symbol_name(&mut module, "__text");
        let data_name = symbol_name(&mut module, "__data");
        let bss_name = symbol_name(&mut module, "__bss");
        let text = module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0,
                align: 4,
                flags: SectionFlags::code(),
                data: vec![0xE8, 0, 0, 0, 0],
                size: 5,
            })
            .unwrap();
        let data = module
            .add_section(Section {
                name: data_name,
                kind: SectionKind::Data,
                address: 0,
                align: 8,
                flags: SectionFlags::data(),
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                size: 8,
            })
            .unwrap();
        module
            .add_section(Section {
                name: bss_name,
                kind: SectionKind::Bss,
                address: 0,
                align: 8,
                flags: SectionFlags::data(),
                data: Vec::new(),
                size: 16,
            })
            .unwrap();
        let start_name = symbol_name(&mut module, "_start");
        let data_symbol_name = symbol_name(&mut module, "_global_data");
        let import_name = symbol_name(&mut module, "_puts");
        let library_name = symbol_name(&mut module, "/usr/lib/libSystem.B.dylib");
        let start = module
            .add_symbol(SymbolEntry {
                name: start_name,
                value: 0,
                size: 5,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::exported(),
            })
            .unwrap();
        let data_symbol = module
            .add_symbol(SymbolEntry {
                name: data_symbol_name,
                value: 0,
                size: 8,
                section: Some(data),
                kind: SymbolKind::Object,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        module
            .add_symbol(SymbolEntry {
                name: import_name,
                value: 0,
                size: 0,
                section: None,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::imported(),
            })
            .unwrap();
        module.add_import(Import {
            library: library_name,
            name: import_name,
            ordinal: None,
            hint: None,
        });
        module
            .add_relocation(Relocation {
                section: text,
                offset: 1,
                symbol: start,
                kind: RelocKind::Relative32,
                addend: 0,
            })
            .unwrap();
        module
            .add_relocation(Relocation {
                section: data,
                offset: 0,
                symbol: data_symbol,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();

        let bytes = crate::write::write(&module).unwrap();
        let parsed = read(&bytes).unwrap();
        assert_eq!(parsed.section_count(), 3);
        assert_eq!(parsed.symbol_count(), 3);
        assert_eq!(parsed.imports().len(), 1);
        assert_eq!(parsed.exports().len(), 1);
        assert_eq!(parsed.relocation_count(), 2);
        let rewritten = crate::write::write(&parsed).unwrap();
        assert_eq!(bytes, rewritten);

        // Truncating the image at every length must be rejected gracefully (never panic),
        // which drives every short-read error path in the parser.
        for len in 0..bytes.len() {
            let _ = read(bytes.get(..len).unwrap());
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive single-test matrix over relocation kinds and external/local symbols"
    )]
    fn relocation_helpers_cover_external_local_and_kinds() {
        let mut module = empty_module();
        let section_name = symbol_name(&mut module, "__text");
        let section = module
            .add_section(Section {
                name: section_name,
                kind: SectionKind::Text,
                address: 0,
                align: 1,
                flags: SectionFlags::code(),
                data: vec![0; 8],
                size: 8,
            })
            .unwrap();
        let symbol_name = symbol_name(&mut module, "sym");
        let symbol = module
            .add_symbol(SymbolEntry {
                name: symbol_name,
                value: 0,
                size: 0,
                section: Some(section),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 2 << 28);
        let records = [SectionRecord {
            sectname: "__text".into(),
            segname: "__TEXT".into(),
            addr: 0,
            size: 8,
            offset: 0,
            align_exp: 0,
            reloff: 0,
            nreloc: 1,
            flags: S_TEXT_FLAGS,
        }];
        read_relocations(
            &mut module,
            &bytes,
            Architecture::X86_64,
            &records,
            &[section],
            &[symbol],
        )
        .unwrap();
        assert_eq!(module.relocation_count(), 0);

        let mut external = Vec::new();
        push_u32(&mut external, 4);
        push_u32(&mut external, 0x0800_0000 | (2 << 28));
        let records = [SectionRecord {
            sectname: "__text".into(),
            segname: "__TEXT".into(),
            addr: 0,
            size: 8,
            offset: 0,
            align_exp: 0,
            reloff: 0,
            nreloc: 1,
            flags: S_TEXT_FLAGS,
        }];
        read_relocations(
            &mut module,
            &external,
            Architecture::X86_64,
            &records,
            &[section],
            &[symbol],
        )
        .unwrap();
        assert_eq!(module.relocation_count(), 1);
        assert!(
            read_relocations(
                &mut module,
                &[],
                Architecture::X86_64,
                &records,
                &[section],
                &[symbol]
            )
            .is_err()
        );

        assert_eq!(
            reloc_kind(Architecture::Aarch64, true, 2, 0),
            RelocKind::Relative32
        );
        assert_eq!(
            reloc_kind(Architecture::Aarch64, false, 3, 0),
            RelocKind::Absolute64
        );
        assert_eq!(
            reloc_kind(Architecture::X86_64, true, 2, 4),
            RelocKind::GotRelative
        );
        assert_eq!(
            reloc_kind(Architecture::X86_64, true, 2, 2),
            RelocKind::Relative32
        );
        assert_eq!(
            reloc_kind(Architecture::X86, false, 2, 0),
            RelocKind::Absolute32
        );
        assert_eq!(
            reloc_kind(Architecture::X86, true, 3, 0),
            RelocKind::Relative64
        );
        assert_eq!(
            reloc_kind(Architecture::Arm, false, 2, 3),
            RelocKind::Other(3)
        );
    }

    #[test]
    fn string_and_range_helpers_reject_bad_offsets() {
        assert_eq!(string_at(b"abc\0tail", 0, 8, 0).unwrap(), "abc");
        assert!(string_at(b"abc", 0, 3, 1).is_err());
        assert!(string_at(b"abc", 0, 0, 0).is_err());
        assert!(string_at(b"abc", 4, 1, 0).is_err());
        assert!(fixed_name(&[0xff, 0]).is_err());
        assert!(check_range(b"abcd", 2, 5).is_err());
        assert!(check_range(b"abcd", u64::MAX, 1).is_err());

        let mut command = Vec::new();
        push_u32(&mut command, 20);
        command.resize(20, 0);
        assert!(read_command_string(&command, 0, 20, 20).is_err());
        let command_without_nul = vec![b'a'; 20];
        assert!(read_command_string(&command_without_nul, 0, 20, 1).is_err());
        // Command string whose range extends past the buffer is rejected.
        assert!(read_command_string(b"short", 0, 100, 4).is_err());
        // Invalid UTF-8 in a load-command string is rejected.
        assert!(read_command_string(b"\xff\0\0\0", 0, 4, 0).is_err());
        // Invalid UTF-8 in a string-table entry is rejected.
        assert!(string_at(b"\xff\0", 0, 2, 0).is_err());
        // Out-of-range and overflowing byte ranges are rejected.
        assert!(bytes_at(b"abc", 8, 1).is_err());
        assert!(bytes_at(b"abc", u64::MAX, 1).is_err());
        assert_eq!(bytes_at(b"abcd", 1, 2).unwrap(), b"bc");
    }

    #[test]
    fn pc_register_index_covers_every_arch() {
        assert_eq!(pc_register_index(Architecture::X86_64), 16);
        assert_eq!(pc_register_index(Architecture::Aarch64), 32);
        assert_eq!(pc_register_index(Architecture::X86), 10);
        assert_eq!(pc_register_index(Architecture::Arm), 15);
        assert_eq!(pc_register_index(Architecture::Riscv64), 15);
    }

    #[test]
    fn unixthread_command_sets_absolute_entry() {
        let cmdsize = 16 + 33 * 8; // header + 33 registers, PC at index 32
        let mut buf = header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, cmdsize);
        push_u32(&mut buf, LC_UNIXTHREAD);
        push_u32(&mut buf, cmdsize);
        push_u32(&mut buf, 6); // ARM_THREAD_STATE64
        push_u32(&mut buf, 68); // count
        for index in 0..33_u32 {
            push_u64(&mut buf, if index == 32 { 0x4000 } else { 0 });
        }
        let module = read(&buf).unwrap();
        assert_eq!(module.entry(), Some(0x4000));
        for len in 0..buf.len() {
            let _ = read(buf.get(..len).unwrap());
        }
    }

    #[test]
    fn short_thread_command_is_skipped_without_entry() {
        let cmdsize = 16 + 8; // not long enough to hold the program counter
        let mut buf = header(MH_MAGIC_64, CPU_TYPE_ARM64, 1, cmdsize);
        push_u32(&mut buf, LC_THREAD);
        push_u32(&mut buf, cmdsize);
        push_u32(&mut buf, 6);
        push_u32(&mut buf, 2);
        push_u64(&mut buf, 0);
        let module = read(&buf).unwrap();
        assert_eq!(module.entry(), None);
    }

    #[test]
    fn dylib_variant_commands_are_parsed() {
        for cmd in [
            LC_LOAD_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
            LC_ID_DYLIB,
        ] {
            let cmdsize = 32_u32;
            let mut buf = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, cmdsize);
            push_u32(&mut buf, cmd);
            push_u32(&mut buf, cmdsize);
            push_u32(&mut buf, 24); // name offset within the command
            buf.resize(buf.len() + 12, 0);
            buf.extend_from_slice(b"/x\0");
            buf.resize(32 + 32, 0);
            assert!(read(&buf).is_ok());
        }
    }

    #[test]
    fn section_with_out_of_range_offset_is_rejected() {
        let cmdsize = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE;
        let mut buf = header(MH_MAGIC_64, CPU_TYPE_X86_64, 1, cmdsize);
        push_u32(&mut buf, LC_SEGMENT_64);
        push_u32(&mut buf, cmdsize);
        push_name(&mut buf, b"__TEXT");
        push_u64(&mut buf, 0); // vmaddr
        push_u64(&mut buf, 8); // vmsize
        push_u64(&mut buf, 0); // fileoff
        push_u64(&mut buf, 0); // filesize
        push_u32(&mut buf, 7); // maxprot
        push_u32(&mut buf, 5); // initprot
        push_u32(&mut buf, 1); // nsects
        push_u32(&mut buf, 0); // flags
        push_name(&mut buf, b"__text");
        push_name(&mut buf, b"__TEXT");
        push_u64(&mut buf, 0); // addr
        push_u64(&mut buf, 8); // size
        push_u32(&mut buf, 0xF000_0000); // offset far past the buffer
        push_u32(&mut buf, 0); // align
        push_u32(&mut buf, 0); // reloff
        push_u32(&mut buf, 0); // nreloc
        push_u32(&mut buf, S_REGULAR); // flags
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        assert!(read(&buf).is_err());
    }

    #[test]
    fn entry_offset_overflow_is_rejected() {
        let cmdsize = SEGMENT_COMMAND_64_SIZE + MAIN_COMMAND_SIZE;
        let mut buf = header(MH_MAGIC_64, CPU_TYPE_X86_64, 2, cmdsize);
        push_u32(&mut buf, LC_SEGMENT_64);
        push_u32(&mut buf, SEGMENT_COMMAND_64_SIZE);
        push_name(&mut buf, b"__TEXT");
        push_u64(&mut buf, u64::MAX); // vmaddr
        push_u64(&mut buf, 0);
        push_u64(&mut buf, 0);
        push_u64(&mut buf, 0);
        push_u32(&mut buf, 5);
        push_u32(&mut buf, 5);
        push_u32(&mut buf, 0); // nsects
        push_u32(&mut buf, 0);
        push_u32(&mut buf, LC_MAIN);
        push_u32(&mut buf, MAIN_COMMAND_SIZE);
        push_u64(&mut buf, u64::MAX); // entryoff
        push_u64(&mut buf, 0);
        assert!(read(&buf).is_err());
    }

    #[test]
    fn canonical_sample_truncations_are_rejected() {
        let images = [
            crate::write::write(&crate::samples::hello_world_aarch64_macos().unwrap()).unwrap(),
            crate::write::write(&crate::samples::hello_world_x86_64_macos().unwrap()).unwrap(),
            crate::write::write(&crate::samples::empty_i386_macos().unwrap()).unwrap(),
            crate::write::write(&crate::samples::empty_arm_macos().unwrap()).unwrap(),
        ];
        for image in &images {
            assert!(read(image).is_ok());
            for len in 0..image.len() {
                let _ = read(image.get(..len).unwrap());
            }
        }
    }
}
