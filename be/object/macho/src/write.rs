//! Serializes an [`ObjectModule`] into a canonical Mach-O image.
//!
//! The executable form uses the system dynamic linker (`LC_LOAD_DYLINKER` + `LC_MAIN`) and an
//! ad-hoc code signature, so self-emitted arm64 binaries are accepted by macOS. The writer also
//! emits symbol, string, dynamic-symbol, empty dyld-info, dylib, and relocation tables.

use crate::codesign;
use crate::consts::{
    ARM64_PAGE_SIZE, BUILD_VERSION_COMMAND_SIZE, CODE_SIGNATURE_COMMAND_SIZE, CPU_SUBTYPE_ARM_ALL,
    CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_I386_ALL, CPU_SUBTYPE_X86_64_ALL, CPU_TYPE_ARM,
    CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64, DYLD_INFO_COMMAND_SIZE, DYLD_PATH,
    DYLIB_COMMAND_HEADER_SIZE, DYLINKER_COMMAND_SIZE, DYSYMTAB_COMMAND_SIZE, LC_BUILD_VERSION,
    LC_CODE_SIGNATURE, LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_MAIN,
    LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LIBSYSTEM_PATH, MACH_HEADER_32_SIZE, MACH_HEADER_64_SIZE,
    MAIN_COMMAND_SIZE, MH_EXECUTE, MH_FLAGS, MH_MAGIC, MH_MAGIC_64, MIN_MACOS_VERSION, N_EXT,
    N_SECT, N_UNDF, N_WEAK_DEF, NLIST_32_SIZE, NLIST_64_SIZE, PAGEZERO_32_SIZE, PAGEZERO_SIZE,
    PLATFORM_MACOS, REFERENCE_FLAG_UNDEFINED_NON_LAZY, RELOCATION_INFO_SIZE, S_REGULAR,
    S_TEXT_FLAGS, S_ZEROFILL, SECTION_32_SIZE, SECTION_64_SIZE, SEGMENT_COMMAND_32_SIZE,
    SEGMENT_COMMAND_64_SIZE, SYMTAB_COMMAND_SIZE, TEXT_32_VMADDR, TEXT_VMADDR, VM_PROT_EXECUTE,
    VM_PROT_READ, VM_PROT_WRITE, X86_PAGE_SIZE,
};
use stratum_oir::{
    Architecture, ByteWriter, Endianness, Error, ObjectModule, PtrWidth, RelocKind, Result,
    Section, SectionId, SectionKind, SymbolBinding, SymbolEntry,
};

use crate::convert::{
    u16_from_usize, u32_from_u64, u32_from_usize, u8_from_u32, usize_from_u32, usize_from_u64,
};

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// Fixed ad-hoc signing identifier used for every image Stratum produces.
pub const SIGNING_IDENTIFIER: &str = "stratum";

const MAX_SECTION_ORDINAL: u32 = 255;
const DEFAULT_ALIGN: u64 = 4;

/// Header and load-command size for the default arm64 hello-world sample.
pub const CODE_OFFSET: u32 = MACH_HEADER_64_SIZE
    + 3 * SEGMENT_COMMAND_64_SIZE
    + SECTION_64_SIZE
    + DYLINKER_COMMAND_SIZE
    + BUILD_VERSION_COMMAND_SIZE
    + MAIN_COMMAND_SIZE
    + DYLD_INFO_COMMAND_SIZE
    + SYMTAB_COMMAND_SIZE
    + DYSYMTAB_COMMAND_SIZE
    + CODE_SIGNATURE_COMMAND_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    W32,
    W64,
}

impl Width {
    const fn is_64(self) -> bool {
        matches!(self, Self::W64)
    }

    const fn header_size(self) -> u32 {
        match self {
            Self::W32 => MACH_HEADER_32_SIZE,
            Self::W64 => MACH_HEADER_64_SIZE,
        }
    }

    const fn segment_command_size(self) -> u32 {
        match self {
            Self::W32 => SEGMENT_COMMAND_32_SIZE,
            Self::W64 => SEGMENT_COMMAND_64_SIZE,
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentKind {
    PageZero,
    Text,
    Data,
    LinkEdit,
}

#[derive(Debug, Clone, Copy)]
struct SectionLayout {
    id: SectionId,
    segment: SegmentKind,
    addr: u64,
    offset: u64,
    vm_size: u64,
    reloc_offset: u32,
    reloc_count: u32,
}

#[derive(Debug, Clone, Copy)]
struct SegmentLayout {
    kind: SegmentKind,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    nsects: u32,
}

#[derive(Debug, Clone)]
struct SymbolLayout {
    name_offset: u32,
    section_ordinal: u8,
    ty: u8,
    desc: u16,
    value: u64,
}

#[derive(Debug, Clone)]
struct LinkEditLayout {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    relocation_start: u32,
    signature_offset: u32,
    signature_size: u32,
}

#[derive(Debug, Clone)]
struct Layout {
    width: Width,
    cputype: u32,
    cpusubtype: u32,
    text_vmaddr: u64,
    sizeofcmds: u32,
    ncmds: u32,
    sections: Vec<SectionLayout>,
    segments: Vec<SegmentLayout>,
    dylibs: Vec<String>,
    symbols: Vec<SymbolLayout>,
    string_table: Vec<u8>,
    linkedit: LinkEditLayout,
}

const fn align_up(value: u64, align: u64) -> u64 {
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn fixed16(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (slot, byte) in out.iter_mut().zip(name.as_bytes()) {
        *slot = *byte;
    }
    out
}

fn padded_command_len(header: u32, text: &str) -> u32 {
    let raw = header
        .saturating_add(u32_from_usize(text.len()))
        .saturating_add(1);
    u32_from_u64(align_up(u64::from(raw), 8))
}

fn arch_info(module: &ObjectModule) -> Result<(Width, u32, u32, u64, u64, u64)> {
    match (module.target().arch, module.target().ptr_width) {
        (Architecture::Aarch64, PtrWidth::W64) => Ok((
            Width::W64,
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64_ALL,
            ARM64_PAGE_SIZE,
            PAGEZERO_SIZE,
            TEXT_VMADDR,
        )),
        (Architecture::X86_64, PtrWidth::W64) => Ok((
            Width::W64,
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            X86_PAGE_SIZE,
            PAGEZERO_SIZE,
            TEXT_VMADDR,
        )),
        (Architecture::X86, PtrWidth::W32) => Ok((
            Width::W32,
            CPU_TYPE_I386,
            CPU_SUBTYPE_I386_ALL,
            X86_PAGE_SIZE,
            PAGEZERO_32_SIZE,
            TEXT_32_VMADDR,
        )),
        (Architecture::Arm, PtrWidth::W32) => Ok((
            Width::W32,
            CPU_TYPE_ARM,
            CPU_SUBTYPE_ARM_ALL,
            X86_PAGE_SIZE,
            PAGEZERO_32_SIZE,
            TEXT_32_VMADDR,
        )),
        _ => Err(Error::Unsupported(
            "Mach-O writer supports x86, x86_64, arm, and arm64",
        )),
    }
}

fn segment_for(section: &Section) -> SegmentKind {
    match section.kind {
        SectionKind::Text | SectionKind::ReadOnlyData | SectionKind::Debug | SectionKind::Other => {
            SegmentKind::Text
        }
        SectionKind::Data | SectionKind::Bss => SegmentKind::Data,
    }
}

fn section_name(section: &Section, module: &ObjectModule) -> Result<String> {
    Ok(module.resolve(section.name)?.into())
}

fn segment_name(kind: SegmentKind) -> &'static str {
    match kind {
        SegmentKind::PageZero => "__PAGEZERO",
        SegmentKind::Text => "__TEXT",
        SegmentKind::Data => "__DATA",
        SegmentKind::LinkEdit => "__LINKEDIT",
    }
}

fn section_flags(section: &Section) -> u32 {
    if section.kind == SectionKind::Text {
        S_REGULAR | S_TEXT_FLAGS
    } else if section.kind == SectionKind::Bss {
        S_ZEROFILL
    } else {
        S_REGULAR
    }
}

fn push_unique_dylib(dylibs: &mut Vec<String>, name: &str) {
    if dylibs.iter().any(|existing| existing == name) {
        return;
    }
    dylibs.push(name.into());
}

fn dylibs(module: &ObjectModule) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for import in module.imports() {
        let lib = module.resolve(import.library)?;
        push_unique_dylib(&mut out, lib);
    }
    if !out.is_empty() && !out.iter().any(|lib| lib == LIBSYSTEM_PATH) {
        push_unique_dylib(&mut out, LIBSYSTEM_PATH);
    }
    Ok(out)
}

fn symbol_string_offset(strings: &mut Vec<u8>, name: &str) -> u32 {
    let offset = u32_from_usize(strings.len());
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    offset
}

fn section_ordinal(sections: &[SectionLayout], id: Option<SectionId>) -> Result<u8> {
    let Some(id) = id else {
        return Ok(0);
    };
    for (index, layout) in sections.iter().enumerate() {
        if layout.id.raw() == id.raw() {
            let raw = u32_from_usize(index.saturating_add(1));
            if raw > MAX_SECTION_ORDINAL {
                return Err(Error::ValueOutOfRange("section ordinal"));
            }
            return Ok(u8_from_u32(raw));
        }
    }
    Err(Error::Malformed("symbol references missing section"))
}

fn symbol_desc(module: &ObjectModule, sym: &SymbolEntry, dylibs: &[String]) -> Result<u16> {
    let mut desc = if sym.binding == SymbolBinding::Weak {
        N_WEAK_DEF
    } else {
        0
    };
    if sym.flags.undefined || sym.flags.imported {
        desc |= REFERENCE_FLAG_UNDEFINED_NON_LAZY;
        for import in module.imports() {
            if import.name != sym.name {
                continue;
            }
            let lib = module.resolve(import.library)?;
            let Some(index) = dylibs.iter().position(|candidate| candidate == lib) else {
                continue;
            };
            let ordinal = u16_from_usize(index.saturating_add(1));
            desc |= ordinal << 8;
        }
    }
    Ok(desc)
}

fn symbol_layouts(
    module: &ObjectModule,
    sections: &[SectionLayout],
    dylibs: &[String],
) -> Result<(Vec<SymbolLayout>, Vec<u8>)> {
    let mut strings = Vec::new();
    strings.push(0);
    let mut layouts = Vec::new();
    for (_, sym) in module.symbols() {
        let name = module.resolve(sym.name)?;
        let name_offset = symbol_string_offset(&mut strings, name);
        let undefined = sym.flags.undefined || sym.flags.imported || sym.section.is_none();
        let mut ty = if undefined { N_UNDF } else { N_SECT };
        if sym.binding != SymbolBinding::Local || sym.flags.exported || sym.flags.imported {
            ty |= N_EXT;
        }
        layouts.push(SymbolLayout {
            name_offset,
            section_ordinal: section_ordinal(sections, sym.section)?,
            ty,
            desc: symbol_desc(module, sym, dylibs)?,
            value: if undefined { 0 } else { sym.value },
        });
    }
    if strings.len() == 1 {
        strings.push(0);
    }
    Ok((layouts, strings))
}

fn command_sizes(
    width: Width,
    section_count: u32,
    has_data_segment: bool,
    dylibs: &[String],
) -> (u32, u32) {
    let segment_count = if has_data_segment { 4_u32 } else { 3_u32 };
    let mut ncmds = segment_count;
    let mut sizeofcmds = segment_count
        .saturating_mul(width.segment_command_size())
        .saturating_add(section_count.saturating_mul(width.section_size()));

    ncmds = ncmds.saturating_add(7);
    sizeofcmds = sizeofcmds
        .saturating_add(DYLINKER_COMMAND_SIZE)
        .saturating_add(BUILD_VERSION_COMMAND_SIZE)
        .saturating_add(MAIN_COMMAND_SIZE)
        .saturating_add(DYLD_INFO_COMMAND_SIZE)
        .saturating_add(SYMTAB_COMMAND_SIZE)
        .saturating_add(DYSYMTAB_COMMAND_SIZE)
        .saturating_add(CODE_SIGNATURE_COMMAND_SIZE);

    for dylib in dylibs {
        ncmds = ncmds.saturating_add(1);
        sizeofcmds =
            sizeofcmds.saturating_add(padded_command_len(DYLIB_COMMAND_HEADER_SIZE, dylib));
    }
    (ncmds, sizeofcmds)
}

fn section_align(section: &Section) -> u64 {
    if section.align <= 1 {
        DEFAULT_ALIGN
    } else {
        section.align
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "layout construction must keep related offsets consistent"
)]
fn build_layout(module: &ObjectModule) -> Result<Layout> {
    let (width, cputype, cpusubtype, page_size, pagezero_size, text_vmaddr) = arch_info(module)?;
    let dylibs = dylibs(module)?;
    let section_count = u32_from_usize(module.section_count());
    let has_data_segment = module
        .sections()
        .any(|(_, section)| segment_for(section) == SegmentKind::Data);
    let (ncmds, sizeofcmds) = command_sizes(width, section_count, has_data_segment, &dylibs);
    let mut cursor = u64::from(width.header_size()) + u64::from(sizeofcmds);
    if cursor > page_size {
        return Err(Error::Unsupported("Mach-O load commands exceed first page"));
    }

    let mut sections = Vec::new();
    let mut text_end = cursor;
    for (id, section) in module.sections() {
        if segment_for(section) == SegmentKind::Text {
            cursor = align_up(cursor, section_align(section));
            let file_size = section.file_size();
            let vm_size = section.vm_size();
            sections.push(SectionLayout {
                id,
                segment: SegmentKind::Text,
                addr: text_vmaddr + cursor,
                offset: cursor,
                vm_size,
                reloc_offset: 0,
                reloc_count: 0,
            });
            cursor = cursor
                .checked_add(file_size)
                .ok_or(Error::ValueOutOfRange("text file size"))?;
            text_end = cursor;
        }
    }
    let text_filesize = align_up(text_end, page_size);
    let mut data_cursor = text_filesize;
    let data_vmaddr = text_vmaddr + text_filesize;
    for (id, section) in module.sections() {
        if segment_for(section) == SegmentKind::Data {
            data_cursor = align_up(data_cursor, section_align(section));
            let file_size = section.file_size();
            let vm_size = section.vm_size();
            sections.push(SectionLayout {
                id,
                segment: SegmentKind::Data,
                addr: data_vmaddr + data_cursor - text_filesize,
                offset: if section.kind == SectionKind::Bss {
                    0
                } else {
                    data_cursor
                },
                vm_size,
                reloc_offset: 0,
                reloc_count: 0,
            });
            data_cursor = data_cursor
                .checked_add(file_size)
                .ok_or(Error::ValueOutOfRange("data file size"))?;
        }
    }
    let data_filesize = data_cursor.saturating_sub(text_filesize);
    let data_vmsize = align_up(
        sections
            .iter()
            .filter(|layout| layout.segment == SegmentKind::Data)
            .map(|layout| (layout.addr - data_vmaddr) + layout.vm_size)
            .max()
            .unwrap_or(0),
        page_size,
    );
    let linkedit_fileoff = align_up(data_cursor, page_size);
    let linkedit_vmaddr = data_vmaddr + align_up(data_filesize.max(data_vmsize), page_size);

    let (symbols, string_table) = symbol_layouts(module, &sections, &dylibs)?;
    let symoff = u32_from_u64(linkedit_fileoff);
    let nsyms = u32_from_usize(symbols.len());
    let sym_bytes = u64::from(nsyms) * u64::from(width.nlist_size());
    let stroff64 = linkedit_fileoff.saturating_add(sym_bytes);
    let stroff = u32_from_u64(stroff64);
    let strsize = u32_from_usize(string_table.len());
    let relocation_start64 = stroff64.saturating_add(u64::from(strsize));
    let relocation_start = u32_from_u64(relocation_start64);
    let mut reloc_cursor = relocation_start;
    for layout in &mut sections {
        let mut count = 0_u32;
        for (_, reloc) in module.relocations() {
            if reloc.section.raw() == layout.id.raw() {
                count = count.saturating_add(1);
            }
        }
        layout.reloc_count = count;
        layout.reloc_offset = if count == 0 { 0 } else { reloc_cursor };
        reloc_cursor = reloc_cursor.saturating_add(count.saturating_mul(RELOCATION_INFO_SIZE));
    }
    let sig_offset64 = align_up(u64::from(reloc_cursor), 16);
    let signature_offset = u32_from_u64(sig_offset64);
    let sig_size = codesign::signature_size(SIGNING_IDENTIFIER, sig_offset64);
    let linkedit_filesize = sig_offset64
        .saturating_sub(linkedit_fileoff)
        .saturating_add(u64::from(sig_size));
    let linkedit_vmsize = align_up(linkedit_filesize, page_size);

    let mut segments = Vec::new();
    segments.push(SegmentLayout {
        kind: SegmentKind::PageZero,
        vmaddr: 0,
        vmsize: pagezero_size,
        fileoff: 0,
        filesize: 0,
        maxprot: 0,
        initprot: 0,
        nsects: 0,
    });
    segments.push(SegmentLayout {
        kind: SegmentKind::Text,
        vmaddr: text_vmaddr,
        vmsize: text_filesize,
        fileoff: 0,
        filesize: text_filesize,
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        nsects: u32_from_usize(
            sections
                .iter()
                .filter(|layout| layout.segment == SegmentKind::Text)
                .count(),
        ),
    });
    if data_filesize != 0 || data_vmsize != 0 {
        segments.push(SegmentLayout {
            kind: SegmentKind::Data,
            vmaddr: data_vmaddr,
            vmsize: data_vmsize.max(page_size),
            fileoff: text_filesize,
            filesize: data_filesize,
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            nsects: u32_from_usize(
                sections
                    .iter()
                    .filter(|layout| layout.segment == SegmentKind::Data)
                    .count(),
            ),
        });
    }
    segments.push(SegmentLayout {
        kind: SegmentKind::LinkEdit,
        vmaddr: linkedit_vmaddr,
        vmsize: linkedit_vmsize,
        fileoff: linkedit_fileoff,
        filesize: linkedit_filesize,
        maxprot: VM_PROT_READ,
        initprot: VM_PROT_READ,
        nsects: 0,
    });

    Ok(Layout {
        width,
        cputype,
        cpusubtype,
        text_vmaddr,
        sizeofcmds,
        ncmds,
        sections,
        segments,
        dylibs,
        symbols,
        string_table,
        linkedit: LinkEditLayout {
            symoff,
            nsyms,
            stroff,
            strsize,
            relocation_start,
            signature_offset,
            signature_size: sig_size,
        },
    })
}

/// Serializes `module` to a canonical Mach-O executable.
///
/// # Errors
///
/// Returns an error if the target is unsupported, fields overflow their Mach-O widths, or
/// ad-hoc signing fails.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    if module.target().endian != Endianness::Little {
        return Err(Error::Unsupported(
            "Mach-O writer supports little-endian targets",
        ));
    }
    let layout = build_layout(module)?;
    let mut image = build_image(module, &layout)?;
    append_signature(&mut image, &layout)?;
    Ok(image)
}

fn append_signature(image: &mut Vec<u8>, layout: &Layout) -> Result<()> {
    let signature_offset = usize_from_u32(layout.linkedit.signature_offset);
    if image.len() != signature_offset {
        return Err(Error::Malformed("Mach-O signature offset mismatch"));
    }
    let text_filesize = text_segment_filesize(layout)?;
    let signature_offset = u64::from(layout.linkedit.signature_offset);
    let signature = codesign::build(image, SIGNING_IDENTIFIER, signature_offset, text_filesize)?;
    image.extend_from_slice(&signature);
    Ok(())
}

fn text_segment_filesize(layout: &Layout) -> Result<u64> {
    layout
        .segments
        .iter()
        .find_map(|segment| (segment.kind == SegmentKind::Text).then_some(segment.filesize))
        .ok_or(Error::Malformed("missing text segment"))
}

fn build_image(module: &ObjectModule, layout: &Layout) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new(Endianness::Little);
    write_header(&mut w, layout);
    for segment in &layout.segments {
        write_segment(&mut w, module, layout, segment)?;
    }
    write_load_dylinker(&mut w);
    for dylib in &layout.dylibs {
        write_load_dylib(&mut w, dylib);
    }
    write_build_version(&mut w);
    write_main(&mut w, module, layout)?;
    write_dyld_info(&mut w);
    write_symtab(&mut w, layout);
    write_dysymtab(&mut w, layout);
    write_code_signature(&mut w, layout);

    let header_end =
        usize_from_u64(u64::from(layout.width.header_size()) + u64::from(layout.sizeofcmds));
    if w.position() != header_end {
        return Err(Error::Malformed("Mach-O header size mismatch"));
    }

    write_section_data(&mut w, module, layout)?;
    pad_to(&mut w, u64::from(layout.linkedit.symoff))?;
    write_symbols(&mut w, layout);
    w.write_bytes(&layout.string_table);
    pad_to(&mut w, u64::from(layout.linkedit.relocation_start))?;
    write_relocations(&mut w, module, layout)?;
    pad_to(&mut w, u64::from(layout.linkedit.signature_offset))?;
    w.finish()
}

fn write_header(w: &mut ByteWriter, layout: &Layout) {
    w.write_u32(if layout.width.is_64() {
        MH_MAGIC_64
    } else {
        MH_MAGIC
    });
    w.write_u32(layout.cputype);
    w.write_u32(layout.cpusubtype);
    w.write_u32(MH_EXECUTE);
    w.write_u32(layout.ncmds);
    w.write_u32(layout.sizeofcmds);
    w.write_u32(MH_FLAGS);
    if layout.width.is_64() {
        w.write_u32(0);
    }
}

fn write_segment(
    w: &mut ByteWriter,
    module: &ObjectModule,
    layout: &Layout,
    segment: &SegmentLayout,
) -> Result<()> {
    let nsects = segment.nsects;
    let cmdsize = layout
        .width
        .segment_command_size()
        .saturating_add(nsects.saturating_mul(layout.width.section_size()));
    w.write_u32(if layout.width.is_64() {
        LC_SEGMENT_64
    } else {
        LC_SEGMENT
    });
    w.write_u32(cmdsize);
    w.write_bytes(&fixed16(segment_name(segment.kind)));
    write_addr(w, layout.width, segment.vmaddr);
    write_addr(w, layout.width, segment.vmsize);
    write_addr(w, layout.width, segment.fileoff);
    write_addr(w, layout.width, segment.filesize);
    w.write_u32(segment.maxprot);
    w.write_u32(segment.initprot);
    w.write_u32(nsects);
    w.write_u32(0);
    for section_layout in layout
        .sections
        .iter()
        .filter(|item| item.segment == segment.kind)
    {
        write_section(w, module, layout, section_layout)?;
    }
    Ok(())
}

fn write_addr(w: &mut ByteWriter, width: Width, value: u64) {
    match width {
        Width::W32 => w.write_u32(u32_from_u64(value)),
        Width::W64 => w.write_u64(value),
    }
}

fn write_section(
    w: &mut ByteWriter,
    module: &ObjectModule,
    layout: &Layout,
    section_layout: &SectionLayout,
) -> Result<()> {
    let section = module.section(section_layout.id);
    w.write_bytes(&fixed16(&section_name(section, module)?));
    w.write_bytes(&fixed16(segment_name(section_layout.segment)));
    write_addr(w, layout.width, section_layout.addr);
    write_addr(w, layout.width, section_layout.vm_size);
    w.write_u32(u32_from_u64(section_layout.offset));
    w.write_u32(align_exp(section.align)?);
    w.write_u32(section_layout.reloc_offset);
    w.write_u32(section_layout.reloc_count);
    w.write_u32(section_flags(section));
    w.write_u32(0);
    w.write_u32(0);
    let _ = layout.width.is_64().then(|| w.write_u32(0));
    Ok(())
}

fn align_exp(align: u64) -> Result<u32> {
    if align <= 1 {
        return Ok(0);
    }
    if !align.is_power_of_two() {
        return Err(Error::Malformed("section alignment is not a power of two"));
    }
    Ok(align.trailing_zeros())
}

fn write_load_dylinker(w: &mut ByteWriter) {
    w.write_u32(LC_LOAD_DYLINKER);
    w.write_u32(DYLINKER_COMMAND_SIZE);
    w.write_u32(12);
    let bytes = DYLD_PATH.as_bytes();
    w.write_bytes(bytes);
    w.write_u8(0);
    let written = 13 + bytes.len();
    let target = usize_from_u32(DYLINKER_COMMAND_SIZE);
    w.write_zeros(target.saturating_sub(written));
}

fn write_load_dylib(w: &mut ByteWriter, path: &str) {
    let cmdsize = padded_command_len(DYLIB_COMMAND_HEADER_SIZE, path);
    w.write_u32(LC_LOAD_DYLIB);
    w.write_u32(cmdsize);
    w.write_u32(DYLIB_COMMAND_HEADER_SIZE);
    w.write_u32(0);
    w.write_u32(MIN_MACOS_VERSION);
    w.write_u32(MIN_MACOS_VERSION);
    w.write_bytes(path.as_bytes());
    w.write_u8(0);
    let written = usize_from_u32(DYLIB_COMMAND_HEADER_SIZE)
        .saturating_add(path.len())
        .saturating_add(1);
    let target = usize_from_u32(cmdsize);
    w.write_zeros(target.saturating_sub(written));
}

fn write_build_version(w: &mut ByteWriter) {
    w.write_u32(LC_BUILD_VERSION);
    w.write_u32(BUILD_VERSION_COMMAND_SIZE);
    w.write_u32(PLATFORM_MACOS);
    w.write_u32(MIN_MACOS_VERSION);
    w.write_u32(MIN_MACOS_VERSION);
    w.write_u32(0);
}

fn write_main(w: &mut ByteWriter, module: &ObjectModule, layout: &Layout) -> Result<()> {
    let entry = module.entry().unwrap_or(
        layout.text_vmaddr + u64::from(layout.width.header_size()) + u64::from(layout.sizeofcmds),
    );
    let entryoff = entry
        .checked_sub(layout.text_vmaddr)
        .ok_or(Error::ValueOutOfRange("entry offset"))?;
    w.write_u32(LC_MAIN);
    w.write_u32(MAIN_COMMAND_SIZE);
    w.write_u64(entryoff);
    w.write_u64(0);
    Ok(())
}

fn write_dyld_info(w: &mut ByteWriter) {
    w.write_u32(LC_DYLD_INFO_ONLY);
    w.write_u32(DYLD_INFO_COMMAND_SIZE);
    for _ in 0..10 {
        w.write_u32(0);
    }
}

fn write_symtab(w: &mut ByteWriter, layout: &Layout) {
    w.write_u32(LC_SYMTAB);
    w.write_u32(SYMTAB_COMMAND_SIZE);
    w.write_u32(layout.linkedit.symoff);
    w.write_u32(layout.linkedit.nsyms);
    w.write_u32(layout.linkedit.stroff);
    w.write_u32(layout.linkedit.strsize);
}

fn write_dysymtab(w: &mut ByteWriter, layout: &Layout) {
    let local_count = layout
        .symbols
        .iter()
        .filter(|sym| sym.ty & N_EXT == 0)
        .count();
    let ext_count = layout
        .symbols
        .iter()
        .filter(|sym| sym.ty & N_EXT != 0 && sym.ty & crate::consts::N_TYPE == N_SECT)
        .count();
    let undef_count = layout
        .symbols
        .iter()
        .filter(|sym| sym.ty & crate::consts::N_TYPE == N_UNDF)
        .count();
    w.write_u32(LC_DYSYMTAB);
    w.write_u32(DYSYMTAB_COMMAND_SIZE);
    w.write_u32(0);
    w.write_u32(u32_from_usize(local_count));
    w.write_u32(u32_from_usize(local_count));
    w.write_u32(u32_from_usize(ext_count));
    w.write_u32(u32_from_usize(local_count.saturating_add(ext_count)));
    w.write_u32(u32_from_usize(undef_count));
    for _ in 0..12 {
        w.write_u32(0);
    }
}

fn write_code_signature(w: &mut ByteWriter, layout: &Layout) {
    w.write_u32(LC_CODE_SIGNATURE);
    w.write_u32(CODE_SIGNATURE_COMMAND_SIZE);
    w.write_u32(layout.linkedit.signature_offset);
    w.write_u32(layout.linkedit.signature_size);
}

fn write_section_data(w: &mut ByteWriter, module: &ObjectModule, layout: &Layout) -> Result<()> {
    for section_layout in &layout.sections {
        let section = module.section(section_layout.id);
        if section.kind != SectionKind::Bss {
            pad_to(w, section_layout.offset)?;
            w.write_bytes(&section.data);
        }
    }
    Ok(())
}

fn pad_to(w: &mut ByteWriter, offset: u64) -> Result<()> {
    let target = usize_from_u64(offset);
    if w.position() > target {
        return Err(Error::Malformed("file layout overlap"));
    }
    w.write_zeros(target - w.position());
    Ok(())
}

fn write_symbols(w: &mut ByteWriter, layout: &Layout) {
    for sym in &layout.symbols {
        w.write_u32(sym.name_offset);
        w.write_u8(sym.ty);
        w.write_u8(sym.section_ordinal);
        w.write_u16(sym.desc);
        write_addr(w, layout.width, sym.value);
    }
}

fn write_relocations(w: &mut ByteWriter, module: &ObjectModule, layout: &Layout) -> Result<()> {
    for section_layout in &layout.sections {
        for (_, reloc) in module.relocations() {
            if reloc.section.raw() == section_layout.id.raw() {
                let address = u32::try_from(reloc.offset)
                    .map_err(|_| Error::ValueOutOfRange("relocation offset"))?;
                w.write_u32(address);
                let symbol_num = reloc.symbol.raw();
                if symbol_num > 0x00FF_FFFF {
                    return Err(Error::ValueOutOfRange("relocation symbol"));
                }
                let (pcrel, len, rtype) = reloc_encoding(reloc.kind, layout.cputype);
                let word =
                    symbol_num | (u32::from(pcrel) << 24) | (len << 25) | (1 << 27) | (rtype << 28);
                w.write_u32(word);
            }
        }
    }
    Ok(())
}

fn reloc_encoding(kind: RelocKind, cputype: u32) -> (bool, u32, u32) {
    match kind {
        RelocKind::Absolute64 => (false, 3, 0),
        RelocKind::Absolute32 => (false, 2, 0),
        RelocKind::Relative32 | RelocKind::PltRelative => {
            (true, 2, if cputype == CPU_TYPE_X86_64 { 2 } else { 0 })
        }
        RelocKind::Relative64 => (true, 3, 0),
        RelocKind::GotRelative => (true, 2, if cputype == CPU_TYPE_X86_64 { 4 } else { 5 }),
        RelocKind::Other(raw) => (false, 2, raw & 0xF),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use stratum_oir::{
        BinaryFormat, Import, Relocation, SectionFlags, Symbol, SymbolFlags, SymbolId, SymbolKind,
        TargetSpec,
    };

    fn module_for(target: TargetSpec) -> ObjectModule {
        ObjectModule::new(BinaryFormat::MachO, target)
    }

    fn intern(module: &mut ObjectModule, name: &str) -> Symbol {
        module.intern(name).unwrap()
    }

    fn text_section(module: &mut ObjectModule, align: u64) -> SectionId {
        let name = intern(module, "__text");
        module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: 0,
                align,
                flags: SectionFlags::code(),
                data: vec![0xC3],
                size: 1,
            })
            .unwrap()
    }

    fn minimal_layout(id: SectionId) -> Layout {
        Layout {
            width: Width::W64,
            cputype: CPU_TYPE_X86_64,
            cpusubtype: CPU_SUBTYPE_X86_64_ALL,
            text_vmaddr: TEXT_VMADDR,
            sizeofcmds: 0,
            ncmds: 0,
            sections: vec![SectionLayout {
                id,
                segment: SegmentKind::Text,
                addr: TEXT_VMADDR,
                offset: 0,
                vm_size: 1,
                reloc_offset: 0,
                reloc_count: 1,
            }],
            segments: vec![SegmentLayout {
                kind: SegmentKind::Text,
                vmaddr: TEXT_VMADDR,
                vmsize: 1,
                fileoff: 0,
                filesize: 1,
                maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
                initprot: VM_PROT_READ | VM_PROT_EXECUTE,
                nsects: 1,
            }],
            dylibs: Vec::new(),
            symbols: Vec::new(),
            string_table: vec![0],
            linkedit: LinkEditLayout {
                symoff: 0,
                nsyms: 0,
                stroff: 0,
                strsize: 1,
                relocation_start: 0,
                signature_offset: 0,
                signature_size: 0,
            },
        }
    }

    #[test]
    fn rejects_unsupported_arch_and_endian_targets() {
        assert!(write(&module_for(TargetSpec::riscv64())).is_err());
        assert!(write(&module_for(TargetSpec::aarch64_be())).is_err());

        let x86 = arch_info(&module_for(TargetSpec::x86())).unwrap();
        assert_eq!(x86.0, Width::W32);
        assert_eq!(x86.1, CPU_TYPE_I386);
        let arm = arch_info(&module_for(TargetSpec::arm())).unwrap();
        assert_eq!(arm.0, Width::W32);
        assert_eq!(arm.1, CPU_TYPE_ARM);
        assert_eq!(Width::W32.header_size(), MACH_HEADER_32_SIZE);
        assert_eq!(Width::W32.segment_command_size(), SEGMENT_COMMAND_32_SIZE);
        assert_eq!(Width::W32.section_size(), SECTION_32_SIZE);
        assert_eq!(Width::W32.nlist_size(), NLIST_32_SIZE);
        assert_eq!(reloc_encoding(RelocKind::GotRelative, CPU_TYPE_ARM).2, 5);
    }

    #[test]
    fn dylibs_and_symbol_desc_cover_import_paths() {
        let mut module = module_for(TargetSpec::x86_64());
        let lib = intern(&mut module, "/custom/libthing.dylib");
        let name = intern(&mut module, "_thing");
        module.add_import(Import {
            library: lib,
            name,
            ordinal: None,
            hint: None,
        });
        let libs = dylibs(&module).unwrap();
        assert!(libs.iter().any(|item| item == "/custom/libthing.dylib"));
        assert!(libs.iter().any(|item| item == LIBSYSTEM_PATH));
        let mut unique = libs.clone();
        let before = unique.len();
        push_unique_dylib(&mut unique, LIBSYSTEM_PATH);
        assert_eq!(unique.len(), before);

        let symbol = SymbolEntry {
            name,
            value: 0,
            size: 0,
            section: None,
            kind: SymbolKind::None,
            binding: SymbolBinding::Weak,
            flags: SymbolFlags::imported(),
        };
        let desc = symbol_desc(&module, &symbol, &libs).unwrap();
        assert_ne!(desc & N_WEAK_DEF, 0);
        assert_ne!(desc >> 8, 0);

        let other = intern(&mut module, "_other");
        let unmatched = SymbolEntry {
            name: other,
            value: 0,
            size: 0,
            section: None,
            kind: SymbolKind::None,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::imported(),
        };
        let unmatched_desc = symbol_desc(&module, &unmatched, &libs).unwrap();
        assert_eq!(unmatched_desc >> 8, 0);

        let missing_dylib = symbol_desc(&module, &symbol, &Vec::new()).unwrap();
        assert_eq!(missing_dylib >> 8, 0);
    }

    #[test]
    fn entry_below_text_base_is_rejected() {
        let mut module = module_for(TargetSpec::x86_64());
        text_section(&mut module, 4);
        module.set_entry(0);
        assert!(write(&module).is_err());
    }

    #[test]
    fn relocation_offset_above_u32_is_rejected() {
        let mut module = module_for(TargetSpec::x86_64());
        let text = text_section(&mut module, 4);
        let sym_name = intern(&mut module, "_s");
        let sym = module
            .add_symbol(SymbolEntry {
                name: sym_name,
                value: 0,
                size: 0,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        module
            .add_relocation(Relocation {
                section: text,
                offset: 0x1_0000_0000,
                symbol: sym,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        assert!(write(&module).is_err());
    }

    fn foreign_symbol() -> Symbol {
        let mut other = ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86_64());
        for index in 0..128 {
            other.intern(&alloc::format!("foreign{index}")).unwrap();
        }
        other.intern("foreign").unwrap()
    }

    #[test]
    fn write_rejects_foreign_section_name() {
        let mut module = module_for(TargetSpec::x86_64());
        module
            .add_section(Section {
                name: foreign_symbol(),
                kind: SectionKind::Text,
                address: 0,
                align: 4,
                flags: SectionFlags::code(),
                data: vec![0xC3],
                size: 1,
            })
            .unwrap();
        assert!(write(&module).is_err());
    }

    #[test]
    fn write_rejects_foreign_symbol_name() {
        let mut module = module_for(TargetSpec::x86_64());
        text_section(&mut module, 4);
        module
            .add_symbol(SymbolEntry {
                name: foreign_symbol(),
                value: 0,
                size: 0,
                section: None,
                kind: SymbolKind::None,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::imported(),
            })
            .unwrap();
        assert!(write(&module).is_err());
    }

    #[test]
    fn write_rejects_foreign_import_library() {
        let mut module = module_for(TargetSpec::x86_64());
        let name = intern(&mut module, "_n");
        module.add_import(Import {
            library: foreign_symbol(),
            name,
            ordinal: None,
            hint: None,
        });
        assert!(write(&module).is_err());
    }

    #[test]
    fn append_signature_succeeds_for_consistent_layout() {
        let mut module = module_for(TargetSpec::x86_64());
        text_section(&mut module, 4);
        let layout = build_layout(&module).unwrap();
        let mut image = build_image(&module, &layout).unwrap();
        let signature_offset = usize::try_from(layout.linkedit.signature_offset).unwrap();
        assert_eq!(image.len(), signature_offset);
        append_signature(&mut image, &layout).unwrap();
        assert!(image.len() > signature_offset);
    }

    #[test]
    fn layout_helpers_reject_oversized_commands_and_ordinals() {
        let mut module = module_for(TargetSpec::x86_64());
        for value in 0_u32..600 {
            let lib = intern(
                &mut module,
                &alloc::format!("/very/long/path/to/lib{value}.dylib"),
            );
            let name = intern(&mut module, &alloc::format!("_symbol_{value}"));
            module.add_import(Import {
                library: lib,
                name,
                ordinal: None,
                hint: None,
            });
        }
        assert!(build_layout(&module).is_err());

        let mut layouts = Vec::new();
        for raw in 0_u32..256 {
            layouts.push(SectionLayout {
                id: SectionId::from_raw(raw),
                segment: SegmentKind::Text,
                addr: 0,
                offset: 0,
                vm_size: 0,
                reloc_offset: 0,
                reloc_count: 0,
            });
        }
        assert!(section_ordinal(&layouts, Some(SectionId::from_raw(255))).is_err());
        assert!(section_ordinal(&[], Some(SectionId::from_raw(0))).is_err());
    }

    #[test]
    fn section_align_and_padding_errors_are_exercised() {
        let mut module = module_for(TargetSpec::x86_64());
        let id = text_section(&mut module, 0);
        assert_eq!(section_align(module.section(id)), DEFAULT_ALIGN);
        let const_name = intern(&mut module, "__const");
        let aligned = module
            .add_section(Section {
                name: const_name,
                kind: SectionKind::ReadOnlyData,
                address: 0,
                align: 16,
                flags: SectionFlags::read_only(),
                data: vec![1],
                size: 1,
            })
            .unwrap();
        assert_eq!(section_align(module.section(aligned)), 16);
        assert_eq!(align_exp(0).unwrap(), 0);
        assert!(align_exp(3).is_err());

        let mut writer = ByteWriter::new(Endianness::Little);
        writer.write_u8(1);
        assert!(pad_to(&mut writer, 0).is_err());
    }

    #[test]
    fn manual_layout_checks_reject_inconsistent_state() {
        let mut module = module_for(TargetSpec::x86_64());
        text_section(&mut module, 4);
        let mut layout = build_layout(&module).unwrap();
        layout.sizeofcmds = layout.sizeofcmds.checked_add(8).unwrap();
        assert!(build_image(&module, &layout).is_err());

        let mut no_text = build_layout(&module).unwrap();
        no_text
            .segments
            .retain(|segment| segment.kind != SegmentKind::Text);
        assert!(text_segment_filesize(&no_text).is_err());

        let mut image = vec![0_u8, 1];
        let mut mismatch = build_layout(&module).unwrap();
        mismatch.linkedit.signature_offset = 8;
        assert!(append_signature(&mut image, &mismatch).is_err());
    }

    #[test]
    fn relocation_writer_covers_overflow_and_encodings() {
        let mut module = module_for(TargetSpec::x86_64());
        let section = SectionId::from_raw(7);
        module
            .add_relocation(Relocation {
                section,
                offset: 0,
                symbol: SymbolId::from_raw(0x0100_0000),
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        let layout = minimal_layout(section);
        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(write_relocations(&mut writer, &module, &layout).is_err());

        assert_eq!(
            reloc_encoding(RelocKind::Absolute64, CPU_TYPE_X86_64),
            (false, 3, 0)
        );
        assert_eq!(
            reloc_encoding(RelocKind::Absolute32, CPU_TYPE_X86_64),
            (false, 2, 0)
        );
        assert_eq!(
            reloc_encoding(RelocKind::Relative32, CPU_TYPE_X86_64),
            (true, 2, 2)
        );
        assert_eq!(
            reloc_encoding(RelocKind::Relative64, CPU_TYPE_X86_64),
            (true, 3, 0)
        );
        assert_eq!(
            reloc_encoding(RelocKind::GotRelative, CPU_TYPE_ARM64),
            (true, 2, 5)
        );
        assert_eq!(
            reloc_encoding(RelocKind::PltRelative, CPU_TYPE_ARM64),
            (true, 2, 0)
        );
        assert_eq!(
            reloc_encoding(RelocKind::Other(0x2A), CPU_TYPE_X86_64),
            (false, 2, 0xA)
        );
    }
}
