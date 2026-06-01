//! Serializes an [`ObjectModule`] into a canonical ELF image.

use crate::consts::{MAGIC, PAGE_SIZE, elf32, elf64};
use crate::native::{
    ElfClass, ElfDataEncoding, ElfMachine, ElfSectionFlags as NativeSectionFlags, ElfSectionType,
    ElfSegmentFlags, ElfSegmentType, ElfSymbolBind, ElfSymbolType, ElfType, ElfVersion,
};
use stratum_oir::{
    Architecture, ByteWriter, Endianness, Error, ObjectModule, PtrWidth, RelocKind, Relocation,
    Result, Section, SectionFlags, SectionId, SectionKind, Segment, SymbolBinding, SymbolEntry,
    SymbolId, SymbolKind,
};

extern crate alloc;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

const fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn machine(arch: Architecture) -> Result<u16> {
    match arch {
        Architecture::X86 => Ok(ElfMachine::X86.raw()),
        Architecture::X86_64 => Ok(ElfMachine::X86_64.raw()),
        Architecture::Arm => Ok(ElfMachine::Arm.raw()),
        Architecture::Aarch64 => Ok(ElfMachine::Aarch64.raw()),
        Architecture::Riscv64 => Ok(ElfMachine::Riscv.raw()),
        Architecture::PowerPc => Ok(ElfMachine::PowerPc.raw()),
        Architecture::PowerPc64 => Ok(ElfMachine::PowerPc64.raw()),
        Architecture::Mips | Architecture::Mips64 => Ok(ElfMachine::Mips.raw()),
        Architecture::S390x => Ok(ElfMachine::S390.raw()),
        Architecture::LoongArch64 => Ok(ElfMachine::LoongArch.raw()),
        Architecture::Sparc64 => Ok(ElfMachine::SparcV9.raw()),
        Architecture::Other(id) => u16::try_from(id).map_err(|_| Error::ValueOutOfRange("machine")),
        Architecture::Wasm32 => Err(Error::Unsupported("ELF target architecture")),
    }
}

const fn class(width: PtrWidth) -> u8 {
    match width {
        PtrWidth::W32 => ElfClass::Class32.raw(),
        PtrWidth::W64 => ElfClass::Class64.raw(),
    }
}

const fn ehdr_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::EHDR_SIZE,
        PtrWidth::W64 => elf64::EHDR_SIZE,
    }
}

const fn phdr_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::PHDR_SIZE,
        PtrWidth::W64 => elf64::PHDR_SIZE,
    }
}

const fn shdr_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::SHDR_SIZE,
        PtrWidth::W64 => elf64::SHDR_SIZE,
    }
}

const fn sym_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::SYM_SIZE,
        PtrWidth::W64 => elf64::SYM_SIZE,
    }
}

const fn rela_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::RELA_SIZE,
        PtrWidth::W64 => elf64::RELA_SIZE,
    }
}

const fn is_allocated(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::Text | SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::Bss
    )
}

fn u64_len(slice: &[u8]) -> u64 {
    slice.len() as u64
}

fn u16_len(value: usize, what: &'static str) -> Result<u16> {
    match u16::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) => Err(Error::ValueOutOfRange(what)),
    }
}

fn u32_index(value: usize, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn u32_value(value: u64, what: &'static str) -> Result<u32> {
    match u32::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) => Err(Error::ValueOutOfRange(what)),
    }
}

fn u16_value(value: u64, what: &'static str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn usize_value(value: u64, what: &'static str) -> Result<usize> {
    usize_value_with_max(value, what, usize::MAX as u64)
}

fn usize_value_with_max(value: u64, what: &'static str, max: u64) -> Result<usize> {
    if value > max {
        return Err(Error::ValueOutOfRange(what));
    }
    usize::try_from(value).or(Err(Error::ValueOutOfRange(what)))
}

fn writer_position(writer: &ByteWriter) -> Result<u64> {
    u64::try_from(writer.position()).map_err(|_| Error::ValueOutOfRange("writer position"))
}

fn pad_writer_to(writer: &mut ByteWriter, target: u64) -> Result<()> {
    let current = writer_position(writer)?;
    if target < current {
        return Err(Error::Malformed("ELF layout went backwards"));
    }
    writer.write_zeros(usize_value(target - current, "padding length")?);
    Ok(())
}

/// A simple append-only ELF string table.
#[derive(Debug)]
struct StringTable {
    bytes: Vec<u8>,
}

impl StringTable {
    fn new() -> Self {
        Self { bytes: vec![0] }
    }

    fn add(&mut self, text: &str) -> Result<u32> {
        if text.is_empty() {
            return Ok(0);
        }
        let offset = u32::try_from(self.bytes.len())
            .map_err(|_| Error::ValueOutOfRange("string table offset"))?;
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
        Ok(offset)
    }
}

/// One ELF section header, accumulated before being written out.
#[derive(Debug, Clone, Copy)]
struct Shdr {
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

impl Shdr {
    const fn zeroed() -> Self {
        Self {
            name: 0,
            sh_type: 0,
            flags: 0,
            addr: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            addralign: 0,
            entsize: 0,
        }
    }

    fn write(&self, w: &mut ByteWriter, width: PtrWidth) -> Result<()> {
        match width {
            PtrWidth::W32 => {
                w.write_u32(self.name);
                w.write_u32(self.sh_type);
                w.write_u32(u32_value(self.flags, "section flags")?);
                w.write_u32(u32_value(self.addr, "section address")?);
                w.write_u32(u32_value(self.offset, "section offset")?);
                w.write_u32(u32_value(self.size, "section size")?);
                w.write_u32(self.link);
                w.write_u32(self.info);
                w.write_u32(u32_value(self.addralign, "section alignment")?);
                w.write_u32(u32_value(self.entsize, "section entry size")?);
            }
            PtrWidth::W64 => {
                w.write_u32(self.name);
                w.write_u32(self.sh_type);
                w.write_u64(self.flags);
                w.write_u64(self.addr);
                w.write_u64(self.offset);
                w.write_u64(self.size);
                w.write_u32(self.link);
                w.write_u32(self.info);
                w.write_u64(self.addralign);
                w.write_u64(self.entsize);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct SecLayout {
    file_offset: u64,
    name_off: u32,
}

#[derive(Debug)]
struct RealSection<'a> {
    id: SectionId,
    section: &'a Section,
}

#[derive(Debug, Clone, Copy)]
struct SectionLookup<'a> {
    sections: &'a [RealSection<'a>],
}

impl<'a> SectionLookup<'a> {
    const fn new(sections: &'a [RealSection<'a>]) -> Self {
        Self { sections }
    }

    fn get(self, id: SectionId, what: &'static str) -> Result<&'a RealSection<'a>> {
        self.sections
            .get(id.index())
            .filter(|entry| entry.id == id)
            .ok_or(Error::Malformed(what))
    }

    fn name(self, module: &'a ObjectModule, id: SectionId) -> Result<&'a str> {
        module.resolve(self.get(id, "relocation section id")?.section.name)
    }

    fn shndx(self, id: SectionId) -> Result<u32> {
        u32::try_from(self.get(id, "section id")?.id.index() + 1)
            .map_err(|_| Error::ValueOutOfRange("section index"))
    }
}

/// Destination for streaming ELF output.
pub trait ElfSink {
    /// Sink-specific write error.
    type Error;

    /// Appends all bytes to the sink.
    ///
    /// # Errors
    ///
    /// Returns an error if the sink cannot accept the complete byte slice.
    fn write_all(&mut self, bytes: &[u8]) -> core::result::Result<(), Self::Error>;
}

impl ElfSink for Vec<u8> {
    type Error = Infallible;

    fn write_all(&mut self, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Error returned by the crate-level [`write_to`](crate::write_to) function.
#[derive(Debug)]
pub enum ElfWriteError<E> {
    /// The module cannot be represented as ELF.
    Object(Error),
    /// The sink rejected bytes during final emission.
    Sink(E),
}

impl<E> From<Error> for ElfWriteError<E> {
    fn from(err: Error) -> Self {
        Self::Object(err)
    }
}

/// Serializes `module` to ELF bytes.
///
/// # Errors
///
/// Returns an error if a field cannot be represented in the target ELF class or if the module
/// layout cannot be encoded as loadable ELF segments.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    plan_emit(module, emit)?
}

/// Serializes `module` to an [`ElfSink`].
///
/// # Errors
///
/// Returns an object error if `module` cannot be represented as ELF, or a sink error if the sink
/// cannot accept all emitted bytes.
pub fn write_to<S>(
    module: &ObjectModule,
    sink: &mut S,
) -> core::result::Result<(), ElfWriteError<S::Error>>
where
    S: ElfSink + ?Sized,
{
    match plan_emit(module, |input| emit_to(input, sink)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(ElfWriteError::Object(err)),
    }
}

fn plan_emit<R, F>(module: &ObjectModule, finish: F) -> Result<R>
where
    F: FnOnce(&Emit<'_>) -> R,
{
    let target = module.target();
    let endian = target.endian;
    let width = target.ptr_width;
    let machine = machine(target.arch)?;

    let sections: Vec<RealSection<'_>> = module
        .sections()
        .map(|(id, section)| RealSection { id, section })
        .collect();
    let section_lookup = SectionLookup::new(&sections);
    let phdrs = build_phdrs(module, &sections)?;
    let phnum = u16_len(phdrs.len(), "program header count")?;

    let mut shstrtab = StringTable::new();
    let layouts = plan_sections(module, &sections, &mut shstrtab, phnum, width)?;
    let shstrtab_name = shstrtab.add(".shstrtab")?;
    let have_symbols = module.symbol_count() > 0;
    let have_relocs = module.relocation_count() > 0;
    let mut names = NameOffsets {
        shstrtab: shstrtab_name,
        symtab: 0,
        strtab: 0,
        relocations: Vec::new(),
    };
    if have_symbols || have_relocs {
        names.symtab = shstrtab.add(".symtab")?;
        names.strtab = shstrtab.add(".strtab")?;
    }
    if have_relocs {
        for reloc in module.relocations().map(|(_, reloc)| reloc) {
            let sec_name = section_lookup.name(module, reloc.section)?;
            names
                .relocations
                .push(shstrtab.add(&format!(".rela{sec_name}"))?);
        }
    }

    let mut cursor = next_cursor(&sections, &layouts)?;
    let shstrtab_off = cursor;
    cursor = cursor
        .checked_add(u64_len(&shstrtab.bytes))
        .ok_or(Error::ValueOutOfRange("section-name string table end"))?;

    let tables = build_tables(module, endian, width, have_symbols || have_relocs, cursor)?;
    cursor = tables.end;
    let relocs = build_relocations(module, endian, width, &tables, section_lookup, cursor)?;
    cursor = relocs.end;

    cursor = align_up(cursor, 8);
    let shoff = cursor;

    let shdr_inputs = ShdrInputs {
        module,
        sections: &sections,
        layouts: &layouts,
        names: &names,
        shstrtab_off,
        shstrtab_bytes: &shstrtab.bytes,
        tables: &tables,
        relocs: &relocs,
        width,
    };
    let shdrs = build_shdrs(shdr_inputs)?;
    let shnum = u16_len(shdrs.len(), "section count")?;
    let shstrndx = u16_len(sections.len() + 1, "section-name string table index")?;

    Ok(finish(&Emit {
        sections: &sections,
        layouts: &layouts,
        phdrs: &phdrs,
        shdrs: &shdrs,
        shstrtab: &shstrtab.bytes,
        shstrtab_off,
        tables: &tables,
        relocs: &relocs,
        shoff,
        ehdr: Ehdr {
            endian,
            width,
            machine,
            entry: module.entry().unwrap_or(0),
            phnum,
            shoff,
            shnum,
            shstrndx,
        },
    }))
}

#[derive(Debug, Clone, Copy)]
struct Phdr {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

impl Phdr {
    fn write(&self, w: &mut ByteWriter, width: PtrWidth) -> Result<()> {
        match width {
            PtrWidth::W32 => {
                w.write_u32(self.typ);
                w.write_u32(u32_value(self.offset, "program offset")?);
                let vaddr = u32_value(self.vaddr, "program vaddr")?;
                w.write_u32(vaddr);
                w.write_u32(vaddr);
                w.write_u32(u32_value(self.filesz, "program filesz")?);
                w.write_u32(u32_value(self.memsz, "program memsz")?);
                w.write_u32(self.flags);
                w.write_u32(u32_value(self.align, "program alignment")?);
            }
            PtrWidth::W64 => {
                w.write_u32(self.typ);
                w.write_u32(self.flags);
                w.write_u64(self.offset);
                w.write_u64(self.vaddr);
                w.write_u64(self.vaddr);
                w.write_u64(self.filesz);
                w.write_u64(self.memsz);
                w.write_u64(self.align);
            }
        }
        Ok(())
    }
}

fn build_phdrs(module: &ObjectModule, sections: &[RealSection<'_>]) -> Result<Vec<Phdr>> {
    if !module.segments().is_empty() {
        let section_lookup = SectionLookup::new(sections);
        return module
            .segments()
            .iter()
            .map(|segment| segment_to_phdr(segment, section_lookup))
            .collect();
    }
    Ok(sections
        .iter()
        .filter(|entry| is_allocated(entry.section.kind))
        .map(|entry| section_to_phdr(entry.section))
        .collect())
}

fn segment_to_phdr(segment: &Segment, section_lookup: SectionLookup<'_>) -> Result<Phdr> {
    let mut filesz = 0_u64;
    let mut memsz = segment.vm_size;
    for id in &segment.sections {
        let section = section_lookup.get(*id, "segment section id")?.section;
        let end = section
            .address
            .checked_add(section.vm_size())
            .ok_or(Error::ValueOutOfRange("segment vm end"))?;
        memsz = memsz.max(end.saturating_sub(segment.address));
        if section.kind != SectionKind::Bss {
            let file_end = section
                .address
                .checked_add(section.file_size())
                .ok_or(Error::ValueOutOfRange("segment file end"))?;
            filesz = filesz.max(file_end.saturating_sub(segment.address));
        }
    }
    Ok(Phdr {
        typ: ElfSegmentType::Load.raw(),
        flags: ph_flags(segment.flags),
        offset: segment.address % PAGE_SIZE,
        vaddr: segment.address,
        filesz,
        memsz,
        align: PAGE_SIZE,
    })
}

fn section_to_phdr(section: &Section) -> Phdr {
    let filesz = if section.kind == SectionKind::Bss {
        0
    } else {
        section.file_size()
    };
    Phdr {
        typ: ElfSegmentType::Load.raw(),
        flags: ph_flags(section.flags),
        offset: section.address % PAGE_SIZE,
        vaddr: section.address,
        filesz,
        memsz: section.size.max(filesz),
        align: PAGE_SIZE,
    }
}

fn ph_flags(flags: SectionFlags) -> u32 {
    let mut raw = 0;
    if flags.read {
        raw |= ElfSegmentFlags::PF_R.raw();
    }
    if flags.write {
        raw |= ElfSegmentFlags::PF_W.raw();
    }
    if flags.execute {
        raw |= ElfSegmentFlags::PF_X.raw();
    }
    raw
}

fn plan_sections(
    module: &ObjectModule,
    sections: &[RealSection<'_>],
    shstrtab: &mut StringTable,
    phnum: u16,
    width: PtrWidth,
) -> Result<Vec<SecLayout>> {
    let mut layouts: Vec<SecLayout> = Vec::with_capacity(sections.len());
    let mut cursor = ehdr_size(width) + u64::from(phnum) * phdr_size(width);
    for entry in sections {
        let section = entry.section;
        let name = module.resolve(section.name)?;
        let name_off = shstrtab.add(name)?;
        let allocated = is_allocated(section.kind);
        let align = if allocated {
            PAGE_SIZE
        } else {
            section.align.max(1)
        };
        cursor = align_up(cursor, align);
        if allocated && section.address % PAGE_SIZE != cursor % PAGE_SIZE {
            return Err(Error::Malformed(
                "allocated section address not congruent with file offset",
            ));
        }
        layouts.push(SecLayout {
            file_offset: cursor,
            name_off,
        });
        if section.kind != SectionKind::Bss {
            cursor = cursor
                .checked_add(section.file_size())
                .ok_or(Error::ValueOutOfRange("section end"))?;
        }
    }
    Ok(layouts)
}

fn next_cursor(sections: &[RealSection<'_>], layouts: &[SecLayout]) -> Result<u64> {
    let mut cursor = 0;
    for (entry, layout) in sections.iter().zip(layouts) {
        cursor = layout.file_offset;
        if entry.section.kind != SectionKind::Bss {
            cursor = cursor
                .checked_add(entry.section.file_size())
                .ok_or(Error::ValueOutOfRange("section end"))?;
        }
    }
    Ok(cursor)
}

#[derive(Debug)]
struct NameOffsets {
    shstrtab: u32,
    symtab: u32,
    strtab: u32,
    relocations: Vec<u32>,
}

#[derive(Debug)]
struct Tables {
    have_symbols: bool,
    symtab_bytes: Vec<u8>,
    symtab_off: u64,
    strtab_bytes: Vec<u8>,
    strtab_off: u64,
    end: u64,
}

fn build_tables(
    module: &ObjectModule,
    endian: Endianness,
    width: PtrWidth,
    have_symbols: bool,
    cursor: u64,
) -> Result<Tables> {
    if !have_symbols {
        return Ok(Tables {
            have_symbols,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: cursor,
        });
    }
    let mut strtab = StringTable::new();
    let mut sw = ByteWriter::new(endian);
    sw.write_zeros(usize_value(sym_size(width), "symbol size")?);
    for (_, symbol) in module.symbols() {
        write_symbol(&mut sw, module, &mut strtab, symbol, width)?;
    }
    let symtab_bytes = sw.finish()?;
    let symtab_off = cursor;
    let strtab_off = symtab_off
        .checked_add(u64_len(&symtab_bytes))
        .ok_or(Error::ValueOutOfRange("symtab end"))?;
    let end = strtab_off
        .checked_add(u64_len(&strtab.bytes))
        .ok_or(Error::ValueOutOfRange("strtab end"))?;
    Ok(Tables {
        have_symbols,
        symtab_bytes,
        symtab_off,
        strtab_bytes: strtab.bytes,
        strtab_off,
        end,
    })
}

#[derive(Debug)]
struct RelocTable {
    bytes: Vec<u8>,
    offset: u64,
    target_shndx: u32,
}

#[derive(Debug)]
struct RelocTables {
    tables: Vec<RelocTable>,
    end: u64,
}

fn build_relocations(
    module: &ObjectModule,
    endian: Endianness,
    width: PtrWidth,
    tables: &Tables,
    section_lookup: SectionLookup<'_>,
    cursor: u64,
) -> Result<RelocTables> {
    let mut out = Vec::new();
    let mut next = cursor;
    if !tables.have_symbols {
        return Ok(RelocTables {
            tables: out,
            end: next,
        });
    }
    for (_, reloc) in module.relocations() {
        let mut rw = ByteWriter::new(endian);
        write_rela(&mut rw, module, reloc, width)?;
        let bytes = rw.finish()?;
        let target_shndx = section_lookup.shndx(reloc.section)?;
        let offset = next;
        next = offset
            .checked_add(u64_len(&bytes))
            .ok_or(Error::ValueOutOfRange("rela end"))?;
        out.push(RelocTable {
            bytes,
            offset,
            target_shndx,
        });
    }
    Ok(RelocTables {
        tables: out,
        end: next,
    })
}

fn symbol_index(symbol: SymbolId) -> Result<u32> {
    u32::try_from(symbol.index() + 1).map_err(|_| Error::ValueOutOfRange("symbol index"))
}

#[derive(Clone, Copy)]
struct ShdrInputs<'a> {
    module: &'a ObjectModule,
    sections: &'a [RealSection<'a>],
    layouts: &'a [SecLayout],
    names: &'a NameOffsets,
    shstrtab_off: u64,
    shstrtab_bytes: &'a [u8],
    tables: &'a Tables,
    relocs: &'a RelocTables,
    width: PtrWidth,
}

fn build_shdrs(inputs: ShdrInputs<'_>) -> Result<Vec<Shdr>> {
    let ShdrInputs {
        module,
        sections,
        layouts,
        names,
        shstrtab_off,
        shstrtab_bytes,
        tables,
        relocs,
        width,
    } = inputs;
    let mut shdrs: Vec<Shdr> = Vec::with_capacity(sections.len() + 4 + relocs.tables.len());
    shdrs.push(Shdr::zeroed());
    for (entry, layout) in sections.iter().zip(layouts) {
        let section = entry.section;
        shdrs.push(Shdr {
            name: layout.name_off,
            sh_type: elf_section_type(module, section)?,
            flags: elf_section_flags(section),
            addr: section.address,
            offset: layout.file_offset,
            size: section.vm_size(),
            link: 0,
            info: 0,
            addralign: section.align.max(1),
            entsize: 0,
        });
    }
    shdrs.push(Shdr {
        name: names.shstrtab,
        sh_type: ElfSectionType::Strtab.raw(),
        offset: shstrtab_off,
        size: u64_len(shstrtab_bytes),
        addralign: 1,
        ..Shdr::zeroed()
    });
    let symtab_index = if tables.have_symbols {
        let symtab_index = u32_index(shdrs.len(), "symtab index")?;
        let strtab_index = symtab_index
            .checked_add(1)
            .ok_or(Error::ValueOutOfRange("string table index"))?;
        shdrs.push(Shdr {
            name: names.symtab,
            sh_type: ElfSectionType::Symtab.raw(),
            offset: tables.symtab_off,
            size: u64_len(&tables.symtab_bytes),
            link: strtab_index,
            info: 1,
            addralign: u64::from(width.bytes()),
            entsize: sym_size(width),
            ..Shdr::zeroed()
        });
        shdrs.push(Shdr {
            name: names.strtab,
            sh_type: ElfSectionType::Strtab.raw(),
            offset: tables.strtab_off,
            size: u64_len(&tables.strtab_bytes),
            addralign: 1,
            ..Shdr::zeroed()
        });
        symtab_index
    } else {
        0
    };
    for (table, name) in relocs.tables.iter().zip(&names.relocations) {
        shdrs.push(Shdr {
            name: *name,
            sh_type: ElfSectionType::Rela.raw(),
            offset: table.offset,
            size: u64_len(&table.bytes),
            link: symtab_index,
            info: table.target_shndx,
            addralign: u64::from(width.bytes()),
            entsize: rela_size(width),
            ..Shdr::zeroed()
        });
    }
    Ok(shdrs)
}

#[derive(Debug, Clone, Copy)]
struct Emit<'a> {
    sections: &'a [RealSection<'a>],
    layouts: &'a [SecLayout],
    phdrs: &'a [Phdr],
    shdrs: &'a [Shdr],
    shstrtab: &'a [u8],
    shstrtab_off: u64,
    tables: &'a Tables,
    relocs: &'a RelocTables,
    shoff: u64,
    ehdr: Ehdr,
}

type EmitResult<S> = core::result::Result<(), ElfWriteError<<S as ElfSink>::Error>>;

#[derive(Debug)]
struct SinkWriter<'a, S: ElfSink + ?Sized> {
    sink: &'a mut S,
    position: u64,
}

impl<'a, S> SinkWriter<'a, S>
where
    S: ElfSink + ?Sized,
{
    fn new(sink: &'a mut S) -> Self {
        Self { sink, position: 0 }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> EmitResult<S> {
        self.sink.write_all(bytes).map_err(ElfWriteError::Sink)?;
        self.position = self
            .position
            .checked_add(u64_len(bytes))
            .ok_or(Error::ValueOutOfRange("emitted ELF size"))?;
        Ok(())
    }

    fn write_zeros(&mut self, mut count: u64) -> EmitResult<S> {
        let zeros = [0_u8; 4096];
        let max_chunk = u64_len(&zeros);
        while count > 0 {
            let chunk = count.min(max_chunk);
            let chunk_len = usize_value(chunk, "zero padding chunk length")?;
            let bytes = zeros
                .get(..chunk_len)
                .ok_or(Error::Malformed("zero padding chunk length"))?;
            self.write_bytes(bytes)?;
            count -= chunk;
        }
        Ok(())
    }

    fn pad_to(&mut self, target: u64) -> EmitResult<S> {
        if target < self.position {
            return Err(Error::Malformed("ELF layout went backwards").into());
        }
        self.write_zeros(target - self.position)
    }
}

fn write_record<S, F>(out: &mut SinkWriter<'_, S>, endian: Endianness, write: F) -> EmitResult<S>
where
    S: ElfSink + ?Sized,
    F: FnOnce(&mut ByteWriter) -> Result<()>,
{
    let mut writer = ByteWriter::new(endian);
    write(&mut writer)?;
    let bytes = writer.finish()?;
    out.write_bytes(&bytes)
}

fn emit(e: &Emit<'_>) -> Result<Vec<u8>> {
    let mut writer = ByteWriter::new(e.ehdr.endian);
    write_ehdr(&mut writer, &e.ehdr)?;
    for phdr in e.phdrs {
        phdr.write(&mut writer, e.ehdr.width)?;
    }
    for (entry, layout) in e.sections.iter().zip(e.layouts) {
        pad_writer_to(&mut writer, layout.file_offset)?;
        if entry.section.kind != SectionKind::Bss {
            writer.write_bytes(&entry.section.data);
        }
    }
    pad_writer_to(&mut writer, e.shstrtab_off)?;
    writer.write_bytes(e.shstrtab);
    if e.tables.have_symbols {
        pad_writer_to(&mut writer, e.tables.symtab_off)?;
        writer.write_bytes(&e.tables.symtab_bytes);
        pad_writer_to(&mut writer, e.tables.strtab_off)?;
        writer.write_bytes(&e.tables.strtab_bytes);
    }
    for table in &e.relocs.tables {
        pad_writer_to(&mut writer, table.offset)?;
        writer.write_bytes(&table.bytes);
    }
    pad_writer_to(&mut writer, e.shoff)?;
    for shdr in e.shdrs {
        shdr.write(&mut writer, e.ehdr.width)?;
    }
    writer.finish()
}

fn emit_to<S>(e: &Emit<'_>, sink: &mut S) -> EmitResult<S>
where
    S: ElfSink + ?Sized,
{
    let mut out = SinkWriter::new(sink);
    write_record(&mut out, e.ehdr.endian, |writer| {
        write_ehdr(writer, &e.ehdr)
    })?;
    for phdr in e.phdrs {
        write_record(&mut out, e.ehdr.endian, |writer| {
            phdr.write(writer, e.ehdr.width)
        })?;
    }
    for (entry, layout) in e.sections.iter().zip(e.layouts) {
        out.pad_to(layout.file_offset)?;
        if entry.section.kind != SectionKind::Bss {
            out.write_bytes(&entry.section.data)?;
        }
    }
    out.pad_to(e.shstrtab_off)?;
    out.write_bytes(e.shstrtab)?;
    if e.tables.have_symbols {
        out.pad_to(e.tables.symtab_off)?;
        out.write_bytes(&e.tables.symtab_bytes)?;
        out.pad_to(e.tables.strtab_off)?;
        out.write_bytes(&e.tables.strtab_bytes)?;
    }
    for table in &e.relocs.tables {
        out.pad_to(table.offset)?;
        out.write_bytes(&table.bytes)?;
    }
    out.pad_to(e.shoff)?;
    for shdr in e.shdrs {
        write_record(&mut out, e.ehdr.endian, |writer| {
            shdr.write(writer, e.ehdr.width)
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Ehdr {
    endian: Endianness,
    width: PtrWidth,
    machine: u16,
    entry: u64,
    phnum: u16,
    shoff: u64,
    shnum: u16,
    shstrndx: u16,
}

fn write_ehdr(w: &mut ByteWriter, ehdr: &Ehdr) -> Result<()> {
    w.write_bytes(&MAGIC);
    w.write_u8(class(ehdr.width));
    w.write_u8(match ehdr.endian {
        Endianness::Little => ElfDataEncoding::Little.raw(),
        Endianness::Big => ElfDataEncoding::Big.raw(),
    });
    w.write_u8(ElfVersion::Current.raw());
    w.write_zeros(9);
    w.write_u16(ElfType::Executable.raw());
    w.write_u16(ehdr.machine);
    w.write_u32(u32::from(ElfVersion::Current.raw()));
    match ehdr.width {
        PtrWidth::W32 => {
            w.write_u32(u32_value(ehdr.entry, "entry")?);
            w.write_u32(u32_value(elf32::EHDR_SIZE, "ELF32 header size")?);
            w.write_u32(u32_value(ehdr.shoff, "section header offset")?);
        }
        PtrWidth::W64 => {
            w.write_u64(ehdr.entry);
            w.write_u64(elf64::EHDR_SIZE);
            w.write_u64(ehdr.shoff);
        }
    }
    w.write_u32(0);
    w.write_u16(u16_value(ehdr_size(ehdr.width), "ELF header size")?);
    w.write_u16(u16_value(phdr_size(ehdr.width), "program header size")?);
    w.write_u16(ehdr.phnum);
    w.write_u16(u16_value(shdr_size(ehdr.width), "section header size")?);
    w.write_u16(ehdr.shnum);
    w.write_u16(ehdr.shstrndx);
    Ok(())
}

fn elf_section_type(module: &ObjectModule, section: &Section) -> Result<u32> {
    let name = module.resolve(section.name)?;
    if name == ".dynamic" {
        return Ok(ElfSectionType::Dynamic.raw());
    }
    if name.starts_with(".note") {
        return Ok(ElfSectionType::Note.raw());
    }
    Ok(match section.kind {
        SectionKind::Bss => ElfSectionType::Nobits.raw(),
        _ => ElfSectionType::Progbits.raw(),
    })
}

fn elf_section_flags(section: &Section) -> u64 {
    let mut flags = NativeSectionFlags::empty();
    if section.flags.read {
        flags |= NativeSectionFlags::SHF_ALLOC;
    }
    if section.flags.write {
        flags |= NativeSectionFlags::SHF_WRITE;
    }
    if section.flags.execute {
        flags |= NativeSectionFlags::SHF_EXECINSTR;
    }
    flags.raw()
}

fn write_symbol(
    w: &mut ByteWriter,
    module: &ObjectModule,
    strtab: &mut StringTable,
    symbol: &SymbolEntry,
    width: PtrWidth,
) -> Result<()> {
    let name = module.resolve(symbol.name)?;
    let name_off = strtab.add(name)?;
    let bind = match symbol.binding {
        SymbolBinding::Local => ElfSymbolBind::Local.raw(),
        SymbolBinding::Global => ElfSymbolBind::Global.raw(),
        SymbolBinding::Weak => ElfSymbolBind::Weak.raw(),
    };
    let typ = match symbol.kind {
        SymbolKind::Function => ElfSymbolType::Function.raw(),
        SymbolKind::Object => ElfSymbolType::Object.raw(),
        SymbolKind::Section => ElfSymbolType::Section.raw(),
        SymbolKind::None => ElfSymbolType::NoType.raw(),
    };
    let shndx = match symbol.section {
        Some(id) => u16::try_from(id.index() + 1).map_err(|_| Error::ValueOutOfRange("shndx"))?,
        None => 0,
    };
    match width {
        PtrWidth::W32 => {
            w.write_u32(name_off);
            w.write_u32(u32_value(symbol.value, "symbol value")?);
            w.write_u32(u32_value(symbol.size, "symbol size")?);
            w.write_u8((bind << 4) | (typ & 0x0f));
            w.write_u8(0);
            w.write_u16(shndx);
        }
        PtrWidth::W64 => {
            w.write_u32(name_off);
            w.write_u8((bind << 4) | (typ & 0x0f));
            w.write_u8(0);
            w.write_u16(shndx);
            w.write_u64(symbol.value);
            w.write_u64(symbol.size);
        }
    }
    Ok(())
}

fn write_rela(
    w: &mut ByteWriter,
    module: &ObjectModule,
    reloc: &Relocation,
    width: PtrWidth,
) -> Result<()> {
    let typ = relocation_type(module.target().arch, reloc.kind);
    let sym = symbol_index(reloc.symbol)?;
    match width {
        PtrWidth::W32 => {
            w.write_u32(u32_value(reloc.offset, "relocation offset")?);
            w.write_u32((sym << 8) | (typ & 0xff));
            let addend = i32::try_from(reloc.addend)
                .map_err(|_| Error::ValueOutOfRange("relocation addend"))?;
            w.write_u32(u32::from_ne_bytes(addend.to_ne_bytes()));
        }
        PtrWidth::W64 => {
            w.write_u64(reloc.offset);
            w.write_u64((u64::from(sym) << 32) | u64::from(typ));
            w.write_u64(u64::from_ne_bytes(reloc.addend.to_ne_bytes()));
        }
    }
    Ok(())
}

#[expect(
    clippy::match_same_arms,
    reason = "ELF relocation numbers intentionally share fallbacks across architectures"
)]
fn relocation_type(arch: Architecture, kind: RelocKind) -> u32 {
    match (arch, kind) {
        (Architecture::X86_64, RelocKind::Absolute64) => 1,
        (Architecture::X86_64, RelocKind::Relative32) => 2,
        (Architecture::X86_64, RelocKind::GotRelative) => 9,
        (Architecture::X86_64, RelocKind::PltRelative) => 4,
        (Architecture::X86, RelocKind::Absolute32) => 1,
        (Architecture::X86, RelocKind::Relative32) => 2,
        (Architecture::Aarch64, RelocKind::Absolute64) => 257,
        (Architecture::Aarch64, RelocKind::Absolute32) => 258,
        (Architecture::Aarch64, RelocKind::Relative32) => 261,
        (Architecture::Arm, RelocKind::Absolute32) => 2,
        (Architecture::Arm, RelocKind::Relative32) => 3,
        (Architecture::Riscv64, RelocKind::Absolute64) => 2,
        (Architecture::Riscv64, RelocKind::Relative32) => 39,
        (Architecture::PowerPc64, RelocKind::Absolute64) => 38,
        (Architecture::PowerPc | Architecture::PowerPc64, RelocKind::Relative32) => 26,
        (Architecture::PowerPc | Architecture::PowerPc64, RelocKind::Absolute32) => 1,
        (Architecture::Mips | Architecture::Mips64, RelocKind::Absolute32) => 2,
        (Architecture::Mips64, RelocKind::Absolute64) => 18,
        (Architecture::S390x, RelocKind::Absolute64) => 22,
        (Architecture::S390x, RelocKind::Relative32) => 5,
        (Architecture::LoongArch64, RelocKind::Absolute64) => 2,
        (Architecture::Sparc64, RelocKind::Absolute64) => 32,
        (_, RelocKind::Other(raw)) => raw,
        (_, RelocKind::Absolute64) => 1,
        (_, RelocKind::Absolute32) => 1,
        (_, RelocKind::Relative32) => 2,
        (_, RelocKind::Relative64) => 0,
        (_, RelocKind::GotRelative) => 0,
        (_, RelocKind::PltRelative) => 0,
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use alloc::vec;
    use stratum_oir::{
        BinaryFormat, ByteWriter, Relocation, SectionFlags, Symbol, SymbolFlags, TargetSpec,
    };

    fn module(target: TargetSpec) -> ObjectModule {
        ObjectModule::new(BinaryFormat::Elf, target)
    }

    fn emit_vec(e: &Emit<'_>) -> Result<Vec<u8>> {
        emit(e)
    }

    #[derive(Debug)]
    struct RecordingSink {
        bytes: Vec<u8>,
        remaining_ok: Option<u8>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                remaining_ok: None,
            }
        }

        fn failing_after(remaining_ok: u8) -> Self {
            Self {
                bytes: Vec::new(),
                remaining_ok: Some(remaining_ok),
            }
        }
    }

    impl ElfSink for RecordingSink {
        type Error = ();

        fn write_all(&mut self, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
            if let Some(remaining_ok) = self.remaining_ok.as_mut() {
                if *remaining_ok == 0 {
                    return Err(());
                }
                *remaining_ok -= 1;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn assert_emit_sink_error(e: &Emit<'_>, remaining_ok: u8) {
        assert!(
            emit_to(e, &mut RecordingSink::failing_after(remaining_ok)).is_err(),
            "sink should fail after {remaining_ok} successful write(s)"
        );
    }

    fn assert_emit_object_error(e: &Emit<'_>) {
        assert!(
            emit_to(e, &mut RecordingSink::new()).is_err(),
            "streaming emit should reject malformed layout"
        );
    }

    #[test]
    fn small_helpers_and_errors_are_covered() {
        assert_eq!(align_up(7, 1), 7);
        assert_eq!(align_up(8, 4), 8);
        assert!(usize_value_with_max(2, "usize", 1).is_err());
        assert!(u32_index(usize::MAX, "index").is_err());
        assert!(u32_value(u64::from(u32::MAX) + 1, "u32").is_err());
        assert!(u16_len(usize::from(u16::MAX) + 1, "u16").is_err());
        assert_eq!(u16_len(usize::from(u16::MAX), "u16").unwrap(), u16::MAX);
        assert!(u16_value(u64::from(u16::MAX) + 1, "u16").is_err());
        assert_eq!(machine(Architecture::Other(0x1234)).unwrap(), 0x1234);
        assert_eq!(machine(Architecture::Arm).unwrap(), ElfMachine::Arm.raw());
        assert_eq!(
            machine(Architecture::Riscv64).unwrap(),
            ElfMachine::Riscv.raw()
        );
        assert_eq!(
            machine(Architecture::PowerPc64).unwrap(),
            ElfMachine::PowerPc64.raw()
        );
        assert_eq!(machine(Architecture::Mips).unwrap(), ElfMachine::Mips.raw());
        assert_eq!(
            machine(Architecture::Mips64).unwrap(),
            ElfMachine::Mips.raw()
        );
        assert_eq!(
            machine(Architecture::S390x).unwrap(),
            ElfMachine::S390.raw()
        );
        assert_eq!(
            machine(Architecture::LoongArch64).unwrap(),
            ElfMachine::LoongArch.raw()
        );
        assert_eq!(
            machine(Architecture::Sparc64).unwrap(),
            ElfMachine::SparcV9.raw()
        );
        assert!(machine(Architecture::Other(u32::MAX)).is_err());
        assert!(machine(Architecture::Wasm32).is_err());
        assert_eq!(
            ph_flags(SectionFlags {
                read: false,
                write: false,
                execute: false,
            }),
            0
        );
        let mut table = StringTable::new();
        assert_eq!(table.add("").unwrap(), 0);
        let mut sink = Vec::new();
        let mut writer = SinkWriter::new(&mut sink);
        writer.write_bytes(&[1, 2, 3]).unwrap();
        assert!(writer.pad_to(2).is_err());
    }

    #[test]
    fn vec_sink_appends_bytes() {
        let mut bytes = Vec::new();
        ElfSink::write_all(&mut bytes, &[1, 2, 3]).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn direct_header_writers_cover_32_bit_overflows() {
        let too_large = u64::from(u32::MAX) + 1;

        macro_rules! assert_shdr_error {
            ($field:ident) => {{
                let mut shdr = Shdr::zeroed();
                shdr.$field = too_large;
                let mut writer = ByteWriter::new(Endianness::Little);
                assert!(shdr.write(&mut writer, PtrWidth::W32).is_err());
            }};
        }
        assert_shdr_error!(flags);
        assert_shdr_error!(addr);
        assert_shdr_error!(offset);
        assert_shdr_error!(size);
        assert_shdr_error!(addralign);
        assert_shdr_error!(entsize);

        macro_rules! assert_phdr_error {
            ($field:ident) => {{
                let mut phdr = Phdr {
                    typ: ElfSegmentType::Load.raw(),
                    flags: ElfSegmentFlags::PF_R.raw(),
                    offset: 0,
                    vaddr: 0,
                    filesz: 0,
                    memsz: 0,
                    align: PAGE_SIZE,
                };
                phdr.$field = too_large;
                let mut writer = ByteWriter::new(Endianness::Little);
                assert!(phdr.write(&mut writer, PtrWidth::W32).is_err());
            }};
        }
        assert_phdr_error!(offset);
        assert_phdr_error!(vaddr);
        assert_phdr_error!(filesz);
        assert_phdr_error!(memsz);
        assert_phdr_error!(align);

        let mut writer = ByteWriter::new(Endianness::Little);
        let ehdr = Ehdr {
            endian: Endianness::Little,
            width: PtrWidth::W32,
            machine: ElfMachine::X86.raw(),
            entry: too_large,
            phnum: 0,
            shoff: 0,
            shnum: 0,
            shstrndx: 0,
        };
        assert!(write_ehdr(&mut writer, &ehdr).is_err());

        let mut writer = ByteWriter::new(Endianness::Little);
        let ehdr = Ehdr {
            entry: 0,
            shoff: too_large,
            ..ehdr
        };
        assert!(write_ehdr(&mut writer, &ehdr).is_err());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture keeps direct symbol and relocation error-edge coverage local"
    )]
    fn direct_symbol_and_relocation_errors_are_covered() {
        let too_large = u64::from(u32::MAX) + 1;
        let mut object = module(TargetSpec::x86());
        let text_name = object.intern(".text").unwrap();
        let text = object
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x1000,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap();
        let name = object.intern("sym").unwrap();
        let symbol = SymbolEntry {
            name,
            value: 0,
            size: 0,
            section: Some(text),
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            flags: SymbolFlags::none(),
        };

        let mut writer = ByteWriter::new(Endianness::Little);
        let invalid_name = SymbolEntry {
            name: Symbol::default(),
            ..symbol.clone()
        };
        let empty_module = module(TargetSpec::x86());
        assert!(
            write_symbol(
                &mut writer,
                &empty_module,
                &mut StringTable::new(),
                &invalid_name,
                PtrWidth::W32
            )
            .is_err()
        );

        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(
            write_symbol(
                &mut writer,
                &object,
                &mut StringTable::new(),
                &SymbolEntry {
                    value: too_large,
                    ..symbol.clone()
                },
                PtrWidth::W32
            )
            .is_err()
        );

        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(
            write_symbol(
                &mut writer,
                &object,
                &mut StringTable::new(),
                &SymbolEntry {
                    size: too_large,
                    ..symbol.clone()
                },
                PtrWidth::W32
            )
            .is_err()
        );

        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(
            write_symbol(
                &mut writer,
                &object,
                &mut StringTable::new(),
                &SymbolEntry {
                    section: Some(SectionId::from_raw(u32::MAX)),
                    ..symbol.clone()
                },
                PtrWidth::W32
            )
            .is_err()
        );

        let mut writer = ByteWriter::new(Endianness::Little);
        write_symbol(
            &mut writer,
            &object,
            &mut StringTable::new(),
            &SymbolEntry {
                section: None,
                kind: SymbolKind::None,
                ..symbol.clone()
            },
            PtrWidth::W32,
        )
        .unwrap();

        let sym = object
            .add_symbol(SymbolEntry {
                flags: SymbolFlags::none(),
                ..symbol
            })
            .unwrap();
        let reloc = Relocation {
            section: text,
            offset: 0,
            symbol: sym,
            kind: RelocKind::Absolute32,
            addend: 0,
        };
        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(
            write_rela(
                &mut writer,
                &object,
                &Relocation {
                    offset: too_large,
                    ..reloc
                },
                PtrWidth::W32
            )
            .is_err()
        );

        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(
            write_rela(
                &mut writer,
                &object,
                &Relocation {
                    symbol: SymbolId::from_raw(u32::MAX),
                    ..reloc
                },
                PtrWidth::W32
            )
            .is_err()
        );
    }

    #[test]
    fn public_writer_reaches_symbol_and_relocation_builder_errors() {
        let too_large = u64::from(u32::MAX) + 1;

        let mut symbol_overflow = module(TargetSpec::x86());
        let text = add_text_section(&mut symbol_overflow);
        let name = symbol_overflow.intern("sym").unwrap();
        symbol_overflow
            .add_symbol(SymbolEntry {
                name,
                value: too_large,
                size: 0,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        assert!(write(&symbol_overflow).is_err());

        let mut reloc_overflow = module(TargetSpec::x86());
        let text = add_text_section(&mut reloc_overflow);
        let name = reloc_overflow.intern("sym").unwrap();
        let symbol = reloc_overflow
            .add_symbol(SymbolEntry {
                name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        reloc_overflow
            .add_relocation(Relocation {
                section: text,
                offset: too_large,
                symbol,
                kind: RelocKind::Absolute32,
                addend: 0,
            })
            .unwrap();
        assert!(write(&reloc_overflow).is_err());

        let mut bad_relocation_section = module(TargetSpec::x86_64());
        let text = add_text_section(&mut bad_relocation_section);
        let name = bad_relocation_section.intern("sym").unwrap();
        let symbol = bad_relocation_section
            .add_symbol(SymbolEntry {
                name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        bad_relocation_section
            .add_relocation(Relocation {
                section: SectionId::from_raw(99),
                offset: 0,
                symbol,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        assert!(write(&bad_relocation_section).is_err());
    }

    #[test]
    fn table_builder_offset_errors_are_covered() {
        let mut object = module(TargetSpec::x86_64());
        let text = add_text_section(&mut object);
        let name = object.intern("sym").unwrap();
        object
            .add_symbol(SymbolEntry {
                name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();

        assert!(build_tables(&object, Endianness::Little, PtrWidth::W64, true, u64::MAX).is_err());
        let symtab_fits_but_strtab_does_not = u64::MAX - (sym_size(PtrWidth::W64) * 2);
        assert!(
            build_tables(
                &object,
                Endianness::Little,
                PtrWidth::W64,
                true,
                symtab_fits_but_strtab_does_not
            )
            .is_err()
        );
    }

    #[test]
    fn relocation_builder_offset_errors_are_covered() {
        let mut object = module(TargetSpec::x86_64());
        let text = add_text_section(&mut object);
        let name = object.intern("sym").unwrap();
        let symbol = object
            .add_symbol(SymbolEntry {
                name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        object
            .add_relocation(Relocation {
                section: text,
                offset: 0,
                symbol,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        let sections: Vec<RealSection<'_>> = object
            .sections()
            .map(|(id, section)| RealSection { id, section })
            .collect();
        let tables = Tables {
            have_symbols: true,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let cursor = u64::MAX - rela_size(PtrWidth::W64) + 1;
        assert!(
            build_relocations(
                &object,
                Endianness::Little,
                PtrWidth::W64,
                &tables,
                SectionLookup::new(&sections),
                cursor
            )
            .is_err()
        );

        let mut bad_target = module(TargetSpec::x86_64());
        let text = add_text_section(&mut bad_target);
        let name = bad_target.intern("bad_target").unwrap();
        let symbol = bad_target
            .add_symbol(SymbolEntry {
                name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        bad_target
            .add_relocation(Relocation {
                section: SectionId::from_raw(99),
                offset: 0,
                symbol,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        let sections: Vec<RealSection<'_>> = bad_target
            .sections()
            .map(|(id, section)| RealSection { id, section })
            .collect();
        assert!(
            build_relocations(
                &bad_target,
                Endianness::Little,
                PtrWidth::W64,
                &tables,
                SectionLookup::new(&sections),
                0
            )
            .is_err()
        );
        let empty_sections: [RealSection<'_>; 0] = [];
        assert!(
            SectionLookup::new(&empty_sections)
                .shndx(SectionId::from_raw(0))
                .is_err()
        );
    }

    #[test]
    fn public_write_to_streams_and_reports_errors() {
        let object = crate::samples::hello_world_x86_64_linux().unwrap();
        let expected = write(&object).unwrap();
        let mut streamed = RecordingSink::new();
        crate::write_to(&object, &mut streamed).unwrap();
        assert_eq!(streamed.bytes, expected);

        assert!(
            crate::write_to(&object, &mut RecordingSink::failing_after(0)).is_err(),
            "failing sink should reject streamed output"
        );

        let unsupported = module(TargetSpec::wasm32());
        let mut ignored = RecordingSink::new();
        assert!(
            crate::write_to(&unsupported, &mut ignored).is_err(),
            "unsupported targets should report object errors"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "direct emit fixtures cover each private layout propagation edge"
    )]
    fn direct_emit_errors_are_covered() {
        let empty_tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let empty_relocs = RelocTables {
            tables: Vec::new(),
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let entry_too_large = Ehdr {
            entry: u64::from(u32::MAX) + 1,
            ..ehdr(PtrWidth::W32)
        };
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf32::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf32::EHDR_SIZE,
                ehdr: entry_too_large,
            })
            .is_err()
        );
        let overflow_phdrs = [Phdr {
            typ: ElfSegmentType::Load.raw(),
            flags: ElfSegmentFlags::PF_R.raw(),
            offset: u64::from(u32::MAX) + 1,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: PAGE_SIZE,
        }];
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &overflow_phdrs,
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf32::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf32::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W32),
            })
            .is_err()
        );

        let section_name = Symbol::default();
        let section = Section {
            name: section_name,
            kind: SectionKind::Text,
            address: 0x1000,
            align: PAGE_SIZE,
            flags: SectionFlags::code(),
            data: vec![0],
            size: 1,
        };
        let sections = [RealSection {
            id: SectionId::from_raw(0),
            section: &section,
        }];
        let layouts = [SecLayout {
            file_offset: 0,
            name_off: 0,
        }];
        assert!(
            emit_vec(&Emit {
                sections: &sections,
                layouts: &layouts,
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: 0,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        let symbol_tables = Tables {
            have_symbols: true,
            symtab_bytes: vec![0],
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &symbol_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        let symbol_tables = Tables {
            have_symbols: true,
            symtab_bytes: vec![0],
            symtab_off: elf64::EHDR_SIZE,
            strtab_bytes: Vec::new(),
            strtab_off: elf64::EHDR_SIZE,
            end: 0,
        };
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &symbol_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        let reloc_tables = RelocTables {
            tables: vec![RelocTable {
                bytes: vec![0],
                offset: 0,
                target_shndx: 1,
            }],
            end: 0,
        };
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &reloc_tables,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[0],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W64),
            })
            .is_err()
        );

        let mut flags_too_large = Shdr::zeroed();
        flags_too_large.flags = u64::from(u32::MAX) + 1;
        let flag_records = [flags_too_large];
        assert!(
            emit_vec(&Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &flag_records,
                shstrtab: &[],
                shstrtab_off: elf32::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf32::EHDR_SIZE,
                ehdr: ehdr(PtrWidth::W32),
            })
            .is_err()
        );
    }

    #[test]
    fn direct_emit_success_and_padding_sink_error_are_covered() {
        let empty_tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let empty_relocs = RelocTables {
            tables: Vec::new(),
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let emit_input = Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &empty_tables,
            relocs: &empty_relocs,
            shoff: elf64::EHDR_SIZE,
            ehdr: ehdr(PtrWidth::W64),
        };
        let emitted = emit_vec(&emit_input).unwrap();
        assert_eq!(
            u64_len(&emitted),
            elf64::EHDR_SIZE + shdr_size(PtrWidth::W64)
        );

        let padded = Emit {
            shstrtab_off: elf64::EHDR_SIZE + 1,
            shoff: elf64::EHDR_SIZE + 1,
            ..emit_input
        };
        assert_emit_sink_error(&padded, 1);
    }

    #[test]
    fn streaming_emit_success_covers_all_payload_groups() {
        let phdrs = [Phdr {
            typ: ElfSegmentType::Load.raw(),
            flags: ElfSegmentFlags::PF_R.raw(),
            offset: 0,
            vaddr: 0,
            filesz: 1,
            memsz: 1,
            align: PAGE_SIZE,
        }];
        let section = Section {
            name: Symbol::default(),
            kind: SectionKind::Text,
            address: 0,
            align: 1,
            flags: SectionFlags::code(),
            data: vec![0],
            size: 1,
        };
        let bss = Section {
            name: Symbol::default(),
            kind: SectionKind::Bss,
            address: 0,
            align: 1,
            flags: SectionFlags::data(),
            data: Vec::new(),
            size: 1,
        };
        let sections = [
            RealSection {
                id: SectionId::from_raw(0),
                section: &section,
            },
            RealSection {
                id: SectionId::from_raw(1),
                section: &bss,
            },
        ];
        let section_off = elf64::EHDR_SIZE + elf64::PHDR_SIZE;
        let layouts = [
            SecLayout {
                file_offset: section_off,
                name_off: 0,
            },
            SecLayout {
                file_offset: section_off + 1,
                name_off: 0,
            },
        ];
        let tables = Tables {
            have_symbols: true,
            symtab_bytes: vec![0],
            symtab_off: section_off + 2,
            strtab_bytes: vec![0],
            strtab_off: section_off + 3,
            end: 0,
        };
        let relocs = RelocTables {
            tables: vec![RelocTable {
                bytes: vec![0],
                offset: section_off + 4,
                target_shndx: 1,
            }],
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let mut sink = RecordingSink::new();
        emit_to(
            &Emit {
                sections: &sections,
                layouts: &layouts,
                phdrs: &phdrs,
                shdrs: &shdrs,
                shstrtab: &[0],
                shstrtab_off: section_off + 1,
                tables: &tables,
                relocs: &relocs,
                shoff: section_off + 5,
                ehdr: Ehdr {
                    phnum: 1,
                    shnum: 1,
                    ..ehdr(PtrWidth::W64)
                },
            },
            &mut sink,
        )
        .unwrap();
        assert!(!sink.bytes.is_empty());
    }

    #[test]
    fn streaming_emit_record_errors_are_covered() {
        let empty_tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let empty_relocs = RelocTables {
            tables: Vec::new(),
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let bad_header = Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf32::EHDR_SIZE,
            tables: &empty_tables,
            relocs: &empty_relocs,
            shoff: elf32::EHDR_SIZE,
            ehdr: Ehdr {
                entry: u64::from(u32::MAX) + 1,
                ..ehdr(PtrWidth::W32)
            },
        };
        assert!(emit_to(&bad_header, &mut RecordingSink::new()).is_err());

        let overflow_program_headers = [Phdr {
            typ: ElfSegmentType::Load.raw(),
            flags: ElfSegmentFlags::PF_R.raw(),
            offset: u64::from(u32::MAX) + 1,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: PAGE_SIZE,
        }];
        let overflow_program_header_emit = Emit {
            phdrs: &overflow_program_headers,
            ehdr: Ehdr {
                phnum: 1,
                ..ehdr(PtrWidth::W32)
            },
            ..bad_header
        };
        assert!(emit_to(&overflow_program_header_emit, &mut RecordingSink::new()).is_err());

        let mut flags_too_large = Shdr::zeroed();
        flags_too_large.flags = u64::from(u32::MAX) + 1;
        let overflow_section_headers = [flags_too_large];
        let overflow_section_header_emit = Emit {
            shdrs: &overflow_section_headers,
            ehdr: ehdr(PtrWidth::W32),
            ..bad_header
        };
        assert!(emit_to(&overflow_section_header_emit, &mut RecordingSink::new()).is_err());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture covers each streaming padding error continuation"
    )]
    fn streaming_emit_padding_errors_are_covered() {
        let empty_tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let empty_relocs = RelocTables {
            tables: Vec::new(),
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let section = Section {
            name: Symbol::default(),
            kind: SectionKind::Text,
            address: 0,
            align: 1,
            flags: SectionFlags::code(),
            data: Vec::new(),
            size: 0,
        };
        let sections = [RealSection {
            id: SectionId::from_raw(0),
            section: &section,
        }];
        let layouts = [SecLayout {
            file_offset: 0,
            name_off: 0,
        }];
        assert_emit_object_error(&Emit {
            sections: &sections,
            layouts: &layouts,
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &empty_tables,
            relocs: &empty_relocs,
            shoff: elf64::EHDR_SIZE,
            ehdr: ehdr(PtrWidth::W64),
        });

        let symtab_backwards = Tables {
            have_symbols: true,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: elf64::EHDR_SIZE,
            end: 0,
        };
        assert_emit_object_error(&Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &symtab_backwards,
            relocs: &empty_relocs,
            shoff: elf64::EHDR_SIZE,
            ehdr: ehdr(PtrWidth::W64),
        });

        let strtab_backwards = Tables {
            have_symbols: true,
            symtab_bytes: vec![0],
            symtab_off: elf64::EHDR_SIZE,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        assert_emit_object_error(&Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &strtab_backwards,
            relocs: &empty_relocs,
            shoff: elf64::EHDR_SIZE,
            ehdr: ehdr(PtrWidth::W64),
        });

        let relocation_backwards = RelocTables {
            tables: vec![RelocTable {
                bytes: Vec::new(),
                offset: 0,
                target_shndx: 1,
            }],
            end: 0,
        };
        assert_emit_object_error(&Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &empty_tables,
            relocs: &relocation_backwards,
            shoff: elf64::EHDR_SIZE,
            ehdr: ehdr(PtrWidth::W64),
        });

        assert_emit_object_error(&Emit {
            sections: &[],
            layouts: &[],
            phdrs: &[],
            shdrs: &shdrs,
            shstrtab: &[],
            shstrtab_off: elf64::EHDR_SIZE,
            tables: &empty_tables,
            relocs: &empty_relocs,
            shoff: 0,
            ehdr: ehdr(PtrWidth::W64),
        });
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture covers sink error propagation at each payload write site"
    )]
    fn emit_payload_write_sites_propagate_sink_errors() {
        let empty_tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 0,
        };
        let empty_relocs = RelocTables {
            tables: Vec::new(),
            end: 0,
        };
        let shdrs = [Shdr::zeroed()];
        let section = Section {
            name: Symbol::default(),
            kind: SectionKind::Text,
            address: 0,
            align: 1,
            flags: SectionFlags::code(),
            data: vec![0],
            size: 1,
        };
        let sections = [RealSection {
            id: SectionId::from_raw(0),
            section: &section,
        }];
        let layouts = [SecLayout {
            file_offset: elf64::EHDR_SIZE,
            name_off: 0,
        }];
        assert_emit_sink_error(
            &Emit {
                sections: &sections,
                layouts: &layouts,
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE + 1,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE + 1,
                ehdr: ehdr(PtrWidth::W64),
            },
            1,
        );

        assert_emit_sink_error(
            &Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[0],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE + 1,
                ehdr: ehdr(PtrWidth::W64),
            },
            1,
        );

        let symtab_tables = Tables {
            have_symbols: true,
            symtab_bytes: vec![0],
            symtab_off: elf64::EHDR_SIZE,
            strtab_bytes: Vec::new(),
            strtab_off: elf64::EHDR_SIZE + 1,
            end: 0,
        };
        assert_emit_sink_error(
            &Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &symtab_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE + 1,
                ehdr: ehdr(PtrWidth::W64),
            },
            2,
        );

        let strtab_tables = Tables {
            have_symbols: true,
            symtab_bytes: Vec::new(),
            symtab_off: elf64::EHDR_SIZE,
            strtab_bytes: vec![0],
            strtab_off: elf64::EHDR_SIZE,
            end: 0,
        };
        assert_emit_sink_error(
            &Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &strtab_tables,
                relocs: &empty_relocs,
                shoff: elf64::EHDR_SIZE + 1,
                ehdr: ehdr(PtrWidth::W64),
            },
            3,
        );

        let reloc_tables = RelocTables {
            tables: vec![RelocTable {
                bytes: vec![0],
                offset: elf64::EHDR_SIZE,
                target_shndx: 1,
            }],
            end: 0,
        };
        assert_emit_sink_error(
            &Emit {
                sections: &[],
                layouts: &[],
                phdrs: &[],
                shdrs: &shdrs,
                shstrtab: &[],
                shstrtab_off: elf64::EHDR_SIZE,
                tables: &empty_tables,
                relocs: &reloc_tables,
                shoff: elf64::EHDR_SIZE + 1,
                ehdr: ehdr(PtrWidth::W64),
            },
            2,
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture keeps high-level writer construction error-edge coverage local"
    )]
    fn writer_build_errors_are_covered() {
        let mut missing_section = module(TargetSpec::x86_64());
        let seg_name = missing_section.intern("LOAD").unwrap();
        missing_section.add_segment(Segment {
            name: seg_name,
            address: 0,
            vm_size: 0,
            flags: SectionFlags::read_only(),
            sections: vec![SectionId::from_raw(99)],
        });
        assert!(write(&missing_section).is_err());

        let mut vm_overflow = module(TargetSpec::x86_64());
        let name = vm_overflow.intern(".text").unwrap();
        let text = vm_overflow
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: u64::MAX,
                align: 1,
                flags: SectionFlags::code(),
                data: Vec::new(),
                size: 1,
            })
            .unwrap();
        let seg_name = vm_overflow.intern("LOAD").unwrap();
        vm_overflow.add_segment(Segment {
            name: seg_name,
            address: 0,
            vm_size: 0,
            flags: SectionFlags::read_only(),
            sections: vec![text],
        });
        assert!(write(&vm_overflow).is_err());

        let mut file_overflow = module(TargetSpec::x86_64());
        let name = file_overflow.intern(".text").unwrap();
        let text = file_overflow
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: u64::MAX,
                align: 1,
                flags: SectionFlags::code(),
                data: vec![0],
                size: 0,
            })
            .unwrap();
        let seg_name = file_overflow.intern("LOAD").unwrap();
        file_overflow.add_segment(Segment {
            name: seg_name,
            address: 0,
            vm_size: 0,
            flags: SectionFlags::read_only(),
            sections: vec![text],
        });
        assert!(write(&file_overflow).is_err());

        let mut many_program_headers = module(TargetSpec::x86_64());
        let seg_name = many_program_headers.intern("LOAD").unwrap();
        for _ in 0..=u16::MAX {
            many_program_headers.add_segment(Segment {
                name: seg_name,
                address: 0,
                vm_size: 0,
                flags: SectionFlags::read_only(),
                sections: Vec::new(),
            });
        }
        assert!(write(&many_program_headers).is_err());

        let mut many_section_headers = module(TargetSpec::x86_64());
        let name = many_section_headers.intern(".x").unwrap();
        for _ in 0..(usize::from(u16::MAX) - 1) {
            many_section_headers
                .add_section(Section {
                    name,
                    kind: SectionKind::Other,
                    address: 0,
                    align: 1,
                    flags: SectionFlags {
                        read: false,
                        write: false,
                        execute: false,
                    },
                    data: Vec::new(),
                    size: 0,
                })
                .unwrap();
        }
        assert!(write(&many_section_headers).is_err());

        let mut section_end = module(TargetSpec::x86_64());
        let name = section_end.intern(".debug").unwrap();
        section_end
            .add_section(Section {
                name,
                kind: SectionKind::Debug,
                address: 0,
                align: u64::MAX,
                flags: SectionFlags {
                    read: false,
                    write: false,
                    execute: false,
                },
                data: vec![0],
                size: 1,
            })
            .unwrap();
        assert!(write(&section_end).is_err());
    }

    fn add_text_section(module: &mut ObjectModule) -> SectionId {
        let text_name = module.intern(".text").unwrap();
        module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x1000,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap()
    }

    const fn ehdr(width: PtrWidth) -> Ehdr {
        Ehdr {
            endian: Endianness::Little,
            width,
            machine: ElfMachine::X86_64.raw(),
            entry: 0,
            phnum: 0,
            shoff: 0,
            shnum: 0,
            shstrndx: 0,
        }
    }

    #[test]
    fn automatic_program_headers_cover_allocated_sections() {
        let mut module = module(TargetSpec::x86_64());
        let text_name = module.intern(".text").unwrap();
        module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x40_1000,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap();
        let bss_name = module.intern(".bss").unwrap();
        module
            .add_section(Section {
                name: bss_name,
                kind: SectionKind::Bss,
                address: 0x40_2000,
                align: PAGE_SIZE,
                flags: SectionFlags::data(),
                data: Vec::new(),
                size: 16,
            })
            .unwrap();
        let bytes = write(&module).unwrap();
        assert!(bytes.starts_with(&MAGIC));
    }

    #[test]
    fn writer_rejects_incongruent_allocated_section() {
        let mut module = module(TargetSpec::x86_64());
        let name = module.intern(".text").unwrap();
        module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: 0x40_1001,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap();
        assert!(write(&module).is_err());
    }

    #[test]
    fn writer_propagates_section_header_errors() {
        let mut module = module(TargetSpec::x86_64());
        module
            .add_section(Section {
                name: Symbol::default(),
                kind: SectionKind::Other,
                address: 0,
                align: 1,
                flags: SectionFlags {
                    read: false,
                    write: false,
                    execute: false,
                },
                data: Vec::new(),
                size: 0,
            })
            .unwrap();
        assert!(write(&module).is_err());
    }

    #[test]
    fn symbols_without_relocations_and_symbol_forms_are_covered() {
        let mut module = module(TargetSpec::x86_64());
        let text_name = module.intern(".text").unwrap();
        let text = module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x40_1000,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap();
        let weak_name = module.intern("weak_obj").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: weak_name,
                value: 0x40_1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Object,
                binding: SymbolBinding::Weak,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let section_name = module.intern("section_sym").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: section_name,
                value: 0,
                size: 0,
                section: Some(text),
                kind: SymbolKind::Section,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let undef_name = module.intern("extern_sym").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: undef_name,
                value: 0,
                size: 0,
                section: None,
                kind: SymbolKind::None,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::imported(),
            })
            .unwrap();
        let bytes = write(&module).unwrap();
        assert!(bytes.starts_with(&MAGIC));
    }

    #[test]
    fn relocation_table_disabled_path_is_covered() {
        let module = module(TargetSpec::x86_64());
        let tables = Tables {
            have_symbols: false,
            symtab_bytes: Vec::new(),
            symtab_off: 0,
            strtab_bytes: Vec::new(),
            strtab_off: 0,
            end: 5,
        };
        let sections: [RealSection<'_>; 0] = [];
        let relocs = build_relocations(
            &module,
            Endianness::Little,
            PtrWidth::W64,
            &tables,
            SectionLookup::new(&sections),
            5,
        )
        .unwrap();
        assert_eq!(relocs.end, 5);
    }

    #[test]
    fn relocation_type_mapping_is_covered() {
        let cases = [
            (Architecture::X86_64, RelocKind::Relative32, 2),
            (Architecture::X86_64, RelocKind::GotRelative, 9),
            (Architecture::X86_64, RelocKind::PltRelative, 4),
            (Architecture::X86, RelocKind::Relative32, 2),
            (Architecture::Aarch64, RelocKind::Absolute32, 258),
            (Architecture::Aarch64, RelocKind::Relative32, 261),
            (Architecture::Arm, RelocKind::Absolute32, 2),
            (Architecture::Arm, RelocKind::Relative32, 3),
            (Architecture::Riscv64, RelocKind::Absolute64, 2),
            (Architecture::Riscv64, RelocKind::Relative32, 39),
            (Architecture::PowerPc64, RelocKind::Absolute64, 38),
            (Architecture::PowerPc64, RelocKind::Relative32, 26),
            (Architecture::Mips, RelocKind::Absolute32, 2),
            (Architecture::Mips64, RelocKind::Absolute32, 2),
            (Architecture::Mips64, RelocKind::Absolute64, 18),
            (Architecture::S390x, RelocKind::Absolute64, 22),
            (Architecture::S390x, RelocKind::Relative32, 5),
            (Architecture::LoongArch64, RelocKind::Absolute64, 2),
            (Architecture::Sparc64, RelocKind::Absolute64, 32),
            (Architecture::Other(0), RelocKind::Other(77), 77),
            (Architecture::Other(0), RelocKind::Absolute64, 1),
            (Architecture::Other(0), RelocKind::Absolute32, 1),
            (Architecture::Other(0), RelocKind::Relative32, 2),
            (Architecture::Other(0), RelocKind::Relative64, 0),
            (Architecture::Other(0), RelocKind::GotRelative, 0),
            (Architecture::Other(0), RelocKind::PltRelative, 0),
        ];
        for (arch, kind, raw) in cases {
            assert_eq!(relocation_type(arch, kind), raw);
        }
    }

    #[test]
    fn direct_writers_cover_32_bit_relocation_addend_error() {
        let mut module = module(TargetSpec::x86());
        let name = module.intern(".text").unwrap();
        let text = module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: 0x1000,
                align: PAGE_SIZE,
                flags: SectionFlags::code(),
                data: vec![0xc3],
                size: 1,
            })
            .unwrap();
        let sym_name = module.intern("sym").unwrap();
        let sym = module
            .add_symbol(SymbolEntry {
                name: sym_name,
                value: 0x1000,
                size: 1,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let reloc = Relocation {
            section: text,
            offset: 0,
            symbol: sym,
            kind: RelocKind::Absolute32,
            addend: i64::from(i32::MAX) + 1,
        };
        let mut writer = ByteWriter::new(Endianness::Little);
        assert!(write_rela(&mut writer, &module, &reloc, PtrWidth::W32).is_err());
    }
}
