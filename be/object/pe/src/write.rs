//! Serializes an [`ObjectModule`] into a canonical, loadable PE executable.

use crate::consts::{
    COFF_HEADER_SIZE, DIRECTORY_BASERELOC, DIRECTORY_DEBUG, DIRECTORY_EXPORT, DIRECTORY_IMPORT,
    DOS_MAGIC, E_LFANEW_OFFSET, FILE_ALIGNMENT, IMAGE_BASE32, IMAGE_BASE64,
    IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386, NUMBER_OF_DIRECTORIES,
    OPTIONAL_HEADER_SIZE_PE32, OPTIONAL_HEADER_SIZE_PE32PLUS, OPTIONAL_MAGIC_PE32,
    OPTIONAL_MAGIC_PE32PLUS, PE_RELOC_AMD64_ADDR32, PE_RELOC_AMD64_ADDR64, PE_RELOC_AMD64_REL32,
    PE_RELOC_ARM_ADDR32, PE_RELOC_ARM_REL32, PE_RELOC_ARM64_ADDR32, PE_RELOC_ARM64_ADDR64,
    PE_RELOC_ARM64_REL32, PE_RELOC_I386_DIR32, PE_RELOC_I386_REL32, PE_SIGNATURE, SCN_CNT_CODE,
    SCN_CNT_INITIALIZED_DATA, SCN_CNT_UNINITIALIZED_DATA, SCN_MEM_EXECUTE, SCN_MEM_READ,
    SCN_MEM_WRITE, SECTION_ALIGNMENT, SECTION_HEADER_SIZE, SUBSYSTEM_WINDOWS_CUI,
    SYM_CLASS_EXTERNAL, SYM_CLASS_STATIC, SYM_DTYPE_FUNCTION,
};
use stratum_oir::{
    Architecture, ByteWriter, DebugFileFormat, Error, ExternalDebugFile, Import, ObjectModule,
    PtrWidth, RelocKind, Relocation, Result, Section, SectionFlags, SectionId, SectionKind,
    SymbolBinding, SymbolId, SymbolKind,
};

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const DOS_HEADER_SIZE: u32 = 0x40;
const DEBUG_DIRECTORY_SIZE: u32 = 28;
const DEBUG_DIRECTORY_SIZE_USIZE: usize = 28;

const fn align_up(value: u32, align: u32) -> u32 {
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
        Architecture::X86 => Ok(IMAGE_FILE_MACHINE_I386),
        Architecture::Arm => Ok(IMAGE_FILE_MACHINE_ARMNT),
        Architecture::X86_64 => Ok(IMAGE_FILE_MACHINE_AMD64),
        Architecture::Aarch64 => Ok(IMAGE_FILE_MACHINE_ARM64),
        _ => Err(Error::Unsupported("PE target architecture")),
    }
}

fn u32_of(value: usize, what: &'static str) -> Result<u32> {
    match u32::try_from(value) {
        Ok(value) => Ok(value),
        Err(_) => Err(Error::ValueOutOfRange(what)),
    }
}

fn rva(section: &OutputSection) -> Result<u32> {
    u32::try_from(section.address).map_err(|_| Error::ValueOutOfRange("section RVA"))
}

fn virtual_size(section: &OutputSection) -> Result<u32> {
    let size = section.vm_size().max(section.file_size());
    u32::try_from(size).map_err(|_| Error::ValueOutOfRange("section virtual size"))
}

fn characteristics(section: &OutputSection) -> u32 {
    let mut chars = 0;
    if section.kind == SectionKind::Bss {
        chars |= SCN_CNT_UNINITIALIZED_DATA;
    } else if section.flags.execute {
        chars |= SCN_CNT_CODE;
    } else {
        chars |= SCN_CNT_INITIALIZED_DATA;
    }
    if section.flags.read {
        chars |= SCN_MEM_READ;
    }
    if section.flags.write {
        chars |= SCN_MEM_WRITE;
    }
    if section.flags.execute {
        chars |= SCN_MEM_EXECUTE;
    }
    chars
}

#[derive(Debug, Clone)]
struct OutputSection {
    origin: Option<SectionId>,
    name: String,
    kind: SectionKind,
    address: u64,
    flags: SectionFlags,
    data: Vec<u8>,
    size: u64,
}

impl OutputSection {
    fn from_module(module: &ObjectModule, id: SectionId, section: &Section) -> Result<Self> {
        Ok(Self {
            origin: Some(id),
            name: module.resolve(section.name)?.to_string(),
            kind: section.kind,
            address: section.address,
            flags: section.flags,
            data: section.data.clone(),
            size: section.size,
        })
    }

    fn synthetic(
        name: &str,
        kind: SectionKind,
        address: u32,
        flags: SectionFlags,
        data: Vec<u8>,
    ) -> Self {
        let size = data.len() as u64;
        Self {
            origin: None,
            name: name.to_string(),
            kind,
            address: u64::from(address),
            flags,
            data,
            size,
        }
    }

    fn file_size(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(0)
    }

    const fn vm_size(&self) -> u64 {
        self.size
    }
}

/// Computed file/RVA placement for one section.
struct Placement {
    rva: u32,
    virtual_size: u32,
    file_offset: u32,
    raw_size: u32,
}

fn name_bytes(section: &OutputSection) -> Result<[u8; 8]> {
    let raw = section.name.as_bytes();
    if raw.len() > 8 {
        return Err(Error::Unsupported("PE section name longer than 8 bytes"));
    }
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(raw) {
        *slot = *byte;
    }
    Ok(out)
}

fn output_sections(module: &ObjectModule, is_pe32_plus: bool) -> Result<Vec<OutputSection>> {
    let mut sections = Vec::with_capacity(module.section_count().saturating_add(4));
    for (id, section) in module.sections() {
        sections.push(OutputSection::from_module(module, id, section)?);
    }

    if !module.imports().is_empty() && !has_section(&sections, ".idata") {
        let address = next_synthetic_rva(&sections)?;
        let data = build_import_section(module, address, is_pe32_plus)?;
        let section = OutputSection::synthetic(
            ".idata",
            SectionKind::Data,
            address,
            SectionFlags::data(),
            data,
        );
        sections.push(section);
    }

    if !module.exports().is_empty() && !has_section(&sections, ".edata") {
        let address = next_synthetic_rva(&sections)?;
        let data = build_export_section(module, address)?;
        let section = OutputSection::synthetic(
            ".edata",
            SectionKind::ReadOnlyData,
            address,
            SectionFlags::read_only(),
            data,
        );
        sections.push(section);
    }

    if has_base_relocations(module) && !has_section(&sections, ".reloc") {
        let address = next_synthetic_rva(&sections)?;
        let data = build_base_reloc_section(module)?;
        let section = OutputSection::synthetic(
            ".reloc",
            SectionKind::Other,
            address,
            SectionFlags::read_only(),
            data,
        );
        sections.push(section);
    }

    if let Some(reference) = pdb_debug_file(module)
        && !has_section(&sections, ".cvdbg")
    {
        let address = next_synthetic_rva(&sections)?;
        let data = build_debug_section(reference, address)?;
        let section = OutputSection::synthetic(
            ".cvdbg",
            SectionKind::Debug,
            address,
            SectionFlags::read_only(),
            data,
        );
        sections.push(section);
    }

    Ok(sections)
}

fn has_section(sections: &[OutputSection], name: &str) -> bool {
    sections.iter().any(|section| section.name == name)
}

fn next_synthetic_rva(sections: &[OutputSection]) -> Result<u32> {
    let mut next = SECTION_ALIGNMENT;
    for section in sections {
        let start = rva(section)?;
        let end = start
            .checked_add(virtual_size(section)?)
            .ok_or(Error::ValueOutOfRange("section RVA"))?;
        next = next.max(align_up(end, SECTION_ALIGNMENT));
    }
    Ok(next)
}

fn checked_add_u32(lhs: u32, rhs: u32, what: &'static str) -> Result<u32> {
    lhs.checked_add(rhs).ok_or(Error::ValueOutOfRange(what))
}

fn checked_mul_u32(lhs: u32, rhs: u32, what: &'static str) -> Result<u32> {
    lhs.checked_mul(rhs).ok_or(Error::ValueOutOfRange(what))
}

#[derive(Clone)]
struct ImportSpec {
    name: String,
    ordinal: Option<u16>,
    hint: u16,
}

struct ImportGroup {
    library: String,
    imports: Vec<ImportSpec>,
}

struct ImportGroupLayout {
    lookup_off: u32,
    addr_off: u32,
    dll_off: u32,
    name_offsets: Vec<u32>,
}

fn build_import_section(
    module: &ObjectModule,
    section_rva: u32,
    is_pe32_plus: bool,
) -> Result<Vec<u8>> {
    let groups = import_groups(module)?;
    let thunk_width = if is_pe32_plus { 8 } else { 4 };
    let descriptor_count = u32_of(groups.len().saturating_add(1), "import descriptors")?;
    let mut cursor = checked_mul_u32(descriptor_count, 20, "import descriptors")?;
    let mut layouts = Vec::with_capacity(groups.len());

    for group in &groups {
        let entry_count = u32_of(group.imports.len().saturating_add(1), "import thunks")?;
        let entries_size = checked_mul_u32(entry_count, thunk_width, "import thunks")?;
        let lookup_off = cursor;
        cursor = checked_add_u32(cursor, entries_size, "import lookup table")?;
        let addr_off = cursor;
        cursor = checked_add_u32(cursor, entries_size, "import address table")?;
        layouts.push(ImportGroupLayout {
            lookup_off,
            addr_off,
            dll_off: 0,
            name_offsets: Vec::new(),
        });
    }

    for (group, layout) in groups.iter().zip(&mut layouts) {
        let mut name_offsets = Vec::with_capacity(group.imports.len());
        for import in &group.imports {
            if import.ordinal.is_some() {
                name_offsets.push(0);
                continue;
            }
            if import.name.is_empty() {
                return Err(Error::Malformed("named import has empty name"));
            }
            name_offsets.push(cursor);
            let name_len = u32_of(import.name.len(), "import name")?;
            let raw_len = checked_add_u32(name_len, 3, "import name")?;
            cursor = checked_add_u32(cursor, align_even(raw_len), "import name")?;
        }
        let dll_off = cursor;
        let dll_len = u32_of(group.library.len(), "import library")?;
        cursor = checked_add_u32(cursor, dll_len.saturating_add(1), "import library")?;
        layout.dll_off = dll_off;
        layout.name_offsets = name_offsets;
    }

    let mut w = ByteWriter::new(stratum_oir::Endianness::Little);
    for layout in &layouts {
        let lookup_rva = checked_add_u32(section_rva, layout.lookup_off, "import lookup RVA")?;
        w.write_u32(lookup_rva);
        w.write_u32(0);
        w.write_u32(0);
        let dll_rva = checked_add_u32(section_rva, layout.dll_off, "import DLL RVA")?;
        w.write_u32(dll_rva);
        let addr_rva = checked_add_u32(section_rva, layout.addr_off, "import address RVA")?;
        w.write_u32(addr_rva);
    }
    w.write_zeros(20);

    for (group, layout) in groups.iter().zip(&layouts) {
        write_import_thunks(&mut w, section_rva, group, layout, is_pe32_plus)?;
        write_import_thunks(&mut w, section_rva, group, layout, is_pe32_plus)?;
    }

    for (group, layout) in groups.iter().zip(&layouts) {
        for (import, name_off) in group.imports.iter().zip(&layout.name_offsets) {
            if import.ordinal.is_some() {
                continue;
            }
            pad_to(&mut w, *name_off)?;
            w.write_u16(import.hint);
            w.write_bytes(import.name.as_bytes());
            w.write_u8(0);
            if !w.position().is_multiple_of(2) {
                w.write_u8(0);
            }
        }
        pad_to(&mut w, layout.dll_off)?;
        w.write_bytes(group.library.as_bytes());
        w.write_u8(0);
    }

    let bytes = w.finish()?;
    ensure_section_size(bytes.len(), cursor, "import section size")?;
    Ok(bytes)
}

fn import_groups(module: &ObjectModule) -> Result<Vec<ImportGroup>> {
    let mut groups: Vec<ImportGroup> = Vec::new();
    for import in module.imports() {
        let library = module.resolve(import.library)?;
        let spec = import_spec(module, *import)?;
        if let Some(group) = groups.iter_mut().find(|group| group.library == library) {
            group.imports.push(spec);
        } else {
            groups.push(ImportGroup {
                library: library.to_string(),
                imports: alloc::vec![spec],
            });
        }
    }
    Ok(groups)
}

fn import_spec(module: &ObjectModule, import: Import) -> Result<ImportSpec> {
    let name = module.resolve(import.name)?;
    Ok(ImportSpec {
        name: name.to_string(),
        ordinal: import.ordinal,
        hint: import.hint.unwrap_or(0),
    })
}

fn write_import_thunks(
    w: &mut ByteWriter,
    section_rva: u32,
    group: &ImportGroup,
    layout: &ImportGroupLayout,
    is_pe32_plus: bool,
) -> Result<()> {
    for (import, name_off) in group.imports.iter().zip(&layout.name_offsets) {
        let value = import_thunk_value(section_rva, import, *name_off, is_pe32_plus)?;
        if is_pe32_plus {
            w.write_u64(value);
        } else {
            w.write_u32(u32::try_from(value).map_err(|_| Error::ValueOutOfRange("import thunk"))?);
        }
    }
    if is_pe32_plus {
        w.write_u64(0);
    } else {
        w.write_u32(0);
    }
    Ok(())
}

fn import_thunk_value(
    section_rva: u32,
    import: &ImportSpec,
    name_off: u32,
    is_pe32_plus: bool,
) -> Result<u64> {
    if let Some(ordinal) = import.ordinal {
        let flag = if is_pe32_plus {
            0x8000_0000_0000_0000_u64
        } else {
            0x8000_0000_u64
        };
        return Ok(flag | u64::from(ordinal));
    }
    let value = checked_add_u32(section_rva, name_off, "import name RVA")?;
    Ok(u64::from(value))
}

const fn align_even(value: u32) -> u32 {
    value + (value & 1)
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct ExportSpec {
    name: String,
    address: u32,
    ordinal: u16,
}

struct ExportLayout {
    base: u16,
    function_count: u32,
    name_count: u32,
    dll_name_off: u32,
    function_table_off: u32,
    name_pointer_table_off: u32,
    ordinal_table_off: u32,
    name_offsets: Vec<u32>,
    section_size: u32,
}

struct ExportTableOffsets {
    names: u32,
    ordinals: u32,
    end: u32,
}

fn build_export_section(module: &ObjectModule, section_rva: u32) -> Result<Vec<u8>> {
    let mut exports = export_specs(module)?;
    exports.sort();
    let layout = export_layout(&exports)?;

    let mut w = ByteWriter::new(stratum_oir::Endianness::Little);
    write_export_header(&mut w, section_rva, &layout)?;
    w.write_bytes(b"stratum.exe\0");
    pad_to(&mut w, layout.function_table_off)?;
    write_export_tables(&mut w, section_rva, &exports, &layout)?;
    let bytes = w.finish()?;
    ensure_section_size(bytes.len(), layout.section_size, "export section size")?;
    Ok(bytes)
}

fn export_layout(exports: &[ExportSpec]) -> Result<ExportLayout> {
    let base = exports
        .iter()
        .map(|export| export.ordinal)
        .min()
        .ok_or(Error::Malformed("empty export table"))?;
    let max_ordinal = exports
        .iter()
        .map(|export| export.ordinal)
        .max()
        .ok_or(Error::Malformed("empty export table"))?;
    let function_count = u32::from(max_ordinal.saturating_sub(base)).saturating_add(1);
    let dll_name_off = 40_u32;
    let dll_name_len = u32_of("stratum.exe".len(), "export DLL name")?.saturating_add(1);
    let function_table_off = align_up(
        checked_add_u32(dll_name_off, dll_name_len, "export DLL name")?,
        4,
    );
    let name_count = u32_of(exports.len(), "export name count")?;
    let table_offsets = export_table_offsets(function_table_off, function_count, name_count)?;
    let mut cursor = table_offsets.end;
    let mut name_offsets = Vec::with_capacity(exports.len());
    for export in exports {
        name_offsets.push(cursor);
        let name_len = u32_of(export.name.len(), "export name")?.saturating_add(1);
        cursor = checked_add_u32(cursor, name_len, "export name")?;
    }
    Ok(ExportLayout {
        base,
        function_count,
        name_count,
        dll_name_off,
        function_table_off,
        name_pointer_table_off: table_offsets.names,
        ordinal_table_off: table_offsets.ordinals,
        name_offsets,
        section_size: cursor,
    })
}

fn export_table_offsets(
    functions_off: u32,
    function_count: u32,
    name_count: u32,
) -> Result<ExportTableOffsets> {
    let address_bytes = checked_mul_u32(function_count, 4, "export address table")?;
    let names = checked_add_u32(functions_off, address_bytes, "export address table")?;
    let name_bytes = checked_mul_u32(name_count, 4, "export name pointer table")?;
    let ordinals = checked_add_u32(names, name_bytes, "export name pointer table")?;
    let ordinal_bytes = checked_mul_u32(name_count, 2, "export ordinal table")?;
    let end = checked_add_u32(ordinals, ordinal_bytes, "export ordinal table")?;
    Ok(ExportTableOffsets {
        names,
        ordinals,
        end,
    })
}

fn write_export_header(w: &mut ByteWriter, section_rva: u32, layout: &ExportLayout) -> Result<()> {
    w.write_u32(0);
    w.write_u32(0);
    w.write_u16(0);
    w.write_u16(0);
    let dll_name_rva = checked_add_u32(section_rva, layout.dll_name_off, "export DLL name RVA")?;
    w.write_u32(dll_name_rva);
    w.write_u32(u32::from(layout.base));
    w.write_u32(layout.function_count);
    w.write_u32(layout.name_count);
    for (offset, what) in [
        (layout.function_table_off, "export function table RVA"),
        (layout.name_pointer_table_off, "export name table RVA"),
        (layout.ordinal_table_off, "export ordinal table RVA"),
    ] {
        write_export_rva(w, section_rva, offset, what)?;
    }
    Ok(())
}

fn write_export_rva(
    w: &mut ByteWriter,
    section_rva: u32,
    offset: u32,
    what: &'static str,
) -> Result<()> {
    let rva = checked_add_u32(section_rva, offset, what)?;
    w.write_u32(rva);
    Ok(())
}

fn write_export_tables(
    w: &mut ByteWriter,
    section_rva: u32,
    exports: &[ExportSpec],
    layout: &ExportLayout,
) -> Result<()> {
    for ordinal_index in 0..layout.function_count {
        let ordinal = layout.base.saturating_add(
            u16::try_from(ordinal_index).map_err(|_| Error::ValueOutOfRange("export ordinal"))?,
        );
        let address = exports
            .iter()
            .find_map(|export| (export.ordinal == ordinal).then_some(export.address))
            .unwrap_or(0);
        w.write_u32(address);
    }
    for name_off in &layout.name_offsets {
        w.write_u32(checked_add_u32(section_rva, *name_off, "export name RVA")?);
    }
    for export in exports {
        w.write_u16(export.ordinal.saturating_sub(layout.base));
    }
    for export in exports {
        w.write_bytes(export.name.as_bytes());
        w.write_u8(0);
    }
    Ok(())
}

fn export_specs(module: &ObjectModule) -> Result<Vec<ExportSpec>> {
    let mut used = Vec::new();
    for export in module.exports() {
        if let Some(ordinal) = export.ordinal {
            if used.contains(&ordinal) {
                return Err(Error::Malformed("duplicate export ordinal"));
            }
            used.push(ordinal);
        }
    }
    let base = used.iter().copied().min().unwrap_or(1);
    let mut next = base;
    let mut specs = Vec::with_capacity(module.exports().len());
    for export in module.exports() {
        let ordinal = if let Some(ordinal) = export.ordinal {
            ordinal
        } else {
            while used.contains(&next) {
                next = next
                    .checked_add(1)
                    .ok_or(Error::ValueOutOfRange("export ordinal"))?;
            }
            let assigned = next;
            used.push(assigned);
            assigned
        };
        next = next.max(
            ordinal
                .checked_add(1)
                .ok_or(Error::ValueOutOfRange("export ordinal"))?,
        );
        specs.push(ExportSpec {
            name: module.resolve(export.name)?.to_string(),
            address: u32::try_from(export.address)
                .map_err(|_| Error::ValueOutOfRange("export address"))?,
            ordinal,
        });
    }
    Ok(specs)
}

fn has_base_relocations(module: &ObjectModule) -> bool {
    module
        .relocations()
        .any(|(_, reloc)| base_reloc_type(reloc.kind).is_some())
}

fn build_base_reloc_section(module: &ObjectModule) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    for (_, reloc) in module.relocations() {
        if let Some(kind) = base_reloc_type(reloc.kind) {
            let section = module
                .sections()
                .find_map(|(id, section)| (id == reloc.section).then_some(section))
                .ok_or(Error::Malformed("relocation references missing section"))?;
            let offset =
                u32::try_from(reloc.offset).map_err(|_| Error::ValueOutOfRange("reloc offset"))?;
            let rva = u32::try_from(section.address)
                .map_err(|_| Error::ValueOutOfRange("reloc RVA"))?
                .checked_add(offset)
                .ok_or(Error::ValueOutOfRange("reloc RVA"))?;
            entries.push((rva, kind));
        }
    }
    entries.sort_unstable();

    let mut w = ByteWriter::new(stratum_oir::Endianness::Little);
    let mut index = 0usize;
    while let Some((page_rva, _)) = entries.get(index).copied() {
        let page = page_rva & 0xffff_f000;
        let block_start = index;
        while entries
            .get(index)
            .is_some_and(|(rva, _)| (*rva & 0xffff_f000) == page)
        {
            index = index.saturating_add(1);
        }
        let count = index.saturating_sub(block_start);
        let padded_count = if count.is_multiple_of(2) {
            count
        } else {
            count.saturating_add(1)
        };
        let padded_count_u32 = u32_of(padded_count, "base reloc count")?;
        let entry_bytes = checked_mul_u32(padded_count_u32, 2, "base reloc block")?;
        let block_size = 8_u32
            .checked_add(entry_bytes)
            .ok_or(Error::ValueOutOfRange("base reloc block"))?;
        w.write_u32(page);
        w.write_u32(block_size);
        for (rva, kind) in entries
            .get(block_start..index)
            .ok_or(Error::Malformed("base reloc block"))?
        {
            let within_page = u16::try_from(*rva - page)
                .map_err(|_| Error::ValueOutOfRange("base reloc offset"))?;
            w.write_u16((u16::from(*kind) << 12) | within_page);
        }
        if count != padded_count {
            w.write_u16(0);
        }
    }
    w.finish()
}

fn pdb_debug_file(module: &ObjectModule) -> Option<&ExternalDebugFile> {
    for file in module.debug().external_files() {
        if file.format() != DebugFileFormat::Pdb {
            continue;
        }
        return Some(file);
    }
    None
}

fn build_debug_section(reference: &ExternalDebugFile, section_rva: u32) -> Result<Vec<u8>> {
    let guid = reference
        .pdb_guid()
        .ok_or(Error::Malformed("PDB debug identifier must be 16 bytes"))?;
    let age = reference
        .pdb_age()
        .ok_or(Error::Malformed("PDB debug age is missing"))?;
    let mut rsds = Vec::with_capacity(
        24usize
            .checked_add(reference.path().len())
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ValueOutOfRange("RSDS record"))?,
    );
    rsds.extend_from_slice(b"RSDS");
    rsds.extend_from_slice(&guid);
    rsds.extend_from_slice(&age.to_le_bytes());
    rsds.extend_from_slice(reference.path().as_bytes());
    rsds.push(0);

    let mut w = ByteWriter::new(stratum_oir::Endianness::Little);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u16(0);
    w.write_u16(0);
    w.write_u32(IMAGE_DEBUG_TYPE_CODEVIEW);
    w.write_u32(u32_of(rsds.len(), "RSDS record")?);
    let raw_rva = checked_add_u32(section_rva, DEBUG_DIRECTORY_SIZE, "debug data RVA")?;
    w.write_u32(raw_rva);
    w.write_u32(0);
    w.write_bytes(&rsds);
    w.finish()
}

fn ensure_section_size(actual: usize, expected: u32, what: &'static str) -> Result<()> {
    if u32_of(actual, what)? != expected {
        return Err(Error::Malformed("section size mismatch"));
    }
    Ok(())
}

fn base_reloc_type(kind: RelocKind) -> Option<u8> {
    match kind {
        RelocKind::Absolute64 => Some(10),
        RelocKind::Absolute32 => Some(3),
        _ => None,
    }
}

/// Serializes `module` to PE bytes.
///
/// # Errors
///
/// Returns an error if the architecture is unsupported, a section name exceeds eight bytes,
/// or any computed offset or size exceeds the 32-bit fields PE provides.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    let target = module.target();
    let machine = machine(target.arch)?;
    let is_pe32_plus = target.ptr_width == PtrWidth::W64;
    let optional_size = if is_pe32_plus {
        OPTIONAL_HEADER_SIZE_PE32PLUS
    } else {
        OPTIONAL_HEADER_SIZE_PE32
    };
    let mut sections = output_sections(module, is_pe32_plus)?;
    let section_count =
        u16::try_from(sections.len()).map_err(|_| Error::ValueOutOfRange("PE section count"))?;

    let header_end = DOS_HEADER_SIZE
        .checked_add(4)
        .and_then(|v| v.checked_add(COFF_HEADER_SIZE))
        .and_then(|v| v.checked_add(u32::from(optional_size)))
        .and_then(|v| v.checked_add(SECTION_HEADER_SIZE * u32::from(section_count)))
        .ok_or(Error::ValueOutOfRange("PE header size"))?;
    let size_of_headers = align_up(header_end, FILE_ALIGNMENT);

    let mut placements: Vec<Placement> = Vec::with_capacity(sections.len());
    let mut file_cursor = size_of_headers;
    for section in &sections {
        let vsize = virtual_size(section)?;
        let raw_size = if section.kind == SectionKind::Bss || section.data.is_empty() {
            0
        } else {
            align_up(
                u32_of(section.data.len(), "section raw size")?,
                FILE_ALIGNMENT,
            )
        };
        let file_offset = if raw_size == 0 { 0 } else { file_cursor };
        placements.push(Placement {
            rva: rva(section)?,
            virtual_size: vsize,
            file_offset,
            raw_size,
        });
        if raw_size != 0 {
            file_cursor = file_cursor
                .checked_add(raw_size)
                .ok_or(Error::ValueOutOfRange("PE file size"))?;
        }
    }

    patch_debug_sections(&mut sections, &placements)?;

    let size_of_image = sections
        .iter()
        .zip(&placements)
        .map(|(_, p)| align_up(p.rva.saturating_add(p.virtual_size), SECTION_ALIGNMENT))
        .max()
        .unwrap_or(align_up(size_of_headers, SECTION_ALIGNMENT));

    let directories = data_directories(&sections, &placements)?;
    let relocations = SectionRelocations::new(module, &sections, file_cursor, machine)?;
    let symbols = CoffSymbols::new(module, &sections, relocations.end)?;

    let layout = Layout {
        machine,
        is_pe32_plus,
        optional_size,
        section_count,
        size_of_headers,
        size_of_image,
        entry: u32::try_from(module.entry().unwrap_or(0))
            .map_err(|_| Error::ValueOutOfRange("PE entry point"))?,
        directories,
        relocations,
        symbols,
    };

    emit(module, &sections, &placements, &layout)
}

#[derive(Clone, Copy)]
struct DataDir {
    rva: u32,
    size: u32,
}

fn data_directories(sections: &[OutputSection], placements: &[Placement]) -> Result<[DataDir; 16]> {
    let mut dirs = [DataDir { rva: 0, size: 0 }; 16];
    for (section, placement) in sections.iter().zip(placements) {
        let dir = match section.name.as_str() {
            ".edata" => Some(DIRECTORY_EXPORT),
            ".idata" => Some(DIRECTORY_IMPORT),
            ".reloc" => Some(DIRECTORY_BASERELOC),
            ".cvdbg" => Some(DIRECTORY_DEBUG),
            _ => None,
        };
        if let Some(index) = dir
            && let Some(slot) = dirs.get_mut(index)
        {
            let size = if index == DIRECTORY_DEBUG {
                DEBUG_DIRECTORY_SIZE
            } else {
                u32_of(section.data.len(), "data directory size")?
            };
            *slot = DataDir {
                rva: placement.rva,
                size,
            };
        }
    }
    Ok(dirs)
}

fn patch_debug_sections(sections: &mut [OutputSection], placements: &[Placement]) -> Result<()> {
    for (section, placement) in sections.iter_mut().zip(placements) {
        if section.name != ".cvdbg" || section.data.len() < DEBUG_DIRECTORY_SIZE_USIZE {
            continue;
        }
        let debug_type = section
            .data
            .get(12..16)
            .and_then(|bytes| bytes.try_into().ok())
            .map_or(0, u32::from_le_bytes);
        if debug_type != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let raw_rva = placement
            .rva
            .checked_add(DEBUG_DIRECTORY_SIZE)
            .ok_or(Error::ValueOutOfRange("debug data RVA"))?;
        let raw_ptr = placement
            .file_offset
            .checked_add(DEBUG_DIRECTORY_SIZE)
            .ok_or(Error::ValueOutOfRange("debug raw pointer"))?;
        let rva_slot = section
            .data
            .get_mut(20..24)
            .ok_or(Error::Malformed("debug directory patch"))?;
        rva_slot.copy_from_slice(&raw_rva.to_le_bytes());
        let ptr_slot = section
            .data
            .get_mut(24..28)
            .ok_or(Error::Malformed("debug directory patch"))?;
        ptr_slot.copy_from_slice(&raw_ptr.to_le_bytes());
    }
    Ok(())
}

struct SectionRelocation {
    bytes: Vec<u8>,
    pointer: u32,
    count: u16,
}

struct SectionRelocations {
    sections: Vec<SectionRelocation>,
    end: u32,
}

impl SectionRelocations {
    fn new(
        module: &ObjectModule,
        sections: &[OutputSection],
        cursor: u32,
        machine: u16,
    ) -> Result<Self> {
        let mut out = Vec::with_capacity(sections.len());
        let mut next = cursor;
        for section in sections {
            let bytes = if let Some(id) = section.origin {
                section_relocation_bytes(module, id, machine)?
            } else {
                Vec::new()
            };
            let count = u16::try_from(bytes.len() / 10)
                .map_err(|_| Error::ValueOutOfRange("section relocation count"))?;
            let pointer = if count == 0 { 0 } else { next };
            if count != 0 {
                next = next
                    .checked_add(u32_of(bytes.len(), "section relocations")?)
                    .ok_or(Error::ValueOutOfRange("section relocations"))?;
            }
            out.push(SectionRelocation {
                bytes,
                pointer,
                count,
            });
        }
        Ok(Self {
            sections: out,
            end: next,
        })
    }
}

fn section_relocation_bytes(
    module: &ObjectModule,
    section: SectionId,
    machine: u16,
) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new(module.target().endian);
    for (_, reloc) in module.relocations() {
        if reloc.section != section {
            continue;
        }
        write_section_relocation(&mut w, module, reloc, machine)?;
    }
    w.finish()
}

fn write_section_relocation(
    w: &mut ByteWriter,
    module: &ObjectModule,
    reloc: &Relocation,
    machine: u16,
) -> Result<()> {
    w.write_u32(u32::try_from(reloc.offset).map_err(|_| Error::ValueOutOfRange("reloc offset"))?);
    w.write_u32(symbol_table_index(module, reloc.symbol)?);
    w.write_u16(coff_reloc_type(machine, reloc.kind)?);
    Ok(())
}

fn symbol_table_index(module: &ObjectModule, symbol: SymbolId) -> Result<u32> {
    for (id, _) in module.symbols() {
        if id == symbol {
            return Ok(id.raw());
        }
    }
    Err(Error::Malformed("relocation references missing symbol"))
}

fn coff_reloc_type(machine: u16, kind: RelocKind) -> Result<u16> {
    if let RelocKind::Other(raw) = kind {
        return u16::try_from(raw).map_err(|_| Error::ValueOutOfRange("COFF relocation type"));
    }
    match (machine, kind) {
        (IMAGE_FILE_MACHINE_AMD64, RelocKind::Absolute64) => Ok(PE_RELOC_AMD64_ADDR64),
        (IMAGE_FILE_MACHINE_AMD64, RelocKind::Absolute32) => Ok(PE_RELOC_AMD64_ADDR32),
        (IMAGE_FILE_MACHINE_AMD64, RelocKind::Relative32 | RelocKind::PltRelative) => {
            Ok(PE_RELOC_AMD64_REL32)
        }
        (IMAGE_FILE_MACHINE_ARM64, RelocKind::Absolute64) => Ok(PE_RELOC_ARM64_ADDR64),
        (IMAGE_FILE_MACHINE_ARM64, RelocKind::Absolute32) => Ok(PE_RELOC_ARM64_ADDR32),
        (IMAGE_FILE_MACHINE_ARM64, RelocKind::Relative32 | RelocKind::PltRelative) => {
            Ok(PE_RELOC_ARM64_REL32)
        }
        (IMAGE_FILE_MACHINE_I386, RelocKind::Absolute32) => Ok(PE_RELOC_I386_DIR32),
        (IMAGE_FILE_MACHINE_I386, RelocKind::Relative32 | RelocKind::PltRelative) => {
            Ok(PE_RELOC_I386_REL32)
        }
        (IMAGE_FILE_MACHINE_ARMNT, RelocKind::Absolute32) => Ok(PE_RELOC_ARM_ADDR32),
        (IMAGE_FILE_MACHINE_ARMNT, RelocKind::Relative32 | RelocKind::PltRelative) => {
            Ok(PE_RELOC_ARM_REL32)
        }
        _ => Err(Error::Unsupported("PE relocation kind")),
    }
}

struct CoffSymbols {
    bytes: Vec<u8>,
    pointer: u32,
    count: u32,
}

impl CoffSymbols {
    fn new(module: &ObjectModule, sections: &[OutputSection], pointer: u32) -> Result<Self> {
        if module.symbol_count() == 0 {
            return Ok(Self {
                bytes: Vec::new(),
                pointer: 0,
                count: 0,
            });
        }

        let mut entries = ByteWriter::new(module.target().endian);
        let mut strings = ByteWriter::new(module.target().endian);
        strings.write_u32(4);
        let mut count = 0u32;
        for (_, symbol) in module.symbols() {
            let name = module.resolve(symbol.name)?;
            write_symbol_name(&mut entries, &mut strings, name)?;
            entries.write_u32(
                u32::try_from(symbol.value).map_err(|_| Error::ValueOutOfRange("symbol value"))?,
            );
            let sec_num = symbol
                .section
                .and_then(|id| section_number(sections, id))
                .unwrap_or(0);
            entries.write_u16(sec_num);
            let ty = if symbol.kind == SymbolKind::Function {
                SYM_DTYPE_FUNCTION
            } else {
                0
            };
            entries.write_u16(ty);
            let class = if symbol.binding == SymbolBinding::Local {
                SYM_CLASS_STATIC
            } else {
                SYM_CLASS_EXTERNAL
            };
            entries.write_u8(class);
            entries.write_u8(0);
            count = count
                .checked_add(1)
                .ok_or(Error::ValueOutOfRange("symbol count"))?;
        }
        let string_bytes = strings.finish()?;
        let mut bytes = entries.finish()?;
        bytes.extend_from_slice(&string_bytes);
        let pointer = align_up(pointer, 4);
        Ok(Self {
            bytes,
            pointer,
            count,
        })
    }
}

fn section_number(sections: &[OutputSection], id: SectionId) -> Option<u16> {
    for (index, section) in sections.iter().enumerate() {
        if section.origin == Some(id) {
            let one_based = index.checked_add(1)?;
            return u16::try_from(one_based).ok();
        }
    }
    None
}

fn write_symbol_name(entries: &mut ByteWriter, strings: &mut ByteWriter, name: &str) -> Result<()> {
    let raw = name.as_bytes();
    if raw.len() <= 8 {
        entries.write_bytes(raw);
        entries.write_zeros(8usize.saturating_sub(raw.len()));
        return Ok(());
    }
    let offset = u32_of(strings.position(), "COFF string offset")?;
    entries.write_u32(0);
    entries.write_u32(offset);
    strings.write_bytes(raw);
    strings.write_u8(0);
    let len = u32_of(strings.position(), "COFF string table")?;
    strings.patch_u32(0, len)?;
    Ok(())
}

struct Layout {
    machine: u16,
    is_pe32_plus: bool,
    optional_size: u16,
    section_count: u16,
    size_of_headers: u32,
    size_of_image: u32,
    entry: u32,
    directories: [DataDir; 16],
    relocations: SectionRelocations,
    symbols: CoffSymbols,
}

fn emit(
    module: &ObjectModule,
    sections: &[OutputSection],
    placements: &[Placement],
    layout: &Layout,
) -> Result<Vec<u8>> {
    let endian = module.target().endian;
    let mut w = ByteWriter::new(endian);

    w.write_u16(DOS_MAGIC);
    w.write_zeros(E_LFANEW_OFFSET - 2);
    w.write_u32(DOS_HEADER_SIZE);

    w.write_u32(PE_SIGNATURE);
    write_coff_header(&mut w, layout);
    write_optional_header(&mut w, sections, placements, layout);
    for ((section, placement), relocations) in sections
        .iter()
        .zip(placements)
        .zip(&layout.relocations.sections)
    {
        write_section_header(&mut w, section, placement, relocations)?;
    }

    for (section, placement) in sections.iter().zip(placements) {
        if placement.raw_size == 0 {
            continue;
        }
        pad_to(&mut w, placement.file_offset)?;
        w.write_bytes(&section.data);
        pad_to(&mut w, placement.file_offset + placement.raw_size)?;
    }
    for relocations in &layout.relocations.sections {
        if relocations.count == 0 {
            continue;
        }
        pad_to(&mut w, relocations.pointer)?;
        w.write_bytes(&relocations.bytes);
    }
    if layout.symbols.count != 0 {
        pad_to(&mut w, layout.symbols.pointer)?;
        w.write_bytes(&layout.symbols.bytes);
    }

    w.finish()
}

fn write_coff_header(w: &mut ByteWriter, layout: &Layout) {
    w.write_u16(layout.machine);
    w.write_u16(layout.section_count);
    w.write_u32(0);
    w.write_u32(layout.symbols.pointer);
    w.write_u32(layout.symbols.count);
    w.write_u16(layout.optional_size);
    let mut chars = IMAGE_FILE_EXECUTABLE_IMAGE;
    if layout.is_pe32_plus {
        chars |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    } else {
        chars |= IMAGE_FILE_32BIT_MACHINE;
    }
    w.write_u16(chars);
}

fn write_optional_header(
    w: &mut ByteWriter,
    sections: &[OutputSection],
    placements: &[Placement],
    layout: &Layout,
) {
    let mut size_of_code = 0u32;
    let mut size_of_init = 0u32;
    let mut size_of_uninit = 0u32;
    let mut base_of_code = 0u32;
    let mut base_of_data = 0u32;
    for (section, placement) in sections.iter().zip(placements) {
        match section.kind {
            SectionKind::Text => {
                size_of_code = size_of_code.saturating_add(placement.raw_size);
                if base_of_code == 0 {
                    base_of_code = placement.rva;
                }
            }
            SectionKind::Bss => {
                size_of_uninit = size_of_uninit.saturating_add(placement.virtual_size);
            }
            _ => {
                size_of_init = size_of_init.saturating_add(placement.raw_size);
                if base_of_data == 0 {
                    base_of_data = placement.rva;
                }
            }
        }
    }

    if layout.is_pe32_plus {
        w.write_u16(OPTIONAL_MAGIC_PE32PLUS);
    } else {
        w.write_u16(OPTIONAL_MAGIC_PE32);
    }
    w.write_u8(0);
    w.write_u8(0);
    w.write_u32(size_of_code);
    w.write_u32(size_of_init);
    w.write_u32(size_of_uninit);
    w.write_u32(layout.entry);
    w.write_u32(base_of_code);
    if layout.is_pe32_plus {
        w.write_u64(IMAGE_BASE64);
    } else {
        w.write_u32(base_of_data);
        w.write_u32(IMAGE_BASE32);
    }
    w.write_u32(SECTION_ALIGNMENT);
    w.write_u32(FILE_ALIGNMENT);
    w.write_u16(6);
    w.write_u16(0);
    w.write_u16(0);
    w.write_u16(0);
    w.write_u16(6);
    w.write_u16(0);
    w.write_u32(0);
    w.write_u32(layout.size_of_image);
    w.write_u32(layout.size_of_headers);
    w.write_u32(0);
    w.write_u16(SUBSYSTEM_WINDOWS_CUI);
    w.write_u16(0);
    if layout.is_pe32_plus {
        w.write_u64(0x0010_0000);
        w.write_u64(0x0000_1000);
        w.write_u64(0x0010_0000);
        w.write_u64(0x0000_1000);
    } else {
        w.write_u32(0x0010_0000);
        w.write_u32(0x0000_1000);
        w.write_u32(0x0010_0000);
        w.write_u32(0x0000_1000);
    }
    w.write_u32(0);
    w.write_u32(NUMBER_OF_DIRECTORIES);
    write_data_directories(w, layout);
}

fn write_data_directories(w: &mut ByteWriter, layout: &Layout) {
    for dir in &layout.directories {
        w.write_u32(dir.rva);
        w.write_u32(dir.size);
    }
}

fn write_section_header(
    w: &mut ByteWriter,
    section: &OutputSection,
    placement: &Placement,
    relocations: &SectionRelocation,
) -> Result<()> {
    w.write_bytes(&name_bytes(section)?);
    w.write_u32(placement.virtual_size);
    w.write_u32(placement.rva);
    w.write_u32(placement.raw_size);
    w.write_u32(placement.file_offset);
    w.write_u32(relocations.pointer);
    w.write_u32(0);
    w.write_u16(relocations.count);
    w.write_u16(0);
    w.write_u32(characteristics(section));
    Ok(())
}

fn pad_to(w: &mut ByteWriter, target: u32) -> Result<()> {
    let current = u32::try_from(w.position()).map_err(|_| Error::ValueOutOfRange("position"))?;
    if target < current {
        return Err(Error::Malformed("PE layout went backwards"));
    }
    let count = usize::try_from(target - current).map_err(|_| Error::ValueOutOfRange("padding"))?;
    w.write_zeros(count);
    Ok(())
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use stratum_oir::{
        BinaryFormat, Endianness, Export, SectionFlags, SymbolEntry, SymbolFlags, TargetSpec,
    };

    fn module(target: TargetSpec) -> ObjectModule {
        ObjectModule::new(BinaryFormat::Pe, target)
    }

    fn add_section(
        module: &mut ObjectModule,
        name: &str,
        kind: SectionKind,
        flags: SectionFlags,
        data: Vec<u8>,
        size: u64,
    ) -> SectionId {
        let symbol = module.intern(name).unwrap();
        module
            .add_section(Section {
                name: symbol,
                kind,
                address: SECTION_ALIGNMENT.into(),
                align: SECTION_ALIGNMENT.into(),
                flags,
                data,
                size,
            })
            .unwrap()
    }

    #[test]
    fn helper_edges_are_covered() {
        assert_eq!(align_up(7, 1), 7);
        assert!(u32_of(usize::MAX, "huge").is_err());
        assert!(machine(Architecture::Wasm32).is_err());
        assert!(ensure_section_size(1, 2, "section").is_err());

        let bss = OutputSection {
            origin: None,
            name: ".bss".to_string(),
            kind: SectionKind::Bss,
            address: 0,
            flags: SectionFlags::data(),
            data: Vec::new(),
            size: 4,
        };
        assert_eq!(
            characteristics(&bss) & SCN_CNT_UNINITIALIZED_DATA,
            SCN_CNT_UNINITIALIZED_DATA
        );
    }

    #[test]
    fn synthetic_directory_sections_are_built_from_metadata() {
        let mut module = module(TargetSpec::x86());
        let text = add_section(
            &mut module,
            ".text",
            SectionKind::Text,
            SectionFlags::code(),
            alloc::vec![0xC3; 16],
            16,
        );
        let lib = module.intern("kernel32.dll").unwrap();
        let proc = module.intern("ExitProcess").unwrap();
        module.add_import(Import {
            library: lib,
            name: proc,
            ordinal: None,
            hint: Some(0),
        });
        let ordinal_name = module.intern("").unwrap();
        module.add_import(Import {
            library: lib,
            name: ordinal_name,
            ordinal: Some(7),
            hint: None,
        });

        let export_name = module.intern("entry").unwrap();
        module.add_export(Export {
            name: export_name,
            address: u64::from(SECTION_ALIGNMENT),
            ordinal: Some(1),
        });
        let symbol_name = module.intern("target").unwrap();
        let symbol = module
            .add_symbol(SymbolEntry {
                name: symbol_name,
                value: u64::from(SECTION_ALIGNMENT),
                size: 8,
                section: Some(text),
                kind: SymbolKind::Object,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        for offset in [0, 8] {
            module
                .add_relocation(Relocation {
                    section: text,
                    offset,
                    symbol,
                    kind: RelocKind::Absolute32,
                    addend: 0,
                })
                .unwrap();
        }
        module.debug_mut().add_external_file(
            ExternalDebugFile::new(
                DebugFileFormat::Other(7),
                "sidecar.debug".to_string(),
                alloc::vec![7],
                None,
            )
            .unwrap(),
        );
        module.debug_mut().add_external_file(ExternalDebugFile::pdb(
            "app.pdb".to_string(),
            [1; 16],
            1,
        ));

        let sections = output_sections(&module, false).unwrap();

        for name in [".idata", ".edata", ".reloc", ".cvdbg"] {
            assert!(
                sections.iter().any(|section| section.name == name),
                "{name}"
            );
        }
        assert_eq!(base_reloc_type(RelocKind::Relative32), None);
    }

    #[test]
    fn import_helpers_cover_pe32_thunks_and_empty_names() {
        let mut bad = module(TargetSpec::x86());
        let library = bad.intern("kernel32.dll").unwrap();
        let empty = bad.intern("").unwrap();
        bad.add_import(Import {
            library,
            name: empty,
            ordinal: None,
            hint: None,
        });
        assert!(build_import_section(&bad, SECTION_ALIGNMENT, false).is_err());

        let group = ImportGroup {
            library: "kernel32.dll".to_string(),
            imports: alloc::vec![
                ImportSpec {
                    name: "ExitProcess".to_string(),
                    ordinal: None,
                    hint: 0,
                },
                ImportSpec {
                    name: String::new(),
                    ordinal: Some(7),
                    hint: 0,
                },
            ],
        };
        let layout = ImportGroupLayout {
            lookup_off: 0,
            addr_off: 0,
            dll_off: 0,
            name_offsets: alloc::vec![0x20, 0],
        };
        let mut w = ByteWriter::new(Endianness::Little);
        write_import_thunks(&mut w, SECTION_ALIGNMENT, &group, &layout, false).unwrap();
        let bytes = w.finish().unwrap();

        assert_eq!(bytes.len(), 12);
        assert_eq!(
            u32::from_le_bytes(bytes.get(4..8).unwrap().try_into().unwrap()),
            0x8000_0007
        );
        assert_eq!(bytes.get(8..12), Some(&[0, 0, 0, 0][..]));

        let group = ImportGroup {
            library: "kernel32.dll".to_string(),
            imports: alloc::vec![
                ImportSpec {
                    name: "AB".to_string(),
                    ordinal: None,
                    hint: 0,
                },
                ImportSpec {
                    name: String::new(),
                    ordinal: Some(7),
                    hint: 0,
                },
            ],
        };
        let layout = ImportGroupLayout {
            lookup_off: 0,
            addr_off: 0,
            dll_off: 0,
            name_offsets: alloc::vec![0x20, 0],
        };
        let mut w = ByteWriter::new(Endianness::Little);
        write_import_thunks(&mut w, SECTION_ALIGNMENT, &group, &layout, true).unwrap();
        let bytes = w.finish().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            u64::from_le_bytes(bytes.get(8..16).unwrap().try_into().unwrap()),
            0x8000_0000_0000_0007
        );
        assert_eq!(bytes.get(16..24), Some(&[0; 8][..]));

        let mut padded = module(TargetSpec::x86_64());
        let library = padded.intern("kernel32.dll").unwrap();
        let name = padded.intern("AB").unwrap();
        padded.add_import(Import {
            library,
            name,
            ordinal: None,
            hint: Some(0),
        });
        let bytes = build_import_section(&padded, SECTION_ALIGNMENT, true).unwrap();
        assert_eq!(bytes.get(72..78), Some(&[0, 0, b'A', b'B', 0, 0][..]));
        assert_eq!(bytes.get(78..91), Some(&b"kernel32.dll\0"[..]));
    }

    #[test]
    fn export_helpers_cover_sparse_and_duplicate_ordinals() {
        let mut sparse = module(TargetSpec::x86_64());
        let auto = sparse.intern("auto").unwrap();
        let one = sparse.intern("one").unwrap();
        let two = sparse.intern("two").unwrap();
        sparse.add_export(Export {
            name: auto,
            address: 0x1000,
            ordinal: None,
        });
        sparse.add_export(Export {
            name: one,
            address: 0x1000,
            ordinal: Some(1),
        });
        sparse.add_export(Export {
            name: two,
            address: 0x1000,
            ordinal: Some(2),
        });
        let specs = export_specs(&sparse).unwrap();
        assert_eq!(specs.first().unwrap().ordinal, 3);
        let layout = export_layout(&specs).unwrap();
        let bytes = build_export_section(&sparse, SECTION_ALIGNMENT).unwrap();
        assert_eq!(
            u32_of(bytes.len(), "export test").unwrap(),
            layout.section_size
        );

        let mut duplicate = module(TargetSpec::x86_64());
        let a = duplicate.intern("a").unwrap();
        let b = duplicate.intern("b").unwrap();
        duplicate.add_export(Export {
            name: a,
            address: 0x1000,
            ordinal: Some(1),
        });
        duplicate.add_export(Export {
            name: b,
            address: 0x1000,
            ordinal: Some(1),
        });
        assert!(export_specs(&duplicate).is_err());
    }

    #[test]
    fn debug_patch_skips_non_codeview_directories() {
        let mut sections = alloc::vec![OutputSection {
            origin: None,
            name: ".cvdbg".to_string(),
            kind: SectionKind::Debug,
            address: u64::from(SECTION_ALIGNMENT),
            flags: SectionFlags::read_only(),
            data: alloc::vec![0; DEBUG_DIRECTORY_SIZE_USIZE],
            size: u64::from(DEBUG_DIRECTORY_SIZE),
        }];
        let placements = alloc::vec![Placement {
            rva: SECTION_ALIGNMENT,
            virtual_size: DEBUG_DIRECTORY_SIZE,
            file_offset: FILE_ALIGNMENT,
            raw_size: FILE_ALIGNMENT,
        }];

        patch_debug_sections(&mut sections, &placements).unwrap();

        assert_eq!(
            sections.first().unwrap().data.get(20..28),
            Some(&[0; 8][..])
        );
    }

    #[test]
    fn debug_directory_entries_are_patched_and_reported() {
        let mut data = alloc::vec![0; DEBUG_DIRECTORY_SIZE_USIZE + 4];
        data.get_mut(12..16)
            .unwrap()
            .copy_from_slice(&IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes());
        let mut sections = alloc::vec![OutputSection {
            origin: None,
            name: ".cvdbg".to_string(),
            kind: SectionKind::Debug,
            address: u64::from(SECTION_ALIGNMENT),
            flags: SectionFlags::read_only(),
            data,
            size: u64::from(DEBUG_DIRECTORY_SIZE + 4),
        }];
        let placements = alloc::vec![Placement {
            rva: SECTION_ALIGNMENT,
            virtual_size: DEBUG_DIRECTORY_SIZE + 4,
            file_offset: FILE_ALIGNMENT,
            raw_size: FILE_ALIGNMENT,
        }];

        patch_debug_sections(&mut sections, &placements).unwrap();
        let dirs = data_directories(&sections, &placements).unwrap();

        assert_eq!(dirs[DIRECTORY_DEBUG].rva, SECTION_ALIGNMENT);
        assert_eq!(dirs[DIRECTORY_DEBUG].size, DEBUG_DIRECTORY_SIZE);
        assert_eq!(
            u32::from_le_bytes(
                sections
                    .first()
                    .unwrap()
                    .data
                    .get(20..24)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            SECTION_ALIGNMENT + DEBUG_DIRECTORY_SIZE
        );
        assert_eq!(
            u32::from_le_bytes(
                sections
                    .first()
                    .unwrap()
                    .data
                    .get(24..28)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            FILE_ALIGNMENT + DEBUG_DIRECTORY_SIZE
        );
    }

    #[test]
    fn coff_relocation_helpers_cover_all_machine_mappings() {
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::Absolute64).unwrap(),
            PE_RELOC_AMD64_ADDR64
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::Absolute32).unwrap(),
            PE_RELOC_AMD64_ADDR32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::Relative32).unwrap(),
            PE_RELOC_AMD64_REL32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::PltRelative).unwrap(),
            PE_RELOC_AMD64_REL32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_ARM64, RelocKind::Absolute64).unwrap(),
            PE_RELOC_ARM64_ADDR64
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_ARM64, RelocKind::Absolute32).unwrap(),
            PE_RELOC_ARM64_ADDR32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_ARM64, RelocKind::Relative32).unwrap(),
            PE_RELOC_ARM64_REL32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_I386, RelocKind::Absolute32).unwrap(),
            PE_RELOC_I386_DIR32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_I386, RelocKind::Relative32).unwrap(),
            PE_RELOC_I386_REL32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_ARMNT, RelocKind::Absolute32).unwrap(),
            PE_RELOC_ARM_ADDR32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_ARMNT, RelocKind::Relative32).unwrap(),
            PE_RELOC_ARM_REL32
        );
        assert_eq!(
            coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::Other(7)).unwrap(),
            7
        );
        assert!(coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::Other(u32::MAX)).is_err());
        assert!(coff_reloc_type(IMAGE_FILE_MACHINE_AMD64, RelocKind::GotRelative).is_err());
        assert_eq!(base_reloc_type(RelocKind::Absolute64), Some(10));

        let mut module = module(TargetSpec::x86_64());
        let text = add_section(
            &mut module,
            ".text",
            SectionKind::Text,
            SectionFlags::code(),
            alloc::vec![0; 4],
            4,
        );
        let name = module.intern("target").unwrap();
        let symbol = module
            .add_symbol(SymbolEntry {
                name,
                value: 0,
                size: 0,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let reloc = Relocation {
            section: text,
            offset: 0,
            symbol,
            kind: RelocKind::Absolute64,
            addend: 0,
        };
        let mut w = ByteWriter::new(Endianness::Little);
        write_section_relocation(&mut w, &module, &reloc, IMAGE_FILE_MACHINE_AMD64).unwrap();
        assert_eq!(symbol_table_index(&module, symbol).unwrap(), symbol.raw());
        assert!(symbol_table_index(&module, SymbolId::from_raw(99)).is_err());
        assert!(
            write_section_relocation(
                &mut w,
                &module,
                &Relocation {
                    offset: u64::MAX,
                    ..reloc
                },
                IMAGE_FILE_MACHINE_AMD64,
            )
            .is_err()
        );
    }

    #[test]
    fn relocation_sections_cover_padding_and_emit_path() {
        let mut module = module(TargetSpec::x86_64());
        let text = add_section(
            &mut module,
            ".text",
            SectionKind::Text,
            SectionFlags::code(),
            alloc::vec![0xC3; 8],
            8,
        );
        let data = add_section(
            &mut module,
            ".data",
            SectionKind::Data,
            SectionFlags::data(),
            alloc::vec![1; 4],
            4,
        );
        let name = module.intern("target").unwrap();
        let symbol = module
            .add_symbol(SymbolEntry {
                name,
                value: 0,
                size: 0,
                section: Some(text),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        module
            .add_relocation(Relocation {
                section: text,
                offset: 4,
                symbol,
                kind: RelocKind::Absolute64,
                addend: 0,
            })
            .unwrap();
        module
            .add_relocation(Relocation {
                section: text,
                offset: 0,
                symbol,
                kind: RelocKind::Relative32,
                addend: 0,
            })
            .unwrap();

        let base_relocs = build_base_reloc_section(&module).unwrap();
        assert_eq!(base_relocs.len(), 12);
        assert_eq!(base_relocs.get(10..12), Some(&[0, 0][..]));

        let sections = output_sections(&module, true).unwrap();
        let relocs =
            SectionRelocations::new(&module, &sections, FILE_ALIGNMENT, IMAGE_FILE_MACHINE_AMD64)
                .unwrap();
        assert!(relocs.sections.iter().any(|section| section.count == 2));
        assert!(relocs.sections.iter().any(|section| section.count == 0));

        let skipped = section_relocation_bytes(&module, data, IMAGE_FILE_MACHINE_AMD64).unwrap();
        assert!(skipped.is_empty());
        let written = section_relocation_bytes(&module, text, IMAGE_FILE_MACHINE_AMD64).unwrap();
        assert_eq!(written.len(), 20);

        let bytes = write(&module).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn rejects_unsupported_and_long_section_names() {
        let unsupported = module(TargetSpec::wasm32());
        assert!(write(&unsupported).is_err());

        let mut named = module(TargetSpec::x86_64());
        add_section(
            &mut named,
            ".too-long",
            SectionKind::Text,
            SectionFlags::code(),
            alloc::vec![0xC3],
            1,
        );
        assert!(write(&named).is_err());
    }

    #[test]
    fn writes_empty_bss_and_no_sections() {
        let empty = module(TargetSpec::x86_64());
        let bytes = write(&empty).unwrap();
        assert!(!bytes.is_empty());

        let mut with_bss = module(TargetSpec::x86());
        add_section(
            &mut with_bss,
            ".bss",
            SectionKind::Bss,
            SectionFlags::data(),
            Vec::new(),
            16,
        );
        let bytes = write(&with_bss).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn writes_non_function_local_and_long_symbols() {
        let mut module = module(TargetSpec::x86_64());
        let section = add_section(
            &mut module,
            ".data",
            SectionKind::Data,
            SectionFlags::data(),
            alloc::vec![1, 2, 3],
            3,
        );
        let local_name = module.intern("local_object").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: local_name,
                value: 1,
                size: 0,
                section: Some(section),
                kind: SymbolKind::Object,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let external_name = module.intern("external_long_symbol_name").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: external_name,
                value: 0,
                size: 0,
                section: None,
                kind: SymbolKind::None,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let bytes = write(&module).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn section_number_and_padding_error_edges() {
        let mut module = module(TargetSpec::x86_64());
        let id = add_section(
            &mut module,
            ".text",
            SectionKind::Text,
            SectionFlags::code(),
            alloc::vec![0xC3],
            1,
        );
        let sections = output_sections(&module, true).unwrap();
        assert_eq!(section_number(&sections, id), Some(1));

        assert_eq!(section_number(&sections, SectionId::from_raw(99)), None);

        let mut writer = ByteWriter::new(Endianness::Little);
        writer.write_u8(1);
        assert!(pad_to(&mut writer, 0).is_err());
    }
}
