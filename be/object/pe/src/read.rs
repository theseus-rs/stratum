//! Parses PE/COFF images into the shared object model.

use crate::consts::{
    DIRECTORY_BASERELOC, DIRECTORY_EXPORT, DIRECTORY_IMPORT, DOS_MAGIC, E_LFANEW_OFFSET,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386, OPTIONAL_MAGIC_PE32, OPTIONAL_MAGIC_PE32PLUS, PE_SIGNATURE,
    SCN_CNT_CODE, SCN_CNT_UNINITIALIZED_DATA, SCN_MEM_EXECUTE, SCN_MEM_READ, SCN_MEM_WRITE,
    SECTION_ALIGNMENT, SECTION_HEADER_SIZE, SYM_CLASS_EXTERNAL, SYM_DTYPE_FUNCTION,
    SYMBOL_TABLE_ENTRY_SIZE,
};
use stratum_oir::{
    Architecture, BinaryFormat, ByteReader, Endianness, Error, Export, Import, ObjectModule,
    PtrWidth, Result, Section, SectionFlags, SectionId, SectionKind, SymbolBinding, SymbolEntry,
    SymbolFlags, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone)]
struct SectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,
}

#[derive(Clone, Copy)]
struct Directory {
    rva: u32,
    size: u32,
}

struct Headers {
    machine: u16,
    sections: u16,
    symbol_ptr: u32,
    symbol_count: u32,
    optional_size: u16,
    entry: u32,
    is_pe32_plus: bool,
    directories: [Directory; 16],
}

/// Parses a PE/COFF executable image.
///
/// # Errors
///
/// Returns an error when a signature is invalid, the target machine is unsupported, or an RVA,
/// section, import table, export table, relocation block, or COFF symbol table is malformed.
pub fn read(bytes: &[u8]) -> Result<ObjectModule> {
    let mut reader = ByteReader::new(bytes, Endianness::Little);
    if reader.read_u16()? != DOS_MAGIC {
        return Err(Error::BadMagic);
    }
    reader.seek(E_LFANEW_OFFSET)?;
    let pe_offset = usize::try_from(reader.read_u32()?)
        .map_err(|_| Error::ValueOutOfRange("PE header offset"))?;
    reader.seek(pe_offset)?;
    if reader.read_u32()? != PE_SIGNATURE {
        return Err(Error::BadMagic);
    }

    let headers = read_headers(&mut reader)?;
    let target = target_for(headers.machine, headers.is_pe32_plus)?;
    let mut module = ObjectModule::new(BinaryFormat::Pe, target);
    module.set_entry(u64::from(headers.entry));

    let section_headers = read_section_headers(&mut reader, headers.sections)?;
    let ids = add_sections(&mut module, bytes, &section_headers)?;
    parse_imports(
        &mut module,
        bytes,
        &section_headers,
        &headers.directories,
        headers.is_pe32_plus,
    )?;
    parse_exports(&mut module, bytes, &section_headers, &headers.directories)?;
    parse_relocs(bytes, &section_headers, &headers.directories)?;
    parse_symbols(&mut module, bytes, &section_headers, &ids, &headers)?;
    Ok(module)
}

fn read_headers(reader: &mut ByteReader<'_>) -> Result<Headers> {
    let machine = reader.read_u16()?;
    let sections = reader.read_u16()?;
    reader.skip(4)?;
    let symbol_ptr = reader.read_u32()?;
    let symbol_count = reader.read_u32()?;
    let optional_size = reader.read_u16()?;
    reader.skip(2)?;
    let optional_start = reader.position();
    let magic = reader.read_u16()?;
    let is_pe32_plus = match magic {
        OPTIONAL_MAGIC_PE32 => false,
        OPTIONAL_MAGIC_PE32PLUS => true,
        _ => return Err(Error::Unsupported("PE optional header magic")),
    };
    reader.skip(14)?;
    let entry = reader.read_u32()?;
    reader.skip(4)?;
    reader.skip(8)?;
    reader.skip(40)?;
    if is_pe32_plus {
        reader.skip(32)?;
    } else {
        reader.skip(16)?;
    }
    reader.skip(4)?;
    let directory_count = reader.read_u32()?;
    let mut directories = [Directory { rva: 0, size: 0 }; 16];
    let capped = directory_count.min(16);
    for slot in directories
        .iter_mut()
        .take(usize::try_from(capped).unwrap_or(0))
    {
        *slot = Directory {
            rva: reader.read_u32()?,
            size: reader.read_u32()?,
        };
    }
    let consumed = reader.position().saturating_sub(optional_start);
    let optional_size_usize = usize::from(optional_size);
    if consumed > optional_size_usize {
        return Err(Error::Malformed("optional header overruns declared size"));
    }
    reader.seek(optional_start + optional_size_usize)?;
    Ok(Headers {
        machine,
        sections,
        symbol_ptr,
        symbol_count,
        optional_size,
        entry,
        is_pe32_plus,
        directories,
    })
}

fn target_for(machine: u16, is_pe32_plus: bool) -> Result<TargetSpec> {
    let (arch, ptr_width) = match machine {
        IMAGE_FILE_MACHINE_I386 => (Architecture::X86, PtrWidth::W32),
        IMAGE_FILE_MACHINE_ARMNT => (Architecture::Arm, PtrWidth::W32),
        IMAGE_FILE_MACHINE_AMD64 => (Architecture::X86_64, PtrWidth::W64),
        IMAGE_FILE_MACHINE_ARM64 => (Architecture::Aarch64, PtrWidth::W64),
        _ => return Err(Error::Unsupported("PE machine")),
    };
    if (ptr_width == PtrWidth::W64) != is_pe32_plus {
        return Err(Error::Malformed(
            "machine and optional-header class disagree",
        ));
    }
    Ok(TargetSpec {
        arch,
        endian: Endianness::Little,
        ptr_width,
    })
}

fn read_section_headers(reader: &mut ByteReader<'_>, count: u16) -> Result<Vec<SectionHeader>> {
    let mut sections = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let raw_name = reader.read_bytes(8)?;
        let name_len = raw_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw_name.len());
        let name = core::str::from_utf8(
            raw_name
                .get(0..name_len)
                .ok_or(Error::Malformed("section name"))?,
        )
        .map_err(|_| Error::Malformed("section name is not UTF-8"))?
        .to_owned();
        let virtual_size = reader.read_u32()?;
        let virtual_address = reader.read_u32()?;
        let raw_size = reader.read_u32()?;
        let raw_ptr = reader.read_u32()?;
        reader.skip(12)?;
        let characteristics = reader.read_u32()?;
        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_ptr,
            characteristics,
        });
    }
    Ok(sections)
}

fn add_sections(
    module: &mut ObjectModule,
    bytes: &[u8],
    headers: &[SectionHeader],
) -> Result<Vec<SectionId>> {
    let mut ids = Vec::with_capacity(headers.len());
    for header in headers {
        let file_bytes = if header.virtual_size == 0 {
            header.raw_size
        } else {
            header.raw_size.min(header.virtual_size)
        };
        let data_len =
            usize::try_from(file_bytes).map_err(|_| Error::ValueOutOfRange("section raw size"))?;
        let data = if data_len == 0 {
            Vec::new()
        } else {
            let start = usize::try_from(header.raw_ptr)
                .map_err(|_| Error::ValueOutOfRange("section raw pointer"))?;
            bytes_at(bytes, start, data_len)?.to_vec()
        };
        let name = module.intern(&header.name)?;
        let kind = classify_section(header);
        let flags = flags_for(header.characteristics);
        let size = u64::from(
            header
                .virtual_size
                .max(u32::try_from(data.len()).unwrap_or(0)),
        );
        let section = Section {
            name,
            kind,
            address: u64::from(header.virtual_address),
            align: u64::from(SECTION_ALIGNMENT),
            flags,
            data,
            size,
        };
        let id = module.add_section(section)?;
        ids.push(id);
    }
    Ok(ids)
}

fn classify_section(header: &SectionHeader) -> SectionKind {
    if header.characteristics & SCN_CNT_UNINITIALIZED_DATA != 0 {
        SectionKind::Bss
    } else if header.characteristics & SCN_CNT_CODE != 0
        || header.characteristics & SCN_MEM_EXECUTE != 0
    {
        SectionKind::Text
    } else if header.name.starts_with(".rdata") || header.name.starts_with(".edata") {
        SectionKind::ReadOnlyData
    } else if header.name.starts_with(".debug") {
        SectionKind::Debug
    } else if header.name.starts_with(".data") || header.name.starts_with(".idata") {
        SectionKind::Data
    } else {
        SectionKind::Other
    }
}

const fn flags_for(chars: u32) -> SectionFlags {
    SectionFlags {
        read: chars & SCN_MEM_READ != 0,
        write: chars & SCN_MEM_WRITE != 0,
        execute: chars & SCN_MEM_EXECUTE != 0,
    }
}

fn parse_imports(
    module: &mut ObjectModule,
    bytes: &[u8],
    sections: &[SectionHeader],
    dirs: &[Directory; 16],
    is_pe32_plus: bool,
) -> Result<()> {
    let dir = dir_at(dirs, DIRECTORY_IMPORT)?;
    if dir.rva == 0 || dir.size == 0 {
        return Ok(());
    }
    let mut offset = rva_to_offset(sections, dir.rva)?;
    let end = offset
        .checked_add(usize::try_from(dir.size).map_err(|_| Error::ValueOutOfRange("import dir"))?)
        .ok_or(Error::ValueOutOfRange("import dir"))?;
    loop {
        if offset
            .checked_add(20)
            .ok_or(Error::ValueOutOfRange("import descriptor"))?
            > end
        {
            return Err(Error::Malformed("unterminated import descriptor table"));
        }
        let mut r = reader_at(bytes, offset)?;
        let original_first_thunk = r.read_u32()?;
        r.skip(8)?;
        let name_rva = r.read_u32()?;
        let first_thunk = r.read_u32()?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            return Ok(());
        }
        let library = c_string(bytes, rva_to_offset(sections, name_rva)?)?;
        let thunk_rva = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        parse_import_thunks(module, bytes, sections, thunk_rva, &library, is_pe32_plus)?;
        offset = offset
            .checked_add(20)
            .ok_or(Error::ValueOutOfRange("import descriptor"))?;
    }
}

fn parse_import_thunks(
    module: &mut ObjectModule,
    bytes: &[u8],
    sections: &[SectionHeader],
    thunk_rva: u32,
    library: &str,
    is_pe32_plus: bool,
) -> Result<()> {
    let mut offset = rva_to_offset(sections, thunk_rva)?;
    loop {
        let value = if is_pe32_plus {
            read_u64_at(bytes, offset)?
        } else {
            u64::from(read_u32_at(bytes, offset)?)
        };
        if value == 0 {
            return Ok(());
        }
        let ordinal_flag = if is_pe32_plus {
            0x8000_0000_0000_0000_u64
        } else {
            0x8000_0000_u64
        };
        let (name, ordinal, hint) = if value & ordinal_flag != 0 {
            let ordinal = (value & 0xffff) as u16;
            (String::new(), Some(ordinal), 0)
        } else {
            let name_rva =
                u32::try_from(value).map_err(|_| Error::ValueOutOfRange("hint/name RVA"))?;
            let name_offset = rva_to_offset(sections, name_rva)?;
            let mut name_reader = reader_at(bytes, name_offset)?;
            let hint = name_reader.read_u16()?;
            (c_string(bytes, name_offset.saturating_add(2))?, None, hint)
        };
        let library_symbol = module.intern(library)?;
        let name_symbol = module.intern(&name)?;
        module.add_import(Import {
            library: library_symbol,
            name: name_symbol,
            ordinal,
            hint: Some(hint),
        });
        let thunk_size = if is_pe32_plus { 8usize } else { 4usize };
        offset = offset
            .checked_add(thunk_size)
            .ok_or(Error::ValueOutOfRange("thunk"))?;
    }
}

fn parse_exports(
    module: &mut ObjectModule,
    bytes: &[u8],
    sections: &[SectionHeader],
    dirs: &[Directory; 16],
) -> Result<()> {
    let dir = dir_at(dirs, DIRECTORY_EXPORT)?;
    if dir.rva == 0 || dir.size == 0 {
        return Ok(());
    }
    let offset = rva_to_offset(sections, dir.rva)?;
    let mut r = reader_at(bytes, offset)?;
    r.skip(16)?;
    let ordinal_base = r.read_u32()?;
    let address_count = r.read_u32()?;
    let name_count = r.read_u32()?;
    let address_table = r.read_u32()?;
    let name_table = r.read_u32()?;
    let ordinal_table = r.read_u32()?;
    for index in 0..name_count {
        let name_slot_rva = name_table.saturating_add(index.saturating_mul(4));
        let name_slot = rva_to_offset(sections, name_slot_rva)?;
        let name_rva = read_u32_at(bytes, name_slot)?;
        let ordinal_slot_rva = ordinal_table.saturating_add(index.saturating_mul(2));
        let ordinal_slot = rva_to_offset(sections, ordinal_slot_rva)?;
        let ordinal_index = read_u16_at(bytes, ordinal_slot)?;
        if u32::from(ordinal_index) >= address_count {
            return Err(Error::Malformed("export ordinal out of range"));
        }
        let address_slot_rva =
            address_table.saturating_add(u32::from(ordinal_index).saturating_mul(4));
        let address_slot = rva_to_offset(sections, address_slot_rva)?;
        let address = read_u32_at(bytes, address_slot)?;
        let export_name = c_string(bytes, rva_to_offset(sections, name_rva)?)?;
        let export_symbol = module.intern(&export_name)?;
        let ordinal = u16::try_from(ordinal_base.saturating_add(u32::from(ordinal_index)))
            .map_err(|_| Error::ValueOutOfRange("export ordinal"))?;
        module.add_export(Export {
            name: export_symbol,
            address: u64::from(address),
            ordinal: Some(ordinal),
        });
    }
    Ok(())
}

fn parse_relocs(bytes: &[u8], sections: &[SectionHeader], dirs: &[Directory; 16]) -> Result<()> {
    let dir = dir_at(dirs, DIRECTORY_BASERELOC)?;
    if dir.rva == 0 || dir.size == 0 {
        return Ok(());
    }
    let mut offset = rva_to_offset(sections, dir.rva)?;
    let end = offset
        .checked_add(usize::try_from(dir.size).map_err(|_| Error::ValueOutOfRange("reloc dir"))?)
        .ok_or(Error::ValueOutOfRange("reloc dir"))?;
    while offset < end {
        let mut r = reader_at(bytes, offset)?;
        let _page_rva = r.read_u32()?;
        let block_size = r.read_u32()?;
        if block_size < 8 || block_size % 2 != 0 {
            return Err(Error::Malformed("base relocation block size"));
        }
        let block_end = offset
            .checked_add(
                usize::try_from(block_size).map_err(|_| Error::ValueOutOfRange("reloc block"))?,
            )
            .ok_or(Error::ValueOutOfRange("reloc block"))?;
        if block_end > end {
            return Err(Error::Malformed("base relocation block overruns directory"));
        }
        offset = block_end;
    }
    Ok(())
}

fn parse_symbols(
    module: &mut ObjectModule,
    bytes: &[u8],
    _sections: &[SectionHeader],
    ids: &[SectionId],
    headers: &Headers,
) -> Result<()> {
    let _ = headers.optional_size;
    if headers.symbol_ptr == 0 || headers.symbol_count == 0 {
        return Ok(());
    }
    let table =
        usize::try_from(headers.symbol_ptr).map_err(|_| Error::ValueOutOfRange("symtab"))?;
    let count =
        usize::try_from(headers.symbol_count).map_err(|_| Error::ValueOutOfRange("symtab"))?;
    let table_bytes = count
        .checked_mul(
            usize::try_from(SYMBOL_TABLE_ENTRY_SIZE)
                .map_err(|_| Error::ValueOutOfRange("symtab"))?,
        )
        .ok_or(Error::ValueOutOfRange("symtab"))?;
    let strings = table
        .checked_add(table_bytes)
        .ok_or(Error::ValueOutOfRange("symtab"))?;
    let mut index = 0usize;
    while index < count {
        let entry_off = table
            .checked_add(
                index
                    .checked_mul(18)
                    .ok_or(Error::ValueOutOfRange("symtab"))?,
            )
            .ok_or(Error::ValueOutOfRange("symtab"))?;
        let mut r = reader_at(bytes, entry_off)?;
        let raw_name = r.read_bytes(8)?;
        let name = symbol_name(bytes, strings, raw_name)?;
        let value = r.read_u32()?;
        let section_number = r.read_u16()?;
        let ty = r.read_u16()?;
        let class = r.read_u8()?;
        let aux = usize::from(r.read_u8()?);
        let section = if section_number == 0 {
            None
        } else {
            ids.get(usize::from(section_number).saturating_sub(1))
                .copied()
        };
        let binding = if class == SYM_CLASS_EXTERNAL {
            SymbolBinding::Global
        } else {
            SymbolBinding::Local
        };
        let flags = if section_number == 0 && class == SYM_CLASS_EXTERNAL {
            SymbolFlags::imported()
        } else {
            SymbolFlags::none()
        };
        let kind = if ty & SYM_DTYPE_FUNCTION != 0 {
            SymbolKind::Function
        } else if section.is_some() && value == 0 && name.starts_with('.') {
            SymbolKind::Section
        } else if section.is_some() {
            SymbolKind::Object
        } else {
            SymbolKind::None
        };
        let interned = module.intern(&name)?;
        let symbol = SymbolEntry {
            name: interned,
            value: u64::from(value),
            size: 0,
            section,
            kind,
            binding,
            flags,
        };
        module.add_symbol(symbol)?;
        index = index
            .checked_add(1)
            .and_then(|v| v.checked_add(aux))
            .ok_or(Error::ValueOutOfRange("symtab"))?;
    }
    Ok(())
}

fn symbol_name(bytes: &[u8], strings: usize, raw_name: &[u8]) -> Result<String> {
    let zeroes = raw_name.get(0..4).ok_or(Error::Malformed("symbol name"))?;
    if zeroes == [0, 0, 0, 0] {
        let offset_bytes: [u8; 4] = raw_name
            .get(4..8)
            .ok_or(Error::Malformed("symbol string offset"))?
            .try_into()
            .map_err(|_| Error::Malformed("symbol string offset"))?;
        let offset = usize::try_from(u32::from_le_bytes(offset_bytes))
            .map_err(|_| Error::ValueOutOfRange("symbol string offset"))?;
        return c_string(bytes, strings.saturating_add(offset));
    }
    let len = raw_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(raw_name.len());
    let name = core::str::from_utf8(
        raw_name
            .get(0..len)
            .ok_or(Error::Malformed("symbol name"))?,
    )
    .map_err(|_| Error::Malformed("symbol name is not UTF-8"))?;
    Ok(name.to_owned())
}

fn dir_at(dirs: &[Directory; 16], index: usize) -> Result<Directory> {
    dirs.get(index)
        .copied()
        .ok_or(Error::Malformed("data directory"))
}

fn rva_to_offset(sections: &[SectionHeader], rva: u32) -> Result<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size).max(1);
        let end = section
            .virtual_address
            .checked_add(span)
            .ok_or(Error::ValueOutOfRange("section RVA"))?;
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            let file = section
                .raw_ptr
                .checked_add(delta)
                .ok_or(Error::ValueOutOfRange("file offset"))?;
            return usize::try_from(file).map_err(|_| Error::ValueOutOfRange("file offset"));
        }
    }
    Err(Error::Malformed("RVA outside sections"))
}

fn bytes_at(bytes: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or(Error::ValueOutOfRange("slice"))?;
    bytes.get(start..end).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: len,
        len: bytes.len(),
    })
}

fn reader_at(bytes: &[u8], offset: usize) -> Result<ByteReader<'_>> {
    // Use one bounds check: the previous bytes_at(..., 0) pre-check returned the same error first,
    // making this defensive out-of-range path unreachable to tests and coverage.
    let slice = bytes.get(offset..).ok_or(Error::UnexpectedEof {
        offset,
        needed: 0,
        len: bytes.len(),
    })?;
    Ok(ByteReader::new(slice, Endianness::Little))
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let mut r = reader_at(bytes, offset)?;
    r.read_u16()
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let mut r = reader_at(bytes, offset)?;
    r.read_u32()
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let mut r = reader_at(bytes, offset)?;
    r.read_u64()
}

fn c_string(bytes: &[u8], offset: usize) -> Result<String> {
    let tail = bytes.get(offset..).ok_or(Error::UnexpectedEof {
        offset,
        needed: 1,
        len: bytes.len(),
    })?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated string"))?;
    let raw = tail.get(0..len).ok_or(Error::Malformed("string"))?;
    core::str::from_utf8(raw)
        .map(str::to_owned)
        .map_err(|_| Error::Malformed("string is not UTF-8"))
}

const _: u32 = SECTION_HEADER_SIZE;

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::consts::{
        OPTIONAL_HEADER_SIZE_PE32PLUS, SCN_CNT_INITIALIZED_DATA, SYM_CLASS_STATIC,
    };
    use crate::{samples, write};
    use stratum_oir::{BinaryFormat, ByteWriter};

    fn sample_bytes() -> Vec<u8> {
        write(&samples::hello_world_x86_64_windows().unwrap()).unwrap()
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes
            .get_mut(offset..offset.saturating_add(2))
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes
            .get_mut(offset..offset.saturating_add(4))
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes
            .get_mut(offset..offset.saturating_add(8))
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }

    fn pe_offset(bytes: &[u8]) -> usize {
        let raw: [u8; 4] = bytes
            .get(E_LFANEW_OFFSET..E_LFANEW_OFFSET.saturating_add(4))
            .and_then(|slice| slice.try_into().ok())
            .unwrap();
        usize::try_from(u32::from_le_bytes(raw)).unwrap()
    }

    fn section() -> SectionHeader {
        SectionHeader {
            name: ".test".to_owned(),
            virtual_size: 0x100,
            virtual_address: 0x1000,
            raw_size: 0x100,
            raw_ptr: 0,
            characteristics: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
        }
    }

    fn dirs_with(index: usize, rva: u32, size: u32) -> [Directory; 16] {
        let mut dirs = [Directory { rva: 0, size: 0 }; 16];
        let slot = dirs.get_mut(index).unwrap();
        *slot = Directory { rva, size };
        dirs
    }

    #[test]
    fn rejects_header_class_and_signature_errors() {
        let mut missing_pe_offset = alloc::vec![0u8; E_LFANEW_OFFSET];
        put_u16(&mut missing_pe_offset, 0, DOS_MAGIC);
        assert!(read(&missing_pe_offset).is_err());

        let mut pe_offset_out_of_bounds = alloc::vec![0u8; E_LFANEW_OFFSET + 4];
        put_u16(&mut pe_offset_out_of_bounds, 0, DOS_MAGIC);
        put_u32(&mut pe_offset_out_of_bounds, E_LFANEW_OFFSET, 0x100);
        assert!(read(&pe_offset_out_of_bounds).is_err());

        let mut missing_pe_signature = alloc::vec![0u8; E_LFANEW_OFFSET + 4];
        put_u16(&mut missing_pe_signature, 0, DOS_MAGIC);
        put_u32(
            &mut missing_pe_signature,
            E_LFANEW_OFFSET,
            u32::try_from(E_LFANEW_OFFSET + 4).unwrap(),
        );
        assert!(read(&missing_pe_signature).is_err());

        let mut bad_sig = sample_bytes();
        let pe = pe_offset(&bad_sig);
        put_u32(&mut bad_sig, pe, 0);
        assert!(read(&bad_sig).is_err());

        let mut bad_magic = sample_bytes();
        let pe = pe_offset(&bad_magic);
        put_u16(&mut bad_magic, pe + 4 + 20, 0);
        assert!(read(&bad_magic).is_err());

        let mut optional_overrun = sample_bytes();
        let pe = pe_offset(&optional_overrun);
        put_u16(&mut optional_overrun, pe + 4 + 16, 2);
        assert!(read(&optional_overrun).is_err());

        let mut unsupported_machine = sample_bytes();
        let pe = pe_offset(&unsupported_machine);
        put_u16(&mut unsupported_machine, pe + 4, 0xffff);
        assert!(read(&unsupported_machine).is_err());

        let mut mismatched_class = sample_bytes();
        let pe = pe_offset(&mismatched_class);
        put_u16(&mut mismatched_class, pe + 4, IMAGE_FILE_MACHINE_I386);
        assert!(read(&mismatched_class).is_err());

        let pe32 = write(&samples::pe32_import_fixture().unwrap()).unwrap();
        assert_eq!(read(&pe32).unwrap().target().arch, Architecture::X86);
        for arch in [Architecture::Arm, Architecture::Aarch64] {
            let module = samples::machine_fixture(arch).unwrap();
            let bytes = write(&module).unwrap();
            assert_eq!(read(&bytes).unwrap().target().arch, arch);
        }

        let mut bad_import = sample_bytes();
        let pe = pe_offset(&bad_import);
        let import_size_off = pe + 4 + 20 + 112 + 8 + 4;
        put_u32(&mut bad_import, import_size_off, 20);
        assert!(read(&bad_import).is_err());
    }

    #[test]
    fn section_helpers_cover_empty_bss_debug_and_rva_errors() {
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        let raw_only = SectionHeader {
            name: ".raw".to_owned(),
            virtual_size: 0,
            virtual_address: 0x1000,
            raw_size: 1,
            raw_ptr: 0,
            characteristics: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
        };
        let empty = SectionHeader {
            name: ".empty".to_owned(),
            virtual_size: 0,
            virtual_address: 0x2000,
            raw_size: 0,
            raw_ptr: 0,
            characteristics: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
        };
        let ids = add_sections(&mut module, &[0xAA], &[raw_only.clone(), empty]).unwrap();
        assert_eq!(ids.len(), 2);

        let bss = SectionHeader {
            characteristics: SCN_CNT_UNINITIALIZED_DATA,
            ..raw_only.clone()
        };
        assert_eq!(classify_section(&bss), SectionKind::Bss);
        let debug = SectionHeader {
            name: ".debug_info".to_owned(),
            ..raw_only.clone()
        };
        assert_eq!(classify_section(&debug), SectionKind::Debug);
        let rdata = SectionHeader {
            name: ".rdata".to_owned(),
            ..raw_only
        };
        assert_eq!(classify_section(&rdata), SectionKind::ReadOnlyData);
        assert!(rva_to_offset(&[section()], 0x5000).is_err());

        let dirs = [Directory { rva: 0, size: 0 }; 16];
        let mut no_imports = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        parse_imports(&mut no_imports, &[], &[], &dirs, true).unwrap();
        parse_relocs(&[], &[], &dirs).unwrap();
        let headers = Headers {
            machine: IMAGE_FILE_MACHINE_AMD64,
            sections: 0,
            symbol_ptr: 0,
            symbol_count: 0,
            optional_size: OPTIONAL_HEADER_SIZE_PE32PLUS,
            entry: 0,
            is_pe32_plus: true,
            directories: dirs,
        };
        parse_symbols(&mut no_imports, &[], &[], &[], &headers).unwrap();
        assert!(reader_at(&[], 1).is_err());
        assert!(c_string(&[], 1).is_err());
        assert!(c_string(b"\xff\0", 0).is_err());
    }

    #[test]
    fn import_tables_cover_ordinal_and_bad_pe32_plus_name_rva() {
        let mut bytes = alloc::vec![0u8; 0x60];
        put_u32(&mut bytes, 12, 0x1030);
        put_u32(&mut bytes, 16, 0x1040);
        bytes
            .get_mut(0x30..0x34)
            .unwrap()
            .copy_from_slice(b"x\0\0\0");
        put_u32(&mut bytes, 0x40, 0x8000_0007);
        let sections = [section()];
        let dirs = dirs_with(DIRECTORY_IMPORT, 0x1000, 0x60);
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86());
        parse_imports(&mut module, &bytes, &sections, &dirs, false).unwrap();
        let import = module.imports().first().unwrap();
        assert_eq!(import.ordinal, Some(7));

        let mut named_thunk = alloc::vec![0u8; 0x20];
        put_u64(&mut named_thunk, 0, 0x1010);
        put_u16(&mut named_thunk, 0x10, 3);
        named_thunk
            .get_mut(0x12..0x15)
            .unwrap()
            .copy_from_slice(b"Fn\0");
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        parse_import_thunks(&mut module, &named_thunk, &sections, 0x1000, "x", true).unwrap();

        let mut bad_thunk = alloc::vec![0u8; 8];
        put_u64(&mut bad_thunk, 0, 0x0000_0001_0000_0000);
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        assert!(
            parse_import_thunks(&mut module, &bad_thunk, &sections, 0x1000, "x", true).is_err()
        );
    }

    #[test]
    fn export_and_reloc_malformed_paths_are_rejected() {
        let sections = [section()];
        let mut export_bytes = alloc::vec![0u8; 0x60];
        put_u32(&mut export_bytes, 16, 1);
        put_u32(&mut export_bytes, 20, 0);
        put_u32(&mut export_bytes, 24, 1);
        put_u32(&mut export_bytes, 28, 0x1050);
        put_u32(&mut export_bytes, 32, 0x1040);
        put_u32(&mut export_bytes, 36, 0x1048);
        put_u32(&mut export_bytes, 0x40, 0x1058);
        put_u16(&mut export_bytes, 0x48, 0);
        let dirs = dirs_with(DIRECTORY_EXPORT, 0x1000, 0x60);
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        assert!(parse_exports(&mut module, &export_bytes, &sections, &dirs).is_err());

        put_u32(&mut export_bytes, 20, 1);
        put_u32(&mut export_bytes, 0x50, 0x1000);
        export_bytes
            .get_mut(0x58..0x5d)
            .unwrap()
            .copy_from_slice(b"main\0");
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        parse_exports(&mut module, &export_bytes, &sections, &dirs).unwrap();
        assert_eq!(module.exports().len(), 1);

        let mut bad_size = alloc::vec![0u8; 8];
        put_u32(&mut bad_size, 4, 7);
        let dirs = dirs_with(DIRECTORY_BASERELOC, 0x1000, 8);
        assert!(parse_relocs(&bad_size, &sections, &dirs).is_err());

        let mut overrun = alloc::vec![0u8; 8];
        put_u32(&mut overrun, 4, 12);
        let dirs = dirs_with(DIRECTORY_BASERELOC, 0x1000, 8);
        assert!(parse_relocs(&overrun, &sections, &dirs).is_err());

        let mut ok_block = alloc::vec![0u8; 8];
        put_u32(&mut ok_block, 4, 8);
        let dirs = dirs_with(DIRECTORY_BASERELOC, 0x1000, 8);
        parse_relocs(&ok_block, &sections, &dirs).unwrap();
    }

    fn write_symbol_entry(
        w: &mut ByteWriter,
        name: &[u8],
        value: u32,
        section_number: u16,
        ty: u16,
        class: u8,
    ) {
        w.write_bytes(name);
        w.write_u32(value);
        w.write_u16(section_number);
        w.write_u16(ty);
        w.write_u8(class);
        w.write_u8(0);
    }

    #[test]
    fn symbol_table_covers_long_names_and_all_symbol_kinds() {
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        let text_name = module.intern(".text").unwrap();
        let section_id = module
            .add_section(Section {
                name: text_name,
                kind: SectionKind::Text,
                address: 0x1000,
                align: 1,
                flags: SectionFlags::code(),
                data: alloc::vec![0xC3],
                size: 1,
            })
            .unwrap();
        let ids = [section_id];
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_zeros(4);
        write_symbol_entry(
            &mut w,
            &[0, 0, 0, 0, 4, 0, 0, 0],
            0,
            0,
            0,
            SYM_CLASS_EXTERNAL,
        );
        write_symbol_entry(&mut w, b"local\0\0\0", 0, 0, 0, SYM_CLASS_STATIC);
        write_symbol_entry(
            &mut w,
            b"func\0\0\0\0",
            1,
            1,
            SYM_DTYPE_FUNCTION,
            SYM_CLASS_EXTERNAL,
        );
        write_symbol_entry(&mut w, b".text\0\0\0", 0, 1, 0, SYM_CLASS_STATIC);
        write_symbol_entry(&mut w, b"object\0\0", 1, 1, 0, SYM_CLASS_STATIC);
        w.write_u32(16);
        w.write_bytes(b"long_name\0");
        let bytes = w.finish().unwrap();
        let headers = Headers {
            machine: IMAGE_FILE_MACHINE_AMD64,
            sections: 1,
            symbol_ptr: 4,
            symbol_count: 5,
            optional_size: OPTIONAL_HEADER_SIZE_PE32PLUS,
            entry: 0,
            is_pe32_plus: true,
            directories: [Directory { rva: 0, size: 0 }; 16],
        };
        parse_symbols(&mut module, &bytes, &[], &ids, &headers).unwrap();
        assert!(module.symbol_count() >= 5);
    }
}
