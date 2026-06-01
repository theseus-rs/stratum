//! Serializes an [`ObjectModule`] into a canonical, loadable PE executable.

use crate::consts::{
    COFF_HEADER_SIZE, DIRECTORY_BASERELOC, DIRECTORY_EXPORT, DIRECTORY_IMPORT, DOS_MAGIC,
    E_LFANEW_OFFSET, FILE_ALIGNMENT, IMAGE_BASE32, IMAGE_BASE64, IMAGE_FILE_32BIT_MACHINE,
    IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386,
    NUMBER_OF_DIRECTORIES, OPTIONAL_HEADER_SIZE_PE32, OPTIONAL_HEADER_SIZE_PE32PLUS,
    OPTIONAL_MAGIC_PE32, OPTIONAL_MAGIC_PE32PLUS, PE_SIGNATURE, SCN_CNT_CODE,
    SCN_CNT_INITIALIZED_DATA, SCN_CNT_UNINITIALIZED_DATA, SCN_MEM_EXECUTE, SCN_MEM_READ,
    SCN_MEM_WRITE, SECTION_ALIGNMENT, SECTION_HEADER_SIZE, SUBSYSTEM_WINDOWS_CUI,
    SYM_CLASS_EXTERNAL, SYM_CLASS_STATIC, SYM_DTYPE_FUNCTION,
};
use stratum_oir::{
    Architecture, ByteWriter, Error, ObjectModule, PtrWidth, Result, Section, SectionId,
    SectionKind, SymbolBinding, SymbolKind,
};

extern crate alloc;
use alloc::vec::Vec;

const DOS_HEADER_SIZE: u32 = 0x40;

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

fn rva(section: &Section) -> Result<u32> {
    u32::try_from(section.address).map_err(|_| Error::ValueOutOfRange("section RVA"))
}

fn virtual_size(section: &Section) -> Result<u32> {
    let size = section.vm_size().max(section.file_size());
    u32::try_from(size).map_err(|_| Error::ValueOutOfRange("section virtual size"))
}

fn characteristics(section: &Section) -> u32 {
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

/// Computed file/RVA placement for one section.
struct Placement {
    id: SectionId,
    rva: u32,
    virtual_size: u32,
    file_offset: u32,
    raw_size: u32,
}

fn name_bytes(module: &ObjectModule, section: &Section) -> Result<[u8; 8]> {
    let name = module.resolve(section.name)?;
    let raw = name.as_bytes();
    if raw.len() > 8 {
        return Err(Error::Unsupported("PE section name longer than 8 bytes"));
    }
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(raw) {
        *slot = *byte;
    }
    Ok(out)
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
    let sections: Vec<(SectionId, &Section)> = module.sections().collect();
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
    for (id, section) in &sections {
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
            id: *id,
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

    let size_of_image = sections
        .iter()
        .zip(&placements)
        .map(|(_, p)| align_up(p.rva.saturating_add(p.virtual_size), SECTION_ALIGNMENT))
        .max()
        .unwrap_or(align_up(size_of_headers, SECTION_ALIGNMENT));

    let directories = data_directories(module, &sections, &placements)?;
    let symbols = CoffSymbols::new(module, &sections, file_cursor)?;

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
        symbols,
    };

    emit(module, &sections, &placements, &layout)
}

#[derive(Clone, Copy)]
struct DataDir {
    rva: u32,
    size: u32,
}

fn data_directories(
    module: &ObjectModule,
    sections: &[(SectionId, &Section)],
    placements: &[Placement],
) -> Result<[DataDir; 16]> {
    let mut dirs = [DataDir { rva: 0, size: 0 }; 16];
    for ((_, section), placement) in sections.iter().zip(placements) {
        let name = module.resolve(section.name)?;
        let dir = match name {
            ".edata" => Some(DIRECTORY_EXPORT),
            ".idata" => Some(DIRECTORY_IMPORT),
            ".reloc" => Some(DIRECTORY_BASERELOC),
            _ => None,
        };
        if let Some(index) = dir
            && let Some(slot) = dirs.get_mut(index)
        {
            *slot = DataDir {
                rva: placement.rva,
                size: u32_of(section.data.len(), "data directory size")?,
            };
        }
    }
    Ok(dirs)
}

struct CoffSymbols {
    bytes: Vec<u8>,
    pointer: u32,
    count: u32,
}

impl CoffSymbols {
    fn new(
        module: &ObjectModule,
        sections: &[(SectionId, &Section)],
        pointer: u32,
    ) -> Result<Self> {
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

fn section_number(sections: &[(SectionId, &Section)], id: SectionId) -> Option<u16> {
    for (index, (section_id, _)) in sections.iter().enumerate() {
        if *section_id == id {
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
    symbols: CoffSymbols,
}

fn emit(
    module: &ObjectModule,
    sections: &[(SectionId, &Section)],
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
    for ((_, section), placement) in sections.iter().zip(placements) {
        write_section_header(&mut w, module, section, placement)?;
    }

    for ((_, section), placement) in sections.iter().zip(placements) {
        if placement.raw_size == 0 {
            continue;
        }
        pad_to(&mut w, placement.file_offset)?;
        w.write_bytes(&section.data);
        pad_to(&mut w, placement.file_offset + placement.raw_size)?;
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
    sections: &[(SectionId, &Section)],
    placements: &[Placement],
    layout: &Layout,
) {
    let mut size_of_code = 0u32;
    let mut size_of_init = 0u32;
    let mut size_of_uninit = 0u32;
    let mut base_of_code = 0u32;
    let mut base_of_data = 0u32;
    for ((_, section), placement) in sections.iter().zip(placements) {
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
    module: &ObjectModule,
    section: &Section,
    placement: &Placement,
) -> Result<()> {
    let _ = placement.id;
    w.write_bytes(&name_bytes(module, section)?);
    w.write_u32(placement.virtual_size);
    w.write_u32(placement.rva);
    w.write_u32(placement.raw_size);
    w.write_u32(placement.file_offset);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u16(0);
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
        BinaryFormat, Endianness, SectionFlags, SymbolEntry, SymbolFlags, TargetSpec,
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

        let mut module = module(TargetSpec::x86_64());
        let name = module.intern(".bss").unwrap();
        let bss = Section {
            name,
            kind: SectionKind::Bss,
            address: 0,
            align: 1,
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
        let sections: Vec<(SectionId, &Section)> = module.sections().collect();
        assert_eq!(section_number(&sections, id), Some(1));

        assert_eq!(section_number(&sections, SectionId::from_raw(99)), None);

        let mut writer = ByteWriter::new(Endianness::Little);
        writer.write_u8(1);
        assert!(pad_to(&mut writer, 0).is_err());
    }
}
