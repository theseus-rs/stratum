//! Parses WebAssembly binary modules into [`ObjectModule`].

use crate::consts::{
    DESC_FUNC, DESC_GLOBAL, DESC_MEMORY, DESC_TABLE, EXPORT_START, OP_END, OP_I32_CONST,
    SECTION_CODE, SECTION_CUSTOM, SECTION_DATA, SECTION_DATA_COUNT, SECTION_ELEMENT,
    SECTION_EXPORT, SECTION_FUNCTION, SECTION_GLOBAL, SECTION_IMPORT, SECTION_MAX_STANDARD,
    SECTION_MEMORY, SECTION_START, SECTION_TABLE, SECTION_TYPE, TYPE_FUNC, WASM_MAGIC,
    WASM_VERSION,
};
use crate::write::ENTRY_FUNC_INDEX;
use stratum_oir::{
    BinaryFormat, ByteReader, Error, Export, Import, ObjectModule, Result, Section, SectionFlags,
    SectionKind, SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::string::{String, ToString};

#[derive(Clone, Copy)]
struct Counts {
    types: u64,
    imported_funcs: u64,
    functions: u64,
    data_count: Option<u64>,
}

impl Counts {
    const fn new() -> Self {
        Self {
            types: 0,
            imported_funcs: 0,
            functions: 0,
            data_count: None,
        }
    }
}

fn u64_to_usize(value: u64, what: &'static str) -> Result<usize> {
    u64_to_usize_with_max(value, what, usize::MAX as u64)
}

fn u64_to_usize_with_max(value: u64, what: &'static str, max: u64) -> Result<usize> {
    if value > max {
        return Err(Error::ValueOutOfRange(what));
    }
    usize::try_from(value).or(Err(Error::ValueOutOfRange(what)))
}

fn ensure_empty(r: &ByteReader<'_>) -> Result<()> {
    if r.remaining() == 0 {
        Ok(())
    } else {
        Err(Error::Malformed("section has trailing bytes"))
    }
}

fn read_name(r: &mut ByteReader<'_>) -> Result<String> {
    let len = r.read_uleb128()?;
    let len = u64_to_usize(len, "name length")?;
    let bytes = r.read_bytes(len)?;
    let value = core::str::from_utf8(bytes).map_err(|_| Error::Malformed("invalid UTF-8 name"))?;
    Ok(value.to_string())
}

fn section_rank(id: u8) -> u8 {
    match id {
        SECTION_TYPE => 1,
        SECTION_IMPORT => 2,
        SECTION_FUNCTION => 3,
        SECTION_TABLE => 4,
        SECTION_MEMORY => 5,
        SECTION_GLOBAL => 6,
        SECTION_EXPORT => 7,
        SECTION_START => 8,
        SECTION_ELEMENT => 9,
        SECTION_DATA_COUNT => 10,
        SECTION_CODE => 11,
        SECTION_DATA => 12,
        _ => 0,
    }
}

fn section_name(id: u8, payload: &[u8]) -> Result<&'static str> {
    match id {
        SECTION_CUSTOM => {
            let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
            let name = read_name(&mut r)?;
            if name == "name" {
                Ok("wasm.custom.name")
            } else {
                Ok("wasm.custom")
            }
        }
        SECTION_TYPE => Ok("wasm.type"),
        SECTION_IMPORT => Ok("wasm.import"),
        SECTION_FUNCTION => Ok("wasm.function"),
        SECTION_TABLE => Ok("wasm.table"),
        SECTION_MEMORY => Ok("wasm.memory"),
        SECTION_GLOBAL => Ok("wasm.global"),
        SECTION_EXPORT => Ok("wasm.export"),
        SECTION_START => Ok("wasm.start"),
        SECTION_ELEMENT => Ok("wasm.element"),
        SECTION_CODE => Ok("wasm.code"),
        SECTION_DATA => Ok("wasm.data"),
        SECTION_DATA_COUNT => Ok("wasm.data_count"),
        _ => Err(Error::Malformed("bad section id")),
    }
}

fn section_kind(id: u8, name: &str) -> SectionKind {
    match id {
        SECTION_CODE => SectionKind::Text,
        SECTION_DATA => SectionKind::Data,
        SECTION_CUSTOM if matches_name_section(name) => SectionKind::Debug,
        _ => SectionKind::Other,
    }
}

fn matches_name_section(name: &str) -> bool {
    name == "wasm.custom.name"
}

const fn section_flags(kind: SectionKind) -> SectionFlags {
    match kind {
        SectionKind::Text => SectionFlags::code(),
        SectionKind::Data => SectionFlags::data(),
        _ => SectionFlags::read_only(),
    }
}

fn validate_value_type(value: u8) -> Result<()> {
    match value {
        0x7F | 0x7E | 0x7D | 0x7C | 0x70 | 0x6F => Ok(()),
        _ => Err(Error::Malformed("bad value type")),
    }
}

fn read_limits(r: &mut ByteReader<'_>) -> Result<()> {
    match r.read_u8()? {
        0x00 => {
            let _ = r.read_uleb128()?;
            Ok(())
        }
        0x01 => {
            let min = r.read_uleb128()?;
            let max = r.read_uleb128()?;
            if min > max {
                return Err(Error::Malformed("limits minimum exceeds maximum"));
            }
            Ok(())
        }
        _ => Err(Error::Malformed("bad limits flags")),
    }
}

fn read_table_type(r: &mut ByteReader<'_>) -> Result<()> {
    match r.read_u8()? {
        0x70 | 0x6F => read_limits(r),
        _ => Err(Error::Malformed("bad reference type")),
    }
}

fn read_global_type(r: &mut ByteReader<'_>) -> Result<()> {
    validate_value_type(r.read_u8()?)?;
    match r.read_u8()? {
        0x00 | 0x01 => Ok(()),
        _ => Err(Error::Malformed("bad mutability")),
    }
}

fn read_const_expr(r: &mut ByteReader<'_>) -> Result<()> {
    loop {
        let op = r.read_u8()?;
        match op {
            OP_END => return Ok(()),
            OP_I32_CONST | 0x42 => {
                let _ = r.read_sleb128()?;
            }
            0x43 => {
                let _ = r.read_u32()?;
            }
            0x44 => {
                let _ = r.read_u64()?;
            }
            0x23 | 0xD2 => {
                let _ = r.read_uleb128()?;
            }
            _ => return Err(Error::Malformed("unsupported const expr opcode")),
        }
    }
}

fn validate_type(payload: &[u8], counts: &mut Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        if r.read_u8()? != TYPE_FUNC {
            return Err(Error::Malformed("bad type form"));
        }
        let params = r.read_uleb128()?;
        for _ in 0..params {
            validate_value_type(r.read_u8()?)?;
        }
        let results = r.read_uleb128()?;
        for _ in 0..results {
            validate_value_type(r.read_u8()?)?;
        }
    }
    ensure_empty(&r)?;
    counts.types = count;
    Ok(())
}

fn add_symbol(module: &mut ObjectModule, name: &str, kind: SymbolKind, index: u64) -> Result<()> {
    let name = module.intern(name)?;
    let symbol = SymbolEntry {
        name,
        kind,
        binding: SymbolBinding::Global,
        section: None,
        value: index,
        size: 0,
        flags: SymbolFlags::none(),
    };
    let _ = module.add_symbol(symbol)?;
    Ok(())
}

fn validate_import(payload: &[u8], module: &mut ObjectModule, counts: &mut Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        let library = read_name(&mut r)?;
        let name = read_name(&mut r)?;
        let desc = r.read_u8()?;
        match desc {
            DESC_FUNC => {
                let type_index = r.read_uleb128()?;
                if type_index >= counts.types {
                    return Err(Error::Malformed("function import type out of range"));
                }
                counts.imported_funcs = counts
                    .imported_funcs
                    .checked_add(1)
                    .ok_or(Error::ValueOutOfRange("function import count"))?;
                let index = counts.imported_funcs - 1;
                add_symbol(module, &name, SymbolKind::Function, index)?;
            }
            DESC_TABLE => read_table_type(&mut r)?,
            DESC_MEMORY => read_limits(&mut r)?,
            DESC_GLOBAL => read_global_type(&mut r)?,
            _ => return Err(Error::Malformed("bad import descriptor")),
        }
        let library = module.intern(&library)?;
        let name = module.intern(&name)?;
        module.add_import(Import {
            library,
            name,
            ordinal: None,
            hint: None,
        });
    }
    ensure_empty(&r)
}

fn validate_function(payload: &[u8], counts: &mut Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        let type_index = r.read_uleb128()?;
        if type_index >= counts.types {
            return Err(Error::Malformed("function type out of range"));
        }
    }
    ensure_empty(&r)?;
    counts.functions = count;
    Ok(())
}

fn validate_table(payload: &[u8]) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        read_table_type(&mut r)?;
    }
    ensure_empty(&r)
}

fn validate_memory(payload: &[u8]) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        read_limits(&mut r)?;
    }
    ensure_empty(&r)
}

fn validate_global(payload: &[u8]) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        read_global_type(&mut r)?;
        read_const_expr(&mut r)?;
    }
    ensure_empty(&r)
}

fn validate_export(payload: &[u8], module: &mut ObjectModule) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        let name = read_name(&mut r)?;
        let desc = r.read_u8()?;
        let index = r.read_uleb128()?;
        let kind = match desc {
            DESC_FUNC => SymbolKind::Function,
            DESC_TABLE => SymbolKind::None,
            DESC_MEMORY | DESC_GLOBAL => SymbolKind::Object,
            _ => return Err(Error::Malformed("bad export descriptor")),
        };
        if desc == DESC_FUNC {
            add_symbol(module, &name, kind, index)?;
            if name == EXPORT_START {
                module.set_entry(index);
            }
        }
        let name = module.intern(&name)?;
        module.add_export(Export {
            name,
            address: index,
            ordinal: None,
        });
    }
    ensure_empty(&r)
}

fn validate_start(payload: &[u8], module: &mut ObjectModule, counts: Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let index = r.read_uleb128()?;
    if index >= counts.imported_funcs + counts.functions {
        return Err(Error::Malformed("start function out of range"));
    }
    module.set_entry(index);
    ensure_empty(&r)
}

fn validate_element(payload: &[u8]) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    for _ in 0..count {
        let flags = r.read_uleb128()?;
        match flags {
            0 => {
                read_const_expr(&mut r)?;
                let funcs = r.read_uleb128()?;
                for _ in 0..funcs {
                    let _ = r.read_uleb128()?;
                }
            }
            1 => {
                let kind = r.read_u8()?;
                if kind != 0x00 {
                    return Err(Error::Malformed("bad element kind"));
                }
                let funcs = r.read_uleb128()?;
                for _ in 0..funcs {
                    let _ = r.read_uleb128()?;
                }
            }
            2 => {
                let _ = r.read_uleb128()?;
                read_const_expr(&mut r)?;
                let kind = r.read_u8()?;
                if kind != 0x00 {
                    return Err(Error::Malformed("bad element kind"));
                }
                let funcs = r.read_uleb128()?;
                for _ in 0..funcs {
                    let _ = r.read_uleb128()?;
                }
            }
            _ => return Err(Error::Malformed("unsupported element segment")),
        }
    }
    ensure_empty(&r)
}

fn validate_code(payload: &[u8], counts: Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    if count != counts.functions {
        return Err(Error::Malformed("function/code count mismatch"));
    }
    for _ in 0..count {
        let size = r.read_uleb128()?;
        let size = u64_to_usize(size, "body length")?;
        let body = r.read_bytes(size)?;
        let mut body_reader = ByteReader::new(body, stratum_oir::Endianness::Little);
        let local_count = body_reader.read_uleb128()?;
        for _ in 0..local_count {
            let _ = body_reader.read_uleb128()?;
            validate_value_type(body_reader.read_u8()?)?;
        }
        if body_reader.remaining() == 0 {
            return Err(Error::Malformed("empty function expression"));
        }
    }
    ensure_empty(&r)
}

fn validate_data(payload: &[u8], counts: Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    if let Some(expected) = counts.data_count
        && count != expected
    {
        return Err(Error::Malformed("data count mismatch"));
    }
    for _ in 0..count {
        let flags = r.read_uleb128()?;
        match flags {
            0 => read_const_expr(&mut r)?,
            1 => {}
            2 => {
                let _ = r.read_uleb128()?;
                read_const_expr(&mut r)?;
            }
            _ => return Err(Error::Malformed("unsupported data segment")),
        }
        let len = r.read_uleb128()?;
        let len = u64_to_usize(len, "data length")?;
        let _ = r.read_bytes(len)?;
    }
    ensure_empty(&r)
}

fn validate_data_count(payload: &[u8], counts: &mut Counts) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let count = r.read_uleb128()?;
    ensure_empty(&r)?;
    counts.data_count = Some(count);
    Ok(())
}

fn validate_name(payload: &[u8]) -> Result<()> {
    let mut r = ByteReader::new(payload, stratum_oir::Endianness::Little);
    let name = read_name(&mut r)?;
    if name != "name" {
        return Ok(());
    }
    let mut last_subsection = 0;
    while r.remaining() > 0 {
        let id = r.read_u8()?;
        if id != 0 && id <= last_subsection {
            return Err(Error::Malformed("name subsections out of order"));
        }
        if id != 0 {
            last_subsection = id;
        }
        let size = r.read_uleb128()?;
        let size = u64_to_usize(size, "name subsection")?;
        let _ = r.read_bytes(size)?;
    }
    Ok(())
}

fn validate_section(
    id: u8,
    payload: &[u8],
    module: &mut ObjectModule,
    counts: &mut Counts,
) -> Result<()> {
    match id {
        SECTION_CUSTOM => validate_name(payload),
        SECTION_TYPE => validate_type(payload, counts),
        SECTION_IMPORT => validate_import(payload, module, counts),
        SECTION_FUNCTION => validate_function(payload, counts),
        SECTION_TABLE => validate_table(payload),
        SECTION_MEMORY => validate_memory(payload),
        SECTION_GLOBAL => validate_global(payload),
        SECTION_EXPORT => validate_export(payload, module),
        SECTION_START => validate_start(payload, module, *counts),
        SECTION_ELEMENT => validate_element(payload),
        SECTION_CODE => validate_code(payload, *counts),
        SECTION_DATA => validate_data(payload, *counts),
        SECTION_DATA_COUNT => validate_data_count(payload, counts),
        _ => Err(Error::Malformed("bad section id")),
    }
}

/// Parses WebAssembly bytes into an [`ObjectModule`].
///
/// # Errors
///
/// Returns an error for malformed headers, invalid section ids, truncated payloads, invalid LEB128
/// encodings, or unsupported malformed subsection encodings.
pub fn read(bytes: &[u8]) -> Result<ObjectModule> {
    let mut r = ByteReader::new(bytes, stratum_oir::Endianness::Little);
    if r.read_bytes(4)? != WASM_MAGIC {
        return Err(Error::Malformed("bad wasm magic"));
    }
    if r.read_bytes(4)? != WASM_VERSION {
        return Err(Error::Malformed("unsupported wasm version"));
    }

    let mut module = ObjectModule::new(BinaryFormat::Wasm, TargetSpec::wasm32());
    let mut counts = Counts::new();
    let mut last_rank = 0;

    while r.remaining() > 0 {
        let id = r.read_u8()?;
        if id > SECTION_MAX_STANDARD {
            return Err(Error::Malformed("bad section id"));
        }
        let rank = section_rank(id);
        if id != SECTION_CUSTOM {
            if rank <= last_rank {
                return Err(Error::Malformed("sections out of order"));
            }
            last_rank = rank;
        }
        let size = r.read_uleb128()?;
        let size = u64_to_usize(size, "section length")?;
        let payload = r.read_bytes(size)?;
        let name = section_name(id, payload)?;
        validate_section(id, payload, &mut module, &mut counts)?;
        let name_id = module.intern(name)?;
        let kind = section_kind(id, name);
        let size = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let section = Section {
            name: name_id,
            kind,
            flags: section_flags(kind),
            align: 1,
            address: 0,
            data: payload.to_vec(),
            size,
        };
        let _ = module.add_section(section)?;
    }

    if module.entry().is_none() && counts.imported_funcs + counts.functions > ENTRY_FUNC_INDEX {
        module.set_entry(ENTRY_FUNC_INDEX);
    }
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{EXPORT_MEMORY, REF_FUNC, VAL_I32};
    use crate::write;
    use stratum_oir::{ByteWriter, Endianness};

    fn finish(w: ByteWriter) -> alloc::vec::Vec<u8> {
        w.finish().unwrap()
    }

    fn payload(mut build: impl FnMut(&mut ByteWriter)) -> alloc::vec::Vec<u8> {
        let mut w = ByteWriter::new(Endianness::Little);
        build(&mut w);
        finish(w)
    }

    fn wasm_with_sections(sections: &[(u8, &[u8])]) -> alloc::vec::Vec<u8> {
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_bytes(&WASM_MAGIC);
        w.write_bytes(&WASM_VERSION);
        for (id, payload) in sections {
            w.write_u8(*id);
            w.write_uleb128(u64::try_from(payload.len()).unwrap());
            w.write_bytes(payload);
        }
        finish(w)
    }

    fn wasm_with_one_section(id: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
        wasm_with_sections(&[(id, body)])
    }

    fn named_payload(name: &str) -> alloc::vec::Vec<u8> {
        payload(|w| write::write_name(w, name).unwrap())
    }

    fn type_payload(type_count: u64) -> alloc::vec::Vec<u8> {
        payload(|w| {
            w.write_uleb128(type_count);
            for _ in 0..type_count {
                w.write_u8(TYPE_FUNC);
                w.write_uleb128(0);
                w.write_uleb128(0);
            }
        })
    }

    fn module() -> ObjectModule {
        ObjectModule::new(BinaryFormat::Wasm, TargetSpec::wasm32())
    }

    fn counts_with_types(types: u64) -> Counts {
        Counts {
            types,
            imported_funcs: 0,
            functions: 0,
            data_count: None,
        }
    }

    #[test]
    fn helpers_reject_bad_input() {
        assert!(u64_to_usize_with_max(2, "usize", 1).is_err());

        let reader = ByteReader::new(&[0], Endianness::Little);
        assert!(ensure_empty(&reader).is_err());
        assert_eq!(
            section_name(SECTION_CUSTOM, &named_payload("other")).unwrap(),
            "wasm.custom"
        );
        assert!(section_name(SECTION_MAX_STANDARD + 1, &[]).is_err());
        assert!(validate_value_type(0).is_err());
        let mut bad_name = ByteReader::new(&[1, 0xff], Endianness::Little);
        assert!(read_name(&mut bad_name).is_err());
        let mut short_name = ByteReader::new(&[2, b'a'], Endianness::Little);
        assert!(read_name(&mut short_name).is_err());
        let mut bad_table = ByteReader::new(&[0], Endianness::Little);
        assert!(read_table_type(&mut bad_table).is_err());
        let mut bad_limits = ByteReader::new(&[2], Endianness::Little);
        assert!(read_limits(&mut bad_limits).is_err());
    }

    #[test]
    fn limit_and_type_variants_are_validated() {
        let limits = payload(|w| {
            w.write_uleb128(1);
            w.write_u8(1);
            w.write_uleb128(2);
            w.write_uleb128(3);
        });
        assert!(validate_memory(&limits).is_ok());

        let bad_limits = payload(|w| {
            w.write_uleb128(1);
            w.write_u8(1);
            w.write_uleb128(4);
            w.write_uleb128(3);
        });
        assert!(validate_memory(&bad_limits).is_err());

        let bad_form = payload(|w| {
            w.write_uleb128(1);
            w.write_u8(0);
        });
        assert!(validate_type(&bad_form, &mut Counts::new()).is_err());

        let bad_function = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(2);
        });
        assert!(validate_function(&bad_function, &mut counts_with_types(1)).is_err());
    }

    #[test]
    fn imports_cover_all_descriptor_arms() {
        let import_payload = payload(|w| {
            w.write_uleb128(3);
            for (name, desc) in [
                ("table", DESC_TABLE),
                ("memory", DESC_MEMORY),
                ("global", DESC_GLOBAL),
            ] {
                write::write_name(w, "env").unwrap();
                write::write_name(w, name).unwrap();
                w.write_u8(desc);
                if desc == DESC_TABLE {
                    w.write_u8(REF_FUNC);
                    w.write_u8(0);
                    w.write_uleb128(1);
                } else if desc == DESC_MEMORY {
                    w.write_u8(0);
                    w.write_uleb128(1);
                } else {
                    w.write_u8(VAL_I32);
                    w.write_u8(1);
                }
            }
        });
        let mut object = module();
        assert!(validate_import(&import_payload, &mut object, &mut counts_with_types(1)).is_ok());

        let bad_type = payload(|w| {
            w.write_uleb128(1);
            write::write_name(w, "env").unwrap();
            write::write_name(w, "f").unwrap();
            w.write_u8(DESC_FUNC);
            w.write_uleb128(1);
        });
        assert!(validate_import(&bad_type, &mut module(), &mut counts_with_types(1)).is_err());

        let bad_desc = payload(|w| {
            w.write_uleb128(1);
            write::write_name(w, "env").unwrap();
            write::write_name(w, "x").unwrap();
            w.write_u8(9);
        });
        assert!(validate_import(&bad_desc, &mut module(), &mut counts_with_types(1)).is_err());
    }

    #[test]
    fn global_and_const_expr_variants_are_validated() {
        for opcode in [0x42, 0x43, 0x44, 0x23, 0xD2, 0] {
            let body = payload(|w| {
                w.write_uleb128(1);
                w.write_u8(VAL_I32);
                w.write_u8(0);
                w.write_u8(opcode);
                match opcode {
                    0x42 => w.write_sleb128(-1),
                    0x43 => w.write_u32(1),
                    0x44 => w.write_u64(1),
                    0x23 | 0xD2 => w.write_uleb128(0),
                    _ => {}
                }
                w.write_u8(OP_END);
            });
            assert_eq!(validate_global(&body).is_ok(), opcode != 0);
        }

        let bad_mutability = payload(|w| {
            w.write_uleb128(1);
            w.write_u8(VAL_I32);
            w.write_u8(2);
        });
        assert!(validate_global(&bad_mutability).is_err());

        let bad_opcode = payload(|w| {
            w.write_uleb128(1);
            w.write_u8(VAL_I32);
            w.write_u8(0);
            w.write_u8(0x45);
        });
        assert!(validate_global(&bad_opcode).is_err());
    }

    #[test]
    fn exports_and_start_are_validated() {
        let bad_export = payload(|w| {
            w.write_uleb128(1);
            write::write_name(w, "bad").unwrap();
            w.write_u8(9);
            w.write_uleb128(0);
        });
        assert!(validate_export(&bad_export, &mut module()).is_err());

        let memory_export = payload(|w| {
            w.write_uleb128(1);
            write::write_name(w, EXPORT_MEMORY).unwrap();
            w.write_u8(DESC_MEMORY);
            w.write_uleb128(0);
        });
        assert!(validate_export(&memory_export, &mut module()).is_ok());

        let start = payload(|w| w.write_uleb128(2));
        assert!(validate_start(&start, &mut module(), counts_with_types(0)).is_err());
    }

    #[test]
    fn element_section_forms_are_validated() {
        let passive = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(1);
            w.write_u8(0);
            w.write_uleb128(1);
            w.write_uleb128(0);
        });
        assert!(validate_element(&passive).is_ok());

        let active_table = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(2);
            w.write_uleb128(0);
            w.write_u8(OP_I32_CONST);
            w.write_sleb128(0);
            w.write_u8(OP_END);
            w.write_u8(0);
            w.write_uleb128(1);
            w.write_uleb128(0);
        });
        assert!(validate_element(&active_table).is_ok());

        for flags in [1_u64, 2] {
            let bad_kind = payload(|w| {
                w.write_uleb128(1);
                w.write_uleb128(flags);
                if flags == 2 {
                    w.write_uleb128(0);
                    w.write_u8(OP_END);
                }
                w.write_u8(1);
            });
            assert!(validate_element(&bad_kind).is_err());
        }

        let unsupported = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(3);
        });
        assert!(validate_element(&unsupported).is_err());
    }

    #[test]
    fn code_and_data_edge_cases_are_validated() {
        let mismatch = payload(|w| w.write_uleb128(1));
        assert!(validate_code(&mismatch, Counts::new()).is_err());

        let with_locals = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(4);
            w.write_uleb128(1);
            w.write_uleb128(1);
            w.write_u8(VAL_I32);
            w.write_u8(OP_END);
        });
        let mut counts = Counts::new();
        counts.functions = 1;
        assert!(validate_code(&with_locals, counts).is_ok());

        let empty_expr = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(1);
            w.write_uleb128(0);
        });
        assert!(validate_code(&empty_expr, counts).is_err());

        let passive_data = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(1);
            w.write_uleb128(0);
        });
        assert!(validate_data(&passive_data, Counts::new()).is_ok());

        let memory_indexed_data = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(2);
            w.write_uleb128(0);
            w.write_u8(OP_END);
            w.write_uleb128(0);
        });
        assert!(validate_data(&memory_indexed_data, Counts::new()).is_ok());

        let mut expected = Counts::new();
        expected.data_count = Some(2);
        assert!(validate_data(&passive_data, expected).is_err());

        let bad_segment = payload(|w| {
            w.write_uleb128(1);
            w.write_uleb128(3);
        });
        assert!(validate_data(&bad_segment, Counts::new()).is_err());
    }

    #[test]
    fn name_sections_and_validate_section_default_are_covered() {
        assert!(validate_name(&named_payload("not-name")).is_ok());

        let out_of_order = payload(|w| {
            write::write_name(w, "name").unwrap();
            w.write_u8(1);
            w.write_uleb128(0);
            w.write_u8(1);
            w.write_uleb128(0);
        });
        assert!(validate_name(&out_of_order).is_err());
        assert!(
            validate_section(
                SECTION_MAX_STANDARD + 1,
                &[],
                &mut module(),
                &mut Counts::new()
            )
            .is_err()
        );
    }

    #[test]
    fn top_level_order_and_default_entry_are_covered() {
        let mut bad_version = alloc::vec![];
        bad_version.extend_from_slice(&WASM_MAGIC);
        bad_version.extend_from_slice(&[2, 0, 0, 0]);
        assert!(read(&bad_version).is_err());

        let mut bad_section_id = alloc::vec![];
        bad_section_id.extend_from_slice(&WASM_MAGIC);
        bad_section_id.extend_from_slice(&WASM_VERSION);
        bad_section_id.push(SECTION_MAX_STANDARD + 1);
        bad_section_id.push(0);
        assert!(read(&bad_section_id).is_err());

        let mut missing_section_size = alloc::vec![];
        missing_section_size.extend_from_slice(&WASM_MAGIC);
        missing_section_size.extend_from_slice(&WASM_VERSION);
        missing_section_size.push(SECTION_CUSTOM);
        assert!(read(&missing_section_size).is_err());

        let mut truncated_section_payload = alloc::vec![];
        truncated_section_payload.extend_from_slice(&WASM_MAGIC);
        truncated_section_payload.extend_from_slice(&WASM_VERSION);
        truncated_section_payload.push(SECTION_CUSTOM);
        truncated_section_payload.push(2);
        truncated_section_payload.push(0);
        assert!(read(&truncated_section_payload).is_err());

        let bad_custom_name = wasm_with_one_section(SECTION_CUSTOM, &[0x80]);
        assert!(read(&bad_custom_name).is_err());

        let memory = write::build_memory_section().unwrap();
        let types = write::build_type_section().unwrap();
        let out_of_order = wasm_with_sections(&[
            (SECTION_MEMORY, memory.as_slice()),
            (SECTION_TYPE, types.as_slice()),
        ]);
        assert!(read(&out_of_order).is_err());

        let funcs = write::build_function_section(2).unwrap();
        let body = write::empty_body();
        let code = write::build_code_section(&[body.as_slice(), body.as_slice()]).unwrap();
        let bytes = wasm_with_sections(&[
            (SECTION_TYPE, types.as_slice()),
            (SECTION_FUNCTION, funcs.as_slice()),
            (SECTION_CODE, code.as_slice()),
        ]);
        let module = read(&bytes).unwrap();
        assert_eq!(module.entry(), Some(ENTRY_FUNC_INDEX));
    }

    #[test]
    fn all_standard_section_names_are_recognized() {
        for id in SECTION_CUSTOM..=SECTION_MAX_STANDARD {
            let body = match id {
                SECTION_TYPE => type_payload(1),
                SECTION_IMPORT => payload(|w| w.write_uleb128(0)),
                SECTION_FUNCTION => payload(|w| w.write_uleb128(0)),
                SECTION_TABLE => payload(|w| w.write_uleb128(0)),
                SECTION_MEMORY => payload(|w| w.write_uleb128(0)),
                SECTION_GLOBAL => payload(|w| w.write_uleb128(0)),
                SECTION_EXPORT => payload(|w| w.write_uleb128(0)),
                SECTION_START => payload(|w| w.write_uleb128(0)),
                SECTION_ELEMENT => payload(|w| w.write_uleb128(0)),
                SECTION_CODE => payload(|w| w.write_uleb128(0)),
                SECTION_DATA => payload(|w| w.write_uleb128(0)),
                SECTION_DATA_COUNT => payload(|w| w.write_uleb128(0)),
                _ => alloc::vec::Vec::new(),
            };
            let bytes = wasm_with_one_section(id, &body);
            let _ = read(&bytes);
        }
    }
}
