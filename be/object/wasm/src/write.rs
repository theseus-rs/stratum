//! Serializes an [`ObjectModule`] into WebAssembly binary format.

use crate::consts::{
    DESC_FUNC, DESC_GLOBAL, DESC_MEMORY, DESC_TABLE, EXPORT_MEMORY, EXPORT_START, OP_CALL, OP_DROP,
    OP_END, OP_I32_CONST, REF_FUNC, SECTION_CODE, SECTION_CUSTOM, SECTION_DATA, SECTION_DATA_COUNT,
    SECTION_ELEMENT, SECTION_EXPORT, SECTION_FUNCTION, SECTION_GLOBAL, SECTION_IMPORT,
    SECTION_MEMORY, SECTION_START, SECTION_TABLE, SECTION_TYPE, TYPE_FUNC, VAL_I32, WASI_FD_WRITE,
    WASI_MODULE, WASM_MAGIC, WASM_VERSION,
};
use stratum_oir::{
    Architecture, ByteWriter, Endianness, Error, ObjectModule, Result, Section, SectionKind,
};

extern crate alloc;
use alloc::vec::Vec;

/// Index of the exported `_start` function in the combined import/function space.
pub const ENTRY_FUNC_INDEX: u64 = 1;

fn writer() -> ByteWriter {
    ByteWriter::new(Endianness::Little)
}

fn finish(w: ByteWriter) -> Result<Vec<u8>> {
    w.finish()
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Writes a length-prefixed name (`vec(byte)`).
#[expect(
    clippy::unnecessary_wraps,
    reason = "fallible signature kept symmetric with the other section writers"
)]
pub(crate) fn write_name(w: &mut ByteWriter, name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    w.write_uleb128(usize_to_u64(bytes.len()));
    w.write_bytes(bytes);
    Ok(())
}

/// Appends a section: id byte, `uleb128` payload length, then the payload.
#[expect(
    clippy::unnecessary_wraps,
    reason = "fallible signature kept symmetric with the other section writers"
)]
fn emit_section(main: &mut ByteWriter, id: u8, payload: &[u8]) -> Result<()> {
    main.write_u8(id);
    main.write_uleb128(usize_to_u64(payload.len()));
    main.write_bytes(payload);
    Ok(())
}

fn raw_section_id(name: &str) -> Option<u8> {
    match name {
        "wasm.custom" => Some(SECTION_CUSTOM),
        "wasm.type" => Some(SECTION_TYPE),
        "wasm.import" => Some(SECTION_IMPORT),
        "wasm.function" => Some(SECTION_FUNCTION),
        "wasm.table" => Some(SECTION_TABLE),
        "wasm.memory" => Some(SECTION_MEMORY),
        "wasm.global" => Some(SECTION_GLOBAL),
        "wasm.export" => Some(SECTION_EXPORT),
        "wasm.start" => Some(SECTION_START),
        "wasm.element" => Some(SECTION_ELEMENT),
        "wasm.code" => Some(SECTION_CODE),
        "wasm.data" => Some(SECTION_DATA),
        "wasm.data_count" => Some(SECTION_DATA_COUNT),
        _ if name.starts_with("wasm.custom.") => Some(SECTION_CUSTOM),
        _ => None,
    }
}

fn write_raw_sections(module: &ObjectModule) -> Result<Option<Vec<u8>>> {
    let mut w = writer();
    w.write_bytes(&WASM_MAGIC);
    w.write_bytes(&WASM_VERSION);
    let mut emitted = false;
    for (_, section) in module.sections() {
        let name = module.resolve(section.name)?;
        if let Some(id) = raw_section_id(name) {
            emit_section(&mut w, id, &section.data)?;
            emitted = true;
        }
    }
    if emitted {
        return Ok(Some(finish(w)?));
    }
    Ok(None)
}

fn section_by_kind(module: &ObjectModule, kind: SectionKind) -> Result<&Section> {
    let mut found = None;
    for (_, section) in module.sections() {
        if section.kind == kind {
            if found.is_some() {
                return Err(Error::Unsupported(
                    "Wasm writer expects one section per kind",
                ));
            }
            found = Some(section);
        }
    }
    found.ok_or(Error::Malformed("missing required section"))
}

/// Serializes `module` to a WebAssembly module.
///
/// # Errors
///
/// Returns an error if the target is not `wasm32`, the module lacks required legacy sections,
/// or a length does not fit its encoding.
pub fn write(module: &ObjectModule) -> Result<Vec<u8>> {
    if module.target().arch != Architecture::Wasm32 {
        return Err(Error::Unsupported("Wasm writer supports wasm32 only"));
    }
    if let Some(bytes) = write_raw_sections(module)? {
        return Ok(bytes);
    }

    let code_body = &section_by_kind(module, SectionKind::Text)?.data;
    let data_bytes = &section_by_kind(module, SectionKind::Data)?.data;

    let mut w = writer();
    w.write_bytes(&WASM_MAGIC);
    w.write_bytes(&WASM_VERSION);

    emit_section(&mut w, SECTION_TYPE, &build_type_section()?)?;
    emit_section(&mut w, SECTION_IMPORT, &build_import_section()?)?;
    emit_section(&mut w, SECTION_FUNCTION, &build_function_section(1)?)?;
    emit_section(&mut w, SECTION_MEMORY, &build_memory_section()?)?;
    emit_section(&mut w, SECTION_EXPORT, &build_export_section(false)?)?;
    emit_section(&mut w, SECTION_CODE, &build_code_section(&[code_body])?)?;
    emit_section(&mut w, SECTION_DATA, &build_data_section(data_bytes)?)?;

    finish(w)
}

pub(crate) fn build_type_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(2);
    w.write_u8(TYPE_FUNC);
    w.write_uleb128(4);
    for _ in 0..4 {
        w.write_u8(VAL_I32);
    }
    w.write_uleb128(1);
    w.write_u8(VAL_I32);
    w.write_u8(TYPE_FUNC);
    w.write_uleb128(0);
    w.write_uleb128(0);
    finish(w)
}

pub(crate) fn build_import_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    write_name(&mut w, WASI_MODULE)?;
    write_name(&mut w, WASI_FD_WRITE)?;
    w.write_u8(DESC_FUNC);
    w.write_uleb128(0);
    finish(w)
}

pub(crate) fn build_function_section(count: u64) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(count);
    for _ in 0..count {
        w.write_uleb128(1);
    }
    finish(w)
}

pub(crate) fn build_table_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    w.write_u8(REF_FUNC);
    w.write_u8(0x00);
    w.write_uleb128(1);
    finish(w)
}

pub(crate) fn build_memory_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    w.write_u8(0x00);
    w.write_uleb128(1);
    finish(w)
}

pub(crate) fn build_global_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    w.write_u8(VAL_I32);
    w.write_u8(0x00);
    w.write_u8(OP_I32_CONST);
    w.write_sleb128(42);
    w.write_u8(OP_END);
    finish(w)
}

pub(crate) fn build_export_section(full: bool) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(if full { 5 } else { 2 });
    write_name(&mut w, EXPORT_MEMORY)?;
    w.write_u8(DESC_MEMORY);
    w.write_uleb128(0);
    write_name(&mut w, EXPORT_START)?;
    w.write_u8(DESC_FUNC);
    w.write_uleb128(ENTRY_FUNC_INDEX);
    if full {
        write_name(&mut w, "helper")?;
        w.write_u8(DESC_FUNC);
        w.write_uleb128(2);
        write_name(&mut w, "table")?;
        w.write_u8(DESC_TABLE);
        w.write_uleb128(0);
        write_name(&mut w, "answer")?;
        w.write_u8(DESC_GLOBAL);
        w.write_uleb128(0);
    }
    finish(w)
}

pub(crate) fn build_start_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(ENTRY_FUNC_INDEX);
    finish(w)
}

pub(crate) fn build_element_section() -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    w.write_uleb128(0);
    w.write_u8(OP_I32_CONST);
    w.write_sleb128(0);
    w.write_u8(OP_END);
    w.write_uleb128(2);
    w.write_uleb128(ENTRY_FUNC_INDEX);
    w.write_uleb128(2);
    finish(w)
}

pub(crate) fn build_code_section(bodies: &[&[u8]]) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(usize_to_u64(bodies.len()));
    for body in bodies {
        w.write_uleb128(usize_to_u64(body.len()));
        w.write_bytes(body);
    }
    finish(w)
}

pub(crate) fn build_data_count_section(count: u64) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(count);
    finish(w)
}

pub(crate) fn build_data_section(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_uleb128(1);
    w.write_uleb128(0);
    w.write_u8(OP_I32_CONST);
    w.write_sleb128(0);
    w.write_u8(OP_END);
    w.write_uleb128(usize_to_u64(bytes.len()));
    w.write_bytes(bytes);
    finish(w)
}

pub(crate) fn build_name_section() -> Result<Vec<u8>> {
    let mut w = writer();
    write_name(&mut w, "name")?;
    let mut module_name = writer();
    write_name(&mut module_name, "stratum.sample")?;
    emit_section(&mut w, 0, &finish(module_name)?)?;
    let mut function_names = writer();
    function_names.write_uleb128(3);
    function_names.write_uleb128(0);
    write_name(&mut function_names, WASI_FD_WRITE)?;
    function_names.write_uleb128(1);
    write_name(&mut function_names, EXPORT_START)?;
    function_names.write_uleb128(2);
    write_name(&mut function_names, "helper")?;
    emit_section(&mut w, 1, &finish(function_names)?)?;
    finish(w)
}

/// Builds the `_start` function body that calls `fd_write(1, iovec=0, 1, nwritten)`.
#[must_use]
pub fn start_body() -> Vec<u8> {
    alloc::vec![
        0x00,
        OP_I32_CONST,
        0x01,
        OP_I32_CONST,
        0x00,
        OP_I32_CONST,
        0x01,
        OP_I32_CONST,
        0x18,
        OP_CALL,
        0x00,
        OP_DROP,
        OP_END,
    ]
}

/// Builds an empty `() -> ()` function body.
#[must_use]
pub fn empty_body() -> Vec<u8> {
    alloc::vec![0x00, OP_END]
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_oir::{BinaryFormat, SectionFlags, TargetSpec};

    fn module(target: TargetSpec) -> ObjectModule {
        ObjectModule::new(BinaryFormat::Wasm, target)
    }

    fn add_section(module: &mut ObjectModule, name: &str, kind: SectionKind, data: &[u8]) {
        let name = module.intern(name).unwrap();
        let flags = match kind {
            SectionKind::Text => SectionFlags::code(),
            SectionKind::Data => SectionFlags::data(),
            _ => SectionFlags::read_only(),
        };
        let _ = module
            .add_section(Section {
                name,
                kind,
                address: 0,
                align: 1,
                flags,
                data: data.to_vec(),
                size: u64::try_from(data.len()).unwrap(),
            })
            .unwrap();
    }

    #[test]
    fn raw_section_ids_cover_all_names() {
        for (name, expected) in [
            ("wasm.custom", SECTION_CUSTOM),
            ("wasm.type", SECTION_TYPE),
            ("wasm.import", SECTION_IMPORT),
            ("wasm.function", SECTION_FUNCTION),
            ("wasm.table", SECTION_TABLE),
            ("wasm.memory", SECTION_MEMORY),
            ("wasm.global", SECTION_GLOBAL),
            ("wasm.export", SECTION_EXPORT),
            ("wasm.start", SECTION_START),
            ("wasm.element", SECTION_ELEMENT),
            ("wasm.code", SECTION_CODE),
            ("wasm.data", SECTION_DATA),
            ("wasm.data_count", SECTION_DATA_COUNT),
            ("wasm.custom.name", SECTION_CUSTOM),
        ] {
            assert_eq!(raw_section_id(name), Some(expected));
        }
        assert_eq!(raw_section_id(".text"), None);
    }

    #[test]
    fn raw_section_writer_handles_empty_and_mixed_modules() {
        let mut empty = module(TargetSpec::wasm32());
        add_section(&mut empty, ".note", SectionKind::Other, &[1]);
        assert!(write_raw_sections(&empty).unwrap().is_none());

        let mut mixed = module(TargetSpec::wasm32());
        add_section(&mut mixed, ".note", SectionKind::Other, &[1]);
        add_section(
            &mut mixed,
            "wasm.custom.name",
            SectionKind::Debug,
            &[4, b'n', b'a', b'm', b'e'],
        );
        let bytes = write_raw_sections(&mixed).unwrap().unwrap();
        assert_eq!(bytes.get(..4), Some(WASM_MAGIC.as_slice()));
    }

    #[test]
    fn section_by_kind_reports_missing_and_duplicates() {
        let empty = module(TargetSpec::wasm32());
        assert!(section_by_kind(&empty, SectionKind::Text).is_err());

        let mut duplicate = module(TargetSpec::wasm32());
        add_section(&mut duplicate, ".text.one", SectionKind::Text, &[0]);
        add_section(&mut duplicate, ".text.two", SectionKind::Text, &[0]);
        assert!(section_by_kind(&duplicate, SectionKind::Text).is_err());
    }

    #[test]
    fn write_rejects_non_wasm_and_supports_legacy_sections() {
        let non_wasm = module(TargetSpec::x86_64());
        assert!(write(&non_wasm).is_err());

        let mut legacy = module(TargetSpec::wasm32());
        let body = empty_body();
        add_section(&mut legacy, ".text", SectionKind::Text, &body);
        add_section(&mut legacy, ".data", SectionKind::Data, &[1, 2, 3]);
        let bytes = write(&legacy).unwrap();
        assert_eq!(bytes.get(..4), Some(WASM_MAGIC.as_slice()));
    }
}
