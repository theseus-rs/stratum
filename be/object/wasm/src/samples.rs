//! Deterministic WebAssembly samples used by tests and examples.

use crate::consts::{EXPORT_START, WASI_FD_WRITE, WASI_MODULE};
use crate::write::{
    ENTRY_FUNC_INDEX, build_code_section, build_data_count_section, build_data_section,
    build_element_section, build_export_section, build_function_section, build_global_section,
    build_import_section, build_memory_section, build_name_section, build_start_section,
    build_table_section, build_type_section, empty_body, start_body,
};
use stratum_oir::{
    BinaryFormat, Export, Import, ObjectModule, Result, Section, SectionFlags, SectionKind,
    SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::vec::Vec;

/// Message printed by the runnable WASI sample.
pub const HELLO_MESSAGE: &str = "Hello, wasm!\n";

const fn section_flags(kind: SectionKind) -> SectionFlags {
    match kind {
        SectionKind::Text => SectionFlags::code(),
        SectionKind::Data => SectionFlags::data(),
        _ => SectionFlags::read_only(),
    }
}

/// Bytes placed in linear memory for the runnable WASI sample.
#[must_use]
pub fn hello_data() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&8_u32.to_le_bytes());
    data.extend_from_slice(&13_u32.to_le_bytes());
    data.extend_from_slice(HELLO_MESSAGE.as_bytes());
    data.resize(28, 0);
    data
}

fn add(module: &mut ObjectModule, section: (&str, SectionKind, Result<Vec<u8>>)) -> Result<()> {
    let (name, kind, data) = section;
    let data = data?;
    let name = module.intern(name)?;
    let section = Section {
        name,
        kind,
        flags: section_flags(kind),
        align: 1,
        address: 0,
        size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        data,
    };
    let _ = module.add_section(section)?;
    Ok(())
}

fn add_export(module: &mut ObjectModule, name: &str, address: u64) -> Result<()> {
    let name = module.intern(name)?;
    module.add_export(Export {
        name,
        address,
        ordinal: None,
    });
    Ok(())
}

fn add_import_export_metadata(module: &mut ObjectModule, full: bool) -> Result<()> {
    let library = module.intern(WASI_MODULE)?;
    let name = module.intern(WASI_FD_WRITE)?;
    module.add_import(Import {
        library,
        name,
        ordinal: None,
        hint: None,
    });
    add_export(module, "memory", 0)?;
    add_export(module, EXPORT_START, ENTRY_FUNC_INDEX)?;
    if full {
        add_export(module, "helper", 2)?;
        add_export(module, "table", 0)?;
        add_export(module, "answer", 0)?;
    }
    let fd_write = module.intern(WASI_FD_WRITE)?;
    let symbol = SymbolEntry {
        name: fd_write,
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        section: None,
        value: 0,
        size: 0,
        flags: SymbolFlags::none(),
    };
    let _ = module.add_symbol(symbol)?;
    let start = module.intern(EXPORT_START)?;
    let symbol = SymbolEntry {
        name: start,
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        section: None,
        value: ENTRY_FUNC_INDEX,
        size: 0,
        flags: SymbolFlags::none(),
    };
    let _ = module.add_symbol(symbol)?;
    if full {
        let helper = module.intern("helper")?;
        let symbol = SymbolEntry {
            name: helper,
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            section: None,
            value: 2,
            size: 0,
            flags: SymbolFlags::none(),
        };
        let _ = module.add_symbol(symbol)?;
    }
    module.set_entry(ENTRY_FUNC_INDEX);
    Ok(())
}

/// Builds a runnable `wasm32-wasi` hello-world module using `fd_write`.
///
/// # Errors
///
/// Returns an error if interning or object construction fails.
pub fn hello_module() -> Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Wasm, TargetSpec::wasm32());
    let section = ("wasm.type", SectionKind::Other, build_type_section());
    add(&mut module, section)?;
    let section = ("wasm.import", SectionKind::Other, build_import_section());
    add(&mut module, section)?;
    let section = (
        "wasm.function",
        SectionKind::Other,
        build_function_section(1),
    );
    add(&mut module, section)?;
    let section = ("wasm.memory", SectionKind::Other, build_memory_section());
    add(&mut module, section)?;
    let section = (
        "wasm.export",
        SectionKind::Other,
        build_export_section(false),
    );
    add(&mut module, section)?;
    let body = start_body();
    let section = ("wasm.code", SectionKind::Text, build_code_section(&[&body]));
    add(&mut module, section)?;
    let data = build_data_section(&hello_data());
    add(&mut module, ("wasm.data", SectionKind::Data, data))?;
    add_import_export_metadata(&mut module, false)?;
    Ok(module)
}

/// Builds a high-fidelity sample containing every standard section and the `name` custom section.
///
/// # Errors
///
/// Returns an error if interning or object construction fails.
pub fn full_featured_module() -> Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Wasm, TargetSpec::wasm32());
    let section = ("wasm.type", SectionKind::Other, build_type_section());
    add(&mut module, section)?;
    let section = ("wasm.import", SectionKind::Other, build_import_section());
    add(&mut module, section)?;
    let section = (
        "wasm.function",
        SectionKind::Other,
        build_function_section(2),
    );
    add(&mut module, section)?;
    let section = ("wasm.table", SectionKind::Other, build_table_section());
    add(&mut module, section)?;
    let section = ("wasm.memory", SectionKind::Other, build_memory_section());
    add(&mut module, section)?;
    let section = ("wasm.global", SectionKind::Other, build_global_section());
    add(&mut module, section)?;
    let section = (
        "wasm.export",
        SectionKind::Other,
        build_export_section(true),
    );
    add(&mut module, section)?;
    let section = ("wasm.start", SectionKind::Other, build_start_section());
    add(&mut module, section)?;
    let section = ("wasm.element", SectionKind::Other, build_element_section());
    add(&mut module, section)?;
    let section = (
        "wasm.data_count",
        SectionKind::Other,
        build_data_count_section(1),
    );
    add(&mut module, section)?;
    let start = start_body();
    let helper = empty_body();
    let code = build_code_section(&[&start, &helper]);
    add(&mut module, ("wasm.code", SectionKind::Text, code))?;
    let data = build_data_section(&hello_data());
    add(&mut module, ("wasm.data", SectionKind::Data, data))?;
    let section = ("wasm.custom.name", SectionKind::Debug, build_name_section());
    add(&mut module, section)?;
    add_import_export_metadata(&mut module, true)?;
    Ok(module)
}

/// Builds the backwards-compatible hello-world sample module.
///
/// # Errors
///
/// Returns an error if the sample cannot be constructed.
pub fn hello_world_wasm32_wasi() -> Result<ObjectModule> {
    hello_module()
}

/// Serializes [`hello_module`] to bytes.
///
/// # Errors
///
/// Returns an error if the sample cannot be constructed or serialised.
pub fn hello_bytes() -> Result<Vec<u8>> {
    crate::write(&hello_module()?)
}

/// Serializes [`full_featured_module`] to bytes.
///
/// # Errors
///
/// Returns an error if the sample cannot be constructed or serialised.
pub fn full_featured_bytes() -> Result<Vec<u8>> {
    crate::write(&full_featured_module()?)
}
