//! Bridges between [`stratum_oir::DebugInfo`] and the PDB model.

use crate::model::{
    PdbFieldRecord, PdbFile, PdbInfo, PdbLineRecord, PdbModule, PdbScopeRecord, PdbSourceRecord,
    PdbSymbolKind, PdbSymbolRecord, PdbTypeKind, PdbTypeRecord, PdbVariableRecord,
};
use stratum_diagnostics::{FileId, Span};
use stratum_oir::{
    CompileUnitRecord, DebugField, DebugFileFormat, DebugInfo, DebugSymbolKind, DebugSymbolRecord,
    DebugTypeKind, DebugTypeRecord, DebugVariableRecord, Error, ExternalDebugFile, FunctionRecord,
    LexicalScopeRecord, LineRecord, ObjectModule, Result, SourceFileRecord,
};

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

const GENERATED_FUNCTION_SYMBOL_KIND: u16 = 0;

/// Builds a PDB model from the debug info attached to `module`.
///
/// # Errors
///
/// Returns an error if an interned function name cannot be resolved or a raw `CodeView` kind does
/// not fit in the PDB record width.
pub fn from_object(module: &ObjectModule) -> Result<PdbFile> {
    let debug = module.debug();
    let mut file = PdbFile {
        info: pdb_info(debug),
        types: Vec::new(),
        ids: Vec::new(),
        modules: build_modules(module, debug)?,
        globals: Vec::new(),
        publics: Vec::new(),
        raw_streams: Vec::new(),
    };

    for ty in debug.types() {
        file.types.push(type_to_pdb(ty)?);
    }
    for symbol in debug.symbols() {
        let record = symbol_to_pdb(symbol)?;
        match symbol.kind {
            DebugSymbolKind::Public => file.publics.push(record),
            _ => file.globals.push(record),
        }
    }
    Ok(file)
}

/// Populates `module`'s debug info from a parsed PDB model.
///
/// # Errors
///
/// Returns an error if interning a function name fails.
pub fn apply_to_object(module: &mut ObjectModule, file: &PdbFile) -> Result<()> {
    module
        .debug_mut()
        .upsert_external_file(ExternalDebugFile::pdb(
            file.info.path.clone(),
            file.info.guid,
            file.info.age,
        ));

    for ty in &file.types {
        module.debug_mut().add_type(type_from_pdb(ty));
    }
    for pdb_module in &file.modules {
        apply_sources(module, &pdb_module.sources);
        module
            .debug_mut()
            .add_compile_unit(compile_unit_from_module(pdb_module));
        for line in &pdb_module.lines {
            module.debug_mut().add_line(LineRecord {
                address: line.address,
                length: line.length,
                span: Span::new(FileId::from_raw(line.file), line.start, line.end),
            });
        }
        for symbol in &pdb_module.symbols {
            if symbol.kind == PdbSymbolKind::Function
                && symbol.raw_kind == GENERATED_FUNCTION_SYMBOL_KIND
            {
                let name = module.intern(&symbol.name)?;
                module.debug_mut().add_function(FunctionRecord {
                    name,
                    address: symbol.address,
                    length: symbol.length,
                });
            } else {
                module.debug_mut().add_symbol(symbol_from_pdb(symbol));
            }
        }
        for scope in &pdb_module.scopes {
            module.debug_mut().add_scope(scope_from_pdb(scope));
        }
    }
    for symbol in file.globals.iter().chain(&file.publics) {
        module.debug_mut().add_symbol(symbol_from_pdb(symbol));
    }
    Ok(())
}

fn pdb_info(debug: &DebugInfo) -> PdbInfo {
    let mut info = PdbInfo::default();
    if let Some(reference) = debug.external_files().iter().find_map(|file| {
        if file.format() != DebugFileFormat::Pdb {
            return None;
        }
        Some((file, file.pdb_guid()?))
    }) {
        info.path = reference.0.path().to_string();
        info.guid = reference.1;
        info.age = reference.0.pdb_age().unwrap_or(info.age);
    }
    info
}

fn build_modules(module: &ObjectModule, debug: &DebugInfo) -> Result<Vec<PdbModule>> {
    let sources = collect_sources(debug);
    if debug.compile_units().is_empty() {
        return Ok(vec![build_single_module(module, debug, &sources)?]);
    }

    let mut modules = Vec::with_capacity(debug.compile_units().len());
    for (index, unit) in debug.compile_units().iter().enumerate() {
        let module_record = build_unit_module(module, debug, &sources, unit, index == 0)?;
        modules.push(module_record);
    }
    Ok(modules)
}

fn build_single_module(
    module: &ObjectModule,
    debug: &DebugInfo,
    sources: &[PdbSourceRecord],
) -> Result<PdbModule> {
    Ok(PdbModule {
        name: "stratum".to_string(),
        object: "stratum.obj".to_string(),
        sources: sources.to_vec(),
        lines: debug.lines().iter().map(line_to_pdb).collect(),
        symbols: function_symbols(module, debug.functions())?,
        scopes: debug.scopes().iter().map(scope_to_pdb).collect(),
        stream: 0,
    })
}

fn build_unit_module(
    module: &ObjectModule,
    debug: &DebugInfo,
    sources: &[PdbSourceRecord],
    unit: &CompileUnitRecord,
    include_unmatched_functions: bool,
) -> Result<PdbModule> {
    let unit_sources: Vec<PdbSourceRecord> = sources
        .iter()
        .filter(|source| unit.files.contains(&source.file))
        .cloned()
        .collect();
    let lines: Vec<PdbLineRecord> = debug
        .lines()
        .iter()
        .filter(|line| unit.files.contains(&line.span.file().raw()))
        .map(line_to_pdb)
        .collect();
    let mut functions = Vec::new();
    for function in debug.functions() {
        let matched = line_file_at(debug, function.address)
            .map_or(include_unmatched_functions, |file| {
                unit.files.contains(&file)
            });
        if matched {
            functions.push(*function);
        }
    }
    let scopes: Vec<PdbScopeRecord> = debug
        .scopes()
        .iter()
        .filter(|scope| {
            line_file_at(debug, scope.address).map_or(include_unmatched_functions, |file| {
                unit.files.contains(&file)
            })
        })
        .map(scope_to_pdb)
        .collect();

    Ok(PdbModule {
        name: unit.name.clone(),
        object: unit.object.clone(),
        sources: unit_sources,
        lines,
        symbols: function_symbols(module, &functions)?,
        scopes,
        stream: 0,
    })
}

fn line_file_at(debug: &DebugInfo, address: u64) -> Option<u32> {
    debug
        .lines()
        .iter()
        .find_map(|line| line.contains(address).then_some(line.span.file().raw()))
}

fn collect_sources(debug: &DebugInfo) -> Vec<PdbSourceRecord> {
    let mut sources: Vec<PdbSourceRecord> = debug.sources().iter().map(source_to_pdb).collect();
    for line in debug.lines() {
        let file = line.span.file().raw();
        if sources.iter().all(|source| source.file != file) {
            sources.push(PdbSourceRecord {
                file,
                path: file_name(file),
                checksum_kind: 0,
                checksum: Vec::new(),
            });
        }
    }
    sources
}

fn function_symbols(
    module: &ObjectModule,
    functions: &[FunctionRecord],
) -> Result<Vec<PdbSymbolRecord>> {
    let mut symbols = Vec::with_capacity(functions.len());
    for function in functions {
        symbols.push(PdbSymbolRecord {
            raw_kind: GENERATED_FUNCTION_SYMBOL_KIND,
            kind: PdbSymbolKind::Function,
            name: module.resolve(function.name)?.to_string(),
            address: function.address,
            length: function.length,
            type_index: None,
            raw: Vec::new(),
        });
    }
    Ok(symbols)
}

fn apply_sources(module: &mut ObjectModule, sources: &[PdbSourceRecord]) {
    for source in sources {
        if module
            .debug()
            .sources()
            .iter()
            .any(|existing| existing.file == source.file)
        {
            continue;
        }
        module.debug_mut().add_source(SourceFileRecord {
            file: source.file,
            path: source.path.clone(),
            checksum_kind: source.checksum_kind,
            checksum: source.checksum.clone(),
        });
    }
}

fn compile_unit_from_module(module: &PdbModule) -> CompileUnitRecord {
    CompileUnitRecord {
        name: module.name.clone(),
        object: module.object.clone(),
        files: module.sources.iter().map(|source| source.file).collect(),
    }
}

fn line_to_pdb(line: &LineRecord) -> PdbLineRecord {
    PdbLineRecord {
        address: line.address,
        length: line.length,
        file: line.span.file().raw(),
        start: line.span.start(),
        end: line.span.end(),
    }
}

fn source_to_pdb(source: &SourceFileRecord) -> PdbSourceRecord {
    PdbSourceRecord {
        file: source.file,
        path: source.path.clone(),
        checksum_kind: source.checksum_kind,
        checksum: source.checksum.clone(),
    }
}

fn type_to_pdb(ty: &DebugTypeRecord) -> Result<PdbTypeRecord> {
    Ok(PdbTypeRecord {
        index: ty.id,
        raw_kind: u16_raw_kind(ty.raw_kind, "type raw kind")?,
        kind: type_kind_to_pdb(ty.kind),
        name: ty.name.clone(),
        size: ty.size,
        references: ty.references.clone(),
        fields: ty.fields.iter().map(field_to_pdb).collect(),
        raw: ty.raw.clone(),
    })
}

fn type_from_pdb(ty: &PdbTypeRecord) -> DebugTypeRecord {
    DebugTypeRecord {
        id: ty.index,
        kind: type_kind_from_pdb(ty.kind),
        name: ty.name.clone(),
        size: ty.size,
        references: ty.references.clone(),
        fields: ty.fields.iter().map(field_from_pdb).collect(),
        raw_kind: u32::from(ty.raw_kind),
        raw: ty.raw.clone(),
    }
}

fn field_to_pdb(field: &DebugField) -> PdbFieldRecord {
    PdbFieldRecord {
        name: field.name.clone(),
        type_index: field.ty,
        offset: field.offset,
    }
}

fn field_from_pdb(field: &PdbFieldRecord) -> DebugField {
    DebugField {
        name: field.name.clone(),
        ty: field.type_index,
        offset: field.offset,
    }
}

fn symbol_to_pdb(symbol: &DebugSymbolRecord) -> Result<PdbSymbolRecord> {
    Ok(PdbSymbolRecord {
        raw_kind: u16_raw_kind(symbol.raw_kind, "symbol raw kind")?,
        kind: symbol_kind_to_pdb(symbol.kind),
        name: symbol.name.clone(),
        address: symbol.address,
        length: symbol.length,
        type_index: symbol.ty,
        raw: symbol.raw.clone(),
    })
}

fn symbol_from_pdb(symbol: &PdbSymbolRecord) -> DebugSymbolRecord {
    DebugSymbolRecord {
        name: symbol.name.clone(),
        address: symbol.address,
        length: symbol.length,
        ty: symbol.type_index,
        kind: symbol_kind_from_pdb(symbol.kind),
        raw_kind: u32::from(symbol.raw_kind),
        raw: symbol.raw.clone(),
    }
}

fn scope_to_pdb(scope: &LexicalScopeRecord) -> PdbScopeRecord {
    PdbScopeRecord {
        id: scope.id,
        parent: scope.parent,
        address: scope.address,
        length: scope.length,
        variables: scope.variables.iter().map(variable_to_pdb).collect(),
    }
}

fn scope_from_pdb(scope: &PdbScopeRecord) -> LexicalScopeRecord {
    LexicalScopeRecord {
        id: scope.id,
        parent: scope.parent,
        address: scope.address,
        length: scope.length,
        variables: scope.variables.iter().map(variable_from_pdb).collect(),
    }
}

fn variable_to_pdb(variable: &DebugVariableRecord) -> PdbVariableRecord {
    PdbVariableRecord {
        name: variable.name.clone(),
        type_index: variable.ty,
        location: variable.location,
        raw_location: variable.raw_location.clone(),
    }
}

fn variable_from_pdb(variable: &PdbVariableRecord) -> DebugVariableRecord {
    DebugVariableRecord {
        name: variable.name.clone(),
        ty: variable.type_index,
        location: variable.location,
        raw_location: variable.raw_location.clone(),
    }
}

fn type_kind_to_pdb(kind: DebugTypeKind) -> PdbTypeKind {
    match kind {
        DebugTypeKind::Primitive => PdbTypeKind::Primitive,
        DebugTypeKind::Pointer => PdbTypeKind::Pointer,
        DebugTypeKind::Function => PdbTypeKind::Function,
        DebugTypeKind::Aggregate => PdbTypeKind::Aggregate,
        DebugTypeKind::Enum => PdbTypeKind::Enum,
        DebugTypeKind::Array => PdbTypeKind::Array,
        DebugTypeKind::Alias => PdbTypeKind::Alias,
        DebugTypeKind::Other(raw) => PdbTypeKind::Other(raw),
    }
}

fn type_kind_from_pdb(kind: PdbTypeKind) -> DebugTypeKind {
    match kind {
        PdbTypeKind::Primitive => DebugTypeKind::Primitive,
        PdbTypeKind::Pointer => DebugTypeKind::Pointer,
        PdbTypeKind::Function => DebugTypeKind::Function,
        PdbTypeKind::Aggregate => DebugTypeKind::Aggregate,
        PdbTypeKind::Enum => DebugTypeKind::Enum,
        PdbTypeKind::Array => DebugTypeKind::Array,
        PdbTypeKind::Alias => DebugTypeKind::Alias,
        PdbTypeKind::Other(raw) => DebugTypeKind::Other(raw),
    }
}

fn symbol_kind_to_pdb(kind: DebugSymbolKind) -> PdbSymbolKind {
    match kind {
        DebugSymbolKind::Public => PdbSymbolKind::Public,
        DebugSymbolKind::Global => PdbSymbolKind::Global,
        DebugSymbolKind::Local => PdbSymbolKind::Local,
        DebugSymbolKind::Function => PdbSymbolKind::Function,
        DebugSymbolKind::Data => PdbSymbolKind::Data,
        DebugSymbolKind::Other(raw) => PdbSymbolKind::Other(raw),
    }
}

fn symbol_kind_from_pdb(kind: PdbSymbolKind) -> DebugSymbolKind {
    match kind {
        PdbSymbolKind::Public => DebugSymbolKind::Public,
        PdbSymbolKind::Global => DebugSymbolKind::Global,
        PdbSymbolKind::Local => DebugSymbolKind::Local,
        PdbSymbolKind::Function => DebugSymbolKind::Function,
        PdbSymbolKind::Data => DebugSymbolKind::Data,
        PdbSymbolKind::Other(raw) => DebugSymbolKind::Other(raw),
    }
}

fn u16_raw_kind(value: u32, what: &'static str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn file_name(file: u32) -> String {
    let mut name = "file:".to_string();
    name.push_str(&file.to_string());
    name
}

#[cfg(test)]
mod tests {
    use super::{apply_to_object, from_object, u16_raw_kind};
    use crate::{PdbSymbolKind, PdbSymbolRecord};
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use stratum_diagnostics::{FileId, Span};
    use stratum_oir::{
        BinaryFormat, CompileUnitRecord, DebugSymbolKind, DebugSymbolRecord, DebugTypeKind,
        DebugTypeRecord, DebugVariableRecord, FunctionRecord, LexicalScopeRecord, LineRecord,
        ObjectModule, SourceFileRecord, TargetSpec,
    };

    fn add_kind_surface(module: &mut ObjectModule) {
        for (id, kind) in [
            (0x1000, DebugTypeKind::Primitive),
            (0x1001, DebugTypeKind::Pointer),
            (0x1002, DebugTypeKind::Function),
            (0x1003, DebugTypeKind::Enum),
            (0x1004, DebugTypeKind::Array),
            (0x1005, DebugTypeKind::Alias),
            (0x1006, DebugTypeKind::Other(0x55)),
        ] {
            module.debug_mut().add_type(DebugTypeRecord {
                id,
                kind,
                name: "kind".to_string(),
                size: 1,
                references: vec![0x74],
                fields: Vec::new(),
                raw_kind: id,
                raw: vec![u8::try_from(id & 0xff).unwrap()],
            });
        }
        for (raw_kind, kind) in [
            (1, DebugSymbolKind::Public),
            (2, DebugSymbolKind::Local),
            (3, DebugSymbolKind::Function),
            (4, DebugSymbolKind::Data),
            (5, DebugSymbolKind::Other(0x77)),
        ] {
            module.debug_mut().add_symbol(DebugSymbolRecord {
                name: "sym".to_string(),
                address: u64::from(raw_kind) * 0x10,
                length: 1,
                ty: Some(0x1000),
                kind,
                raw_kind,
                raw: vec![u8::try_from(raw_kind).unwrap()],
            });
        }
    }

    #[test]
    fn no_compile_unit_path_synthesizes_module_sources_and_scopes() {
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        module.debug_mut().add_line(LineRecord {
            address: 0x1000,
            length: 4,
            span: Span::new(FileId::from_raw(7), 1, 2),
        });
        let func = module.intern("loose").unwrap();
        module.debug_mut().add_function(FunctionRecord {
            name: func,
            address: 0x1000,
            length: 4,
        });
        module.debug_mut().add_scope(LexicalScopeRecord {
            id: 1,
            parent: Some(0),
            address: 0x1000,
            length: 4,
            variables: vec![DebugVariableRecord {
                name: "x".to_string(),
                ty: Some(0x1000),
                location: -8,
                raw_location: vec![0xaa],
            }],
        });

        let pdb = from_object(&module).unwrap();
        assert_eq!(pdb.modules.len(), 1);
        let pdb_module = pdb.modules.first().unwrap();
        assert_eq!(pdb_module.name, "stratum");
        assert_eq!(pdb_module.sources.first().unwrap().path, "file:7");
        assert_eq!(pdb_module.symbols.first().unwrap().name, "loose");
        assert_eq!(
            pdb_module
                .scopes
                .first()
                .and_then(|scope| scope.variables.first())
                .unwrap()
                .location,
            -8
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "coverage fixture intentionally assembles the rich debug surface in one place"
    )]
    fn rich_kinds_apply_back_to_object() {
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        module.debug_mut().add_source(SourceFileRecord {
            file: 1,
            path: "a.c".to_string(),
            checksum_kind: 1,
            checksum: vec![1, 2],
        });
        module.debug_mut().add_compile_unit(CompileUnitRecord {
            name: "unit-a".to_string(),
            object: "a.obj".to_string(),
            files: vec![1],
        });
        module.debug_mut().add_compile_unit(CompileUnitRecord {
            name: "unit-b".to_string(),
            object: "b.obj".to_string(),
            files: vec![2],
        });
        module.debug_mut().add_line(LineRecord {
            address: 0x1000,
            length: 4,
            span: Span::new(FileId::from_raw(1), 1, 3),
        });
        module.debug_mut().add_line(LineRecord {
            address: 0x2000,
            length: 4,
            span: Span::new(FileId::from_raw(2), 4, 6),
        });
        let matched = module.intern("matched").unwrap();
        let unmatched = module.intern("unmatched").unwrap();
        module.debug_mut().add_function(FunctionRecord {
            name: matched,
            address: 0x2000,
            length: 4,
        });
        module.debug_mut().add_function(FunctionRecord {
            name: unmatched,
            address: 0x3000,
            length: 4,
        });
        module.debug_mut().add_scope(LexicalScopeRecord {
            id: 2,
            parent: None,
            address: 0x3000,
            length: 4,
            variables: Vec::new(),
        });
        module.debug_mut().add_scope(LexicalScopeRecord {
            id: 3,
            parent: Some(2),
            address: 0x2000,
            length: 4,
            variables: vec![DebugVariableRecord {
                name: "scoped".to_string(),
                ty: Some(0x1000),
                location: 16,
                raw_location: vec![0xbb],
            }],
        });
        add_kind_surface(&mut module);

        let mut pdb = from_object(&module).unwrap();
        let duplicated_source = pdb
            .modules
            .first()
            .unwrap()
            .sources
            .first()
            .unwrap()
            .clone();
        pdb.modules
            .get_mut(1)
            .unwrap()
            .sources
            .push(duplicated_source);
        pdb.modules
            .get_mut(0)
            .unwrap()
            .symbols
            .push(PdbSymbolRecord {
                raw_kind: 0x100,
                kind: PdbSymbolKind::Data,
                name: "module_data".to_string(),
                address: 0x4000,
                length: 4,
                type_index: None,
                raw: vec![0xcc],
            });
        assert_eq!(pdb.publics.len(), 1);
        assert!(pdb.modules.iter().any(|module| module.name == "unit-a"));
        assert!(pdb.modules.iter().any(|module| module.name == "unit-b"));

        let mut rebuilt = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        apply_to_object(&mut rebuilt, &pdb).unwrap();
        assert_eq!(rebuilt.debug().types().len(), module.debug().types().len());
        assert!(
            rebuilt
                .debug()
                .symbols()
                .iter()
                .any(|symbol| symbol.kind == DebugSymbolKind::Other(0x77))
        );
        assert!(
            rebuilt
                .debug()
                .symbols()
                .iter()
                .any(|symbol| symbol.name == "module_data")
        );
        assert!(rebuilt.debug().scopes().iter().any(|scope| scope.id == 2));
        assert!(
            rebuilt
                .debug()
                .scopes()
                .iter()
                .flat_map(|scope| &scope.variables)
                .any(|variable| variable.name == "scoped")
        );
    }

    #[test]
    fn raw_kind_overflow_is_rejected() {
        assert!(u16_raw_kind(0x1_0000, "raw").is_err());
    }
}
