#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

mod adapt;
mod codec;
mod consts;
mod model;
mod msf;

pub use adapt::{apply_to_object, from_object};
pub use codec::{read, write};
pub use model::{
    NamedStream, PdbFieldRecord, PdbFile, PdbInfo, PdbLineRecord, PdbModule, PdbRawStream,
    PdbScopeRecord, PdbSourceRecord, PdbSymbolKind, PdbSymbolRecord, PdbTypeKind, PdbTypeRecord,
    PdbVariableRecord,
};

#[cfg(test)]
mod tests {
    use super::{apply_to_object, from_object, read, write};
    use stratum_diagnostics::{FileId, Span};
    use stratum_oir::{
        BinaryFormat, CompileUnitRecord, DebugField, DebugFileFormat, DebugSymbolKind,
        DebugSymbolRecord, DebugTypeKind, DebugTypeRecord, ExternalDebugFile, FunctionRecord,
        LineRecord, ObjectModule, SourceFileRecord, TargetSpec,
    };

    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    fn add_other_external_file(module: &mut ObjectModule) {
        module.debug_mut().add_external_file(
            ExternalDebugFile::new(
                DebugFileFormat::Other(1),
                "app.dwo".to_string(),
                vec![1],
                None,
            )
            .unwrap(),
        );
    }

    fn add_pdb_external_file(module: &mut ObjectModule) {
        module.debug_mut().add_external_file(ExternalDebugFile::pdb(
            "target/stratum.pdb".to_string(),
            [7; 16],
            3,
        ));
    }

    fn module() -> ObjectModule {
        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        let main = module.intern("main").unwrap();
        module.debug_mut().add_line(LineRecord {
            address: 0x1000,
            length: 8,
            span: Span::new(FileId::from_raw(1), 10, 20),
        });
        module.debug_mut().add_source(SourceFileRecord {
            file: 1,
            path: "src/main.stratum".to_string(),
            checksum_kind: 0,
            checksum: Vec::new(),
        });
        module.debug_mut().add_compile_unit(CompileUnitRecord {
            name: "stratum".to_string(),
            object: "stratum.obj".to_string(),
            files: vec![1],
        });
        module.debug_mut().add_function(FunctionRecord {
            name: main,
            address: 0x1000,
            length: 8,
        });
        module.debug_mut().add_type(DebugTypeRecord {
            id: 0x1000,
            kind: DebugTypeKind::Aggregate,
            name: "Point".to_string(),
            size: 8,
            references: Vec::new(),
            fields: vec![DebugField {
                name: "x".to_string(),
                ty: 0x74,
                offset: 0,
            }],
            raw_kind: 0x1505,
            raw: Vec::new(),
        });
        module.debug_mut().add_symbol(DebugSymbolRecord {
            name: "global".to_string(),
            address: 0x2000,
            length: 4,
            ty: Some(0x1000),
            kind: DebugSymbolKind::Global,
            raw_kind: 0x110E,
            raw: Vec::new(),
        });
        module
    }

    #[test]
    fn object_debug_round_trips_through_pdb() {
        let mut original = module();
        add_other_external_file(&mut original);
        add_pdb_external_file(&mut original);
        let pdb = from_object(&original).unwrap();
        let bytes = write(&pdb).unwrap();
        let parsed = read(&bytes).unwrap();
        assert_eq!(write(&parsed).unwrap(), bytes);

        let mut rebuilt = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        apply_to_object(&mut rebuilt, &parsed).unwrap();
        let mut expected = module();
        add_pdb_external_file(&mut expected);
        assert_eq!(expected.dump(), rebuilt.dump());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(read(&[0; 64]).is_err());
    }
}
