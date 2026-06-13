//! Deterministic textual rendering of an [`ObjectModule`], for debugging and round-trip
//! snapshot comparison.

use crate::alloc_prelude::*;
use crate::model::{
    ObjectModule, Section, SectionKind, Segment, SymbolBinding, SymbolEntry, SymbolKind,
};
use crate::reloc::RelocKind;
use crate::target::{Architecture, Endianness};
use core::fmt::Write as _;

impl ObjectModule {
    /// Renders the module to a stable, line-oriented form.
    ///
    /// The output is intentionally simple and deterministic so two modules that are
    /// semantically equal (e.g. before and after a `write → read` cycle) produce identical
    /// text, which is how the round-trip tests assert losslessness.
    #[must_use]
    pub fn dump(&self) -> String {
        let mut out = String::new();
        let target = self.target();
        let arch = match target.arch {
            Architecture::Other(id) => format!("other(0x{id:x})"),
            other => other.name().to_string(),
        };
        let endian = match target.endian {
            Endianness::Little => "little",
            Endianness::Big => "big",
        };
        let width = u16::from(target.ptr_width.bytes()) * 8;
        let _ = writeln!(
            out,
            "module format={} arch={arch} endian={endian} ptr={width}",
            self.format().name()
        );
        match self.entry() {
            Some(entry) => {
                let _ = writeln!(out, "entry 0x{entry:x}");
            }
            None => out.push_str("entry none\n"),
        }

        for (id, section) in self.sections() {
            self.dump_section(id.raw(), section, &mut out);
        }
        for segment in self.segments() {
            self.dump_segment(segment, &mut out);
        }
        for (id, symbol) in self.symbols() {
            self.dump_symbol(id.raw(), symbol, &mut out);
        }
        for (id, reloc) in self.relocations() {
            let _ = writeln!(
                out,
                "reloc[{}] section={} offset=0x{:x} symbol={} kind={} addend={}",
                id.raw(),
                reloc.section.raw(),
                reloc.offset,
                reloc.symbol.raw(),
                reloc_kind_name(reloc.kind),
                reloc.addend
            );
        }
        for import in self.imports() {
            let library = self.resolve(import.library).unwrap_or("<bad>");
            let name = self.resolve(import.name).unwrap_or("<bad>");
            let _ = writeln!(
                out,
                "import {library}!{name} ordinal={} hint={}",
                opt(import.ordinal),
                opt(import.hint)
            );
        }
        for export in self.exports() {
            let name = self.resolve(export.name).unwrap_or("<bad>");
            let _ = writeln!(
                out,
                "export {name} addr=0x{:x} ordinal={}",
                export.address,
                opt(export.ordinal)
            );
        }
        for line in self.debug().lines() {
            let _ = writeln!(
                out,
                "line addr=0x{:x} len={} span={:?}",
                line.address, line.length, line.span
            );
        }
        for func in self.debug().functions() {
            let name = self.resolve(func.name).unwrap_or("<bad>");
            let _ = writeln!(
                out,
                "func {name} addr=0x{:x} len={}",
                func.address, func.length
            );
        }
        out
    }

    fn dump_section(&self, index: u32, section: &Section, out: &mut String) {
        let name = self.resolve(section.name).unwrap_or("<bad>");
        let kind = match section.kind {
            SectionKind::Text => "text",
            SectionKind::Data => "data",
            SectionKind::ReadOnlyData => "rodata",
            SectionKind::Bss => "bss",
            SectionKind::Debug => "debug",
            SectionKind::Other => "other",
        };
        let flags = [
            (section.flags.read, 'r'),
            (section.flags.write, 'w'),
            (section.flags.execute, 'x'),
        ]
        .into_iter()
        .map(|(set, ch)| if set { ch } else { '-' })
        .collect::<String>();
        let _ = writeln!(
            out,
            "section[{index}] {name} kind={kind} addr=0x{:x} align={} flags={flags} size={} data={}",
            section.address,
            section.align,
            section.size,
            hex(&section.data)
        );
    }

    fn dump_symbol(&self, index: u32, symbol: &SymbolEntry, out: &mut String) {
        let name = self.resolve(symbol.name).unwrap_or("<bad>");
        let kind = match symbol.kind {
            SymbolKind::Function => "function",
            SymbolKind::Object => "object",
            SymbolKind::Section => "section",
            SymbolKind::None => "none",
        };
        let binding = match symbol.binding {
            SymbolBinding::Local => "local",
            SymbolBinding::Global => "global",
            SymbolBinding::Weak => "weak",
        };
        let section = match symbol.section {
            Some(id) => {
                let mut buf = String::new();
                let _ = write!(buf, "{}", id.raw());
                buf
            }
            None => "none".to_string(),
        };
        let flags = [
            (symbol.flags.undefined, 'u'),
            (symbol.flags.imported, 'i'),
            (symbol.flags.exported, 'e'),
        ]
        .into_iter()
        .map(|(set, ch)| if set { ch } else { '-' })
        .collect::<String>();
        let _ = writeln!(
            out,
            "symbol[{index}] {name} kind={kind} binding={binding} value=0x{:x} size={} section={section} flags={flags}",
            symbol.value, symbol.size
        );
    }

    fn dump_segment(&self, segment: &Segment, out: &mut String) {
        let name = self.resolve(segment.name).unwrap_or("<bad>");
        let flags = [
            (segment.flags.read, 'r'),
            (segment.flags.write, 'w'),
            (segment.flags.execute, 'x'),
        ]
        .into_iter()
        .map(|(set, ch)| if set { ch } else { '-' })
        .collect::<String>();
        let mut members = String::new();
        for (i, id) in segment.sections.iter().enumerate() {
            if i > 0 {
                members.push(',');
            }
            let _ = write!(members, "{}", id.raw());
        }
        let _ = writeln!(
            out,
            "segment {name} addr=0x{:x} vmsize={} flags={flags} sections=[{members}]",
            segment.address, segment.vm_size
        );
    }
}

fn opt(value: Option<u16>) -> String {
    match value {
        Some(v) => {
            let mut buf = String::new();
            let _ = write!(buf, "{v}");
            buf
        }
        None => "none".to_string(),
    }
}

fn reloc_kind_name(kind: RelocKind) -> String {
    match kind {
        RelocKind::Absolute64 => "abs64".to_string(),
        RelocKind::Absolute32 => "abs32".to_string(),
        RelocKind::Relative32 => "rel32".to_string(),
        RelocKind::Relative64 => "rel64".to_string(),
        RelocKind::GotRelative => "got".to_string(),
        RelocKind::PltRelative => "plt".to_string(),
        RelocKind::Other(id) => format!("other(0x{id:x})"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hex;
    use crate::alloc_prelude::*;
    use crate::model::{ObjectModule, Section, SectionFlags, SectionKind, Segment};
    use crate::target::{BinaryFormat, TargetSpec};

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn dump_is_deterministic_and_includes_sections() {
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        module.set_entry(0x1000);
        let name = module.intern(".text").unwrap();
        module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: 0x1000,
                align: 16,
                flags: SectionFlags::code(),
                data: vec![0x90],
                size: 1,
            })
            .unwrap();
        let first = module.dump();
        let second = module.dump();
        assert_eq!(first, second);
        assert!(first.contains("module format=elf arch=x86_64 endian=little ptr=64"));
        assert!(first.contains("entry 0x1000"));
        assert!(first.contains("section[0] .text kind=text"));
        assert!(first.contains("flags=r-x"));
        assert!(first.contains("data=90"));
    }

    #[test]
    fn dump_renders_relocations_imports_exports_and_segments() {
        use crate::linkage::{Export, Import};
        use crate::model::{SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind};
        use crate::reloc::{RelocKind, Relocation};
        use stratum_diagnostics::{FileId, Span};

        let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
        let text = module.intern(".text").unwrap();
        let sec = module
            .add_section(Section {
                name: text,
                kind: SectionKind::Text,
                address: 0x1000,
                align: 16,
                flags: SectionFlags::code(),
                data: vec![0x00, 0x00, 0x00, 0x00],
                size: 4,
            })
            .unwrap();
        let target = module.intern("target").unwrap();
        let sym = module
            .add_symbol(SymbolEntry {
                name: target,
                value: 0x2000,
                size: 8,
                section: Some(sec),
                kind: SymbolKind::Object,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::exported(),
            })
            .unwrap();
        module
            .add_relocation(Relocation {
                section: sec,
                offset: 0,
                symbol: sym,
                kind: RelocKind::Relative32,
                addend: -4,
            })
            .unwrap();
        let lib = module.intern("kernel32.dll").unwrap();
        let proc = module.intern("ExitProcess").unwrap();
        module.add_import(Import {
            library: lib,
            name: proc,
            ordinal: None,
            hint: Some(7),
        });
        let exp = module.intern("start").unwrap();
        module.add_export(Export {
            name: exp,
            address: 0x1000,
            ordinal: Some(1),
        });
        let seg = module.intern("__TEXT").unwrap();
        module.add_segment(Segment {
            name: seg,
            address: 0x1000,
            vm_size: 0x1000,
            flags: SectionFlags::code(),
            sections: vec![sec],
        });
        module.debug_mut().add_line(crate::debug::LineRecord {
            address: 0x1000,
            length: 4,
            span: Span::new(FileId::from_raw(1), 2, 6),
        });
        module
            .debug_mut()
            .add_function(crate::debug::FunctionRecord {
                name: target,
                address: 0x1000,
                length: 4,
            });

        let dump = module.dump();
        assert!(dump.contains("reloc[0] section=0 offset=0x0 symbol=0 kind=rel32 addend=-4"));
        assert!(dump.contains("import kernel32.dll!ExitProcess ordinal=none hint=7"));
        assert!(dump.contains("export start addr=0x1000 ordinal=1"));
        assert!(dump.contains("segment __TEXT addr=0x1000 vmsize=4096 flags=r-x sections=[0]"));
        assert!(dump.contains("line addr=0x1000 len=4"));
        assert!(dump.contains("func target addr=0x1000 len=4"));
        assert!(dump.contains("size=8"));
        assert!(dump.contains("flags=--e"));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustively exercises every dump arm in one module"
    )]
    fn dump_covers_other_arch_symbol_and_relocation_variants() {
        use crate::model::{SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind};
        use crate::reloc::{RelocKind, Relocation};
        use crate::target::{Architecture, Endianness, PtrWidth};

        let spec = TargetSpec::new(Architecture::Other(0x99), Endianness::Big, PtrWidth::W32);
        let mut module = ObjectModule::new(BinaryFormat::Elf, spec);
        let text = module.intern(".text").unwrap();
        let section_id = module
            .add_section(Section {
                name: text,
                kind: SectionKind::Text,
                address: 0,
                align: 4,
                flags: SectionFlags::code(),
                data: vec![0, 0, 0, 0],
                size: 4,
            })
            .unwrap();

        let entries = [
            (SymbolKind::Function, SymbolBinding::Local),
            (SymbolKind::Object, SymbolBinding::Global),
            (SymbolKind::Section, SymbolBinding::Weak),
            (SymbolKind::None, SymbolBinding::Local),
        ];
        for (i, (kind, binding)) in entries.into_iter().enumerate() {
            let name = module.intern(&format!("s{i}")).unwrap();
            module
                .add_symbol(SymbolEntry {
                    name,
                    value: 0,
                    size: 0,
                    section: None,
                    kind,
                    binding,
                    flags: SymbolFlags::none(),
                })
                .unwrap();
        }
        let extra = module.intern("weak").unwrap();
        module
            .add_symbol(SymbolEntry {
                name: extra,
                value: 0,
                size: 0,
                section: None,
                kind: SymbolKind::None,
                binding: SymbolBinding::Weak,
                flags: SymbolFlags::none(),
            })
            .unwrap();

        let dummy = module
            .add_symbol(SymbolEntry {
                name: extra,
                value: 0,
                size: 0,
                section: Some(section_id),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Local,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        for kind in [
            RelocKind::Absolute64,
            RelocKind::Absolute32,
            RelocKind::Relative32,
            RelocKind::Relative64,
            RelocKind::GotRelative,
            RelocKind::PltRelative,
            RelocKind::Other(0x7),
        ] {
            module
                .add_relocation(Relocation {
                    section: section_id,
                    offset: 0,
                    symbol: dummy,
                    kind,
                    addend: 0,
                })
                .unwrap();
        }

        let dump = module.dump();
        assert!(dump.contains("arch=other(0x99) endian=big ptr=32"));
        assert!(dump.contains("kind=section"));
        assert!(dump.contains("kind=none"));
        assert!(dump.contains("binding=weak"));
        assert!(dump.contains("kind=rel64"));
        assert!(dump.contains("kind=got"));
        assert!(dump.contains("kind=plt"));
        assert!(dump.contains("kind=other(0x7)"));

        // A segment owning more than one section exercises the member separator.
        let data_name = module.intern(".data").unwrap();
        let data_id = module
            .add_section(Section {
                name: data_name,
                kind: SectionKind::Data,
                address: 0x10,
                align: 4,
                flags: SectionFlags::data(),
                data: vec![0, 0, 0, 0],
                size: 4,
            })
            .unwrap();
        let seg_name = module.intern("LOAD").unwrap();
        module.add_segment(Segment {
            name: seg_name,
            address: 0,
            vm_size: 0x14,
            flags: SectionFlags::code(),
            sections: vec![section_id, data_id],
        });
        assert!(module.dump().contains("sections=[0,1]"));
    }
}
