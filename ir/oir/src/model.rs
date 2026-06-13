//! The format-neutral object model: modules, sections, symbols, and relocations.

use crate::alloc_prelude::*;
use crate::debug::DebugInfo;
use crate::error::Result;
use crate::linkage::{Export, Import};
use crate::reloc::Relocation;
use crate::target::{BinaryFormat, TargetSpec};
use core::ops::Index;
use stratum_arena::{Arena, Id, Interner, Symbol};

/// Identifies a [`Section`] within an [`ObjectModule`].
pub type SectionId = Id<Section>;

/// Identifies a [`SymbolEntry`] within an [`ObjectModule`].
pub type SymbolId = Id<SymbolEntry>;

/// Identifies a [`Relocation`] within an [`ObjectModule`].
pub type RelocationId = Id<Relocation>;

/// The broad role of a section, abstracting over the per-format section/segment zoo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Executable machine code (`.text`, `__text`, Wasm code).
    Text,
    /// Initialised, writable data (`.data`, `__data`).
    Data,
    /// Initialised, read-only data (`.rodata`, `__const`).
    ReadOnlyData,
    /// Zero-initialised data occupying no file space (`.bss`, `__bss`).
    Bss,
    /// Debug information carried verbatim (`.debug_*`, `__debug_*`, Wasm custom).
    Debug,
    /// Anything Stratum does not classify; preserved for round-tripping.
    Other,
}

/// Memory permissions requested for a section's pages at load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SectionFlags {
    /// Readable at run time.
    pub read: bool,
    /// Writable at run time.
    pub write: bool,
    /// Executable at run time.
    pub execute: bool,
}

impl SectionFlags {
    /// `r-x` permissions for code.
    #[must_use]
    pub const fn code() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// `rw-` permissions for writable data.
    #[must_use]
    pub const fn data() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// `r--` permissions for read-only data.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }
}

/// A contiguous, named region of an image with a load address and bytes.
#[derive(Debug, Clone)]
pub struct Section {
    /// Interned section name.
    pub name: Symbol,
    /// Classified role.
    pub kind: SectionKind,
    /// Virtual address the section is mapped at (`0` if not mapped).
    pub address: u64,
    /// Required alignment in bytes (a power of two, or `0`/`1` for none).
    pub align: u64,
    /// Load-time permissions.
    pub flags: SectionFlags,
    /// File contents. For [`Bss`](SectionKind::Bss) this is empty and [`size`](Self::size)
    /// gives the run-time footprint.
    pub data: Vec<u8>,
    /// Run-time size in bytes (defaults to `data.len()`; larger for `.bss`).
    pub size: u64,
}

impl Section {
    /// The number of bytes this section occupies in the file image (its `data` length).
    #[must_use]
    pub fn file_size(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(0)
    }

    /// The number of bytes this section occupies in memory at run time.
    ///
    /// For [`Bss`](SectionKind::Bss) this exceeds [`file_size`](Self::file_size); the gap is
    /// zero-filled by the loader.
    #[must_use]
    pub const fn vm_size(&self) -> u64 {
        self.size
    }
}

/// A loadable grouping of sections sharing one mapping, mirroring a Mach-O segment or an ELF
/// `PT_LOAD` program header. Segments are an optional overlay on the section list; codecs that
/// do not model segments simply leave the table empty.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Interned segment name (e.g. `__TEXT`).
    pub name: Symbol,
    /// Virtual address the segment is mapped at.
    pub address: u64,
    /// Run-time size of the mapping in bytes.
    pub vm_size: u64,
    /// Load-time permissions for the whole mapping.
    pub flags: SectionFlags,
    /// Sections contained in this segment, in load order.
    pub sections: Vec<SectionId>,
}

/// The kind of program entity a symbol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// A function / code entry point.
    Function,
    /// A data object.
    Object,
    /// A section itself.
    Section,
    /// An unspecified or absolute symbol.
    None,
}

/// The linkage visibility of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolBinding {
    /// Visible only within the module.
    Local,
    /// Visible to other modules.
    Global,
    /// Global but overridable.
    Weak,
}

/// Linkage attributes refining how a symbol participates in loading and resolution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SymbolFlags {
    /// The symbol is referenced but not defined in this module (an external/undefined symbol).
    pub undefined: bool,
    /// The symbol is imported from another image (e.g. a PE/Mach-O dynamic import).
    pub imported: bool,
    /// The symbol is exported for other images to bind against.
    pub exported: bool,
}

impl SymbolFlags {
    /// No special attributes (a plain, locally-defined symbol).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            undefined: false,
            imported: false,
            exported: false,
        }
    }

    /// Marks a symbol that is defined here and visible to other images.
    #[must_use]
    pub const fn exported() -> Self {
        Self {
            undefined: false,
            imported: false,
            exported: true,
        }
    }

    /// Marks an undefined symbol imported from another image.
    #[must_use]
    pub const fn imported() -> Self {
        Self {
            undefined: true,
            imported: true,
            exported: false,
        }
    }
}

/// A named address within the image.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Interned symbol name.
    pub name: Symbol,
    /// Address or offset value.
    pub value: u64,
    /// Size of the entity in bytes (`0` when unknown or not applicable).
    pub size: u64,
    /// Section the symbol is defined in, if any.
    pub section: Option<SectionId>,
    /// Entity kind.
    pub kind: SymbolKind,
    /// Linkage visibility.
    pub binding: SymbolBinding,
    /// Refining linkage attributes.
    pub flags: SymbolFlags,
}

/// A linked, format-neutral executable image.
///
/// An `ObjectModule` is the binary-end analogue of `HirContext`: the single value a codec
/// reads into and writes out of. Sections and symbols live in arenas and are addressed by
/// [`SectionId`] / [`SymbolId`].
#[derive(Debug)]
pub struct ObjectModule {
    interner: Interner,
    target: TargetSpec,
    format: BinaryFormat,
    entry: Option<u64>,
    sections: Arena<Section>,
    symbols: Arena<SymbolEntry>,
    relocations: Arena<Relocation>,
    segments: Vec<Segment>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    debug: DebugInfo,
}

impl ObjectModule {
    /// Creates an empty module for `format` on `target`.
    #[must_use]
    pub fn new(format: BinaryFormat, target: TargetSpec) -> Self {
        Self {
            interner: Interner::new(),
            target,
            format,
            entry: None,
            sections: Arena::new(),
            symbols: Arena::new(),
            relocations: Arena::new(),
            segments: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            debug: DebugInfo::new(),
        }
    }

    /// The container format.
    #[must_use]
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    /// The target description.
    #[must_use]
    pub fn target(&self) -> TargetSpec {
        self.target
    }

    /// The entry-point virtual address (or function index for Wasm), if set.
    #[must_use]
    pub fn entry(&self) -> Option<u64> {
        self.entry
    }

    /// Sets the entry point.
    pub fn set_entry(&mut self, entry: u64) {
        self.entry = Some(entry);
    }

    /// Interns `text`, returning a reusable [`Symbol`].
    ///
    /// # Errors
    ///
    /// Returns an error if the interner is full.
    pub fn intern(&mut self, text: &str) -> Result<Symbol> {
        Ok(self.interner.intern(text)?)
    }

    /// Resolves a [`Symbol`] back to its string.
    ///
    /// # Errors
    ///
    /// Returns an error if `symbol` was not produced by this module.
    pub fn resolve(&self, symbol: Symbol) -> Result<&str> {
        Ok(self.interner.resolve(symbol)?)
    }

    /// The shared interner, mainly for dumping.
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Appends a section and returns its id.
    ///
    /// # Errors
    ///
    /// Returns an error if the section arena is full.
    pub fn add_section(&mut self, section: Section) -> Result<SectionId> {
        Ok(self.sections.alloc(section)?)
    }

    /// Appends a symbol and returns its id.
    ///
    /// # Errors
    ///
    /// Returns an error if the symbol arena is full.
    pub fn add_symbol(&mut self, symbol: SymbolEntry) -> Result<SymbolId> {
        Ok(self.symbols.alloc(symbol)?)
    }

    /// Returns the section for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this module.
    #[must_use]
    pub fn section(&self, id: SectionId) -> &Section {
        self.sections.index(id)
    }

    /// Returns the symbol for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this module.
    #[must_use]
    pub fn symbol(&self, id: SymbolId) -> &SymbolEntry {
        self.symbols.index(id)
    }

    /// Iterates over `(SectionId, &Section)` pairs in allocation order.
    pub fn sections(&self) -> impl Iterator<Item = (SectionId, &Section)> {
        self.sections.iter()
    }

    /// Iterates over `(SymbolId, &SymbolEntry)` pairs in allocation order.
    pub fn symbols(&self) -> impl Iterator<Item = (SymbolId, &SymbolEntry)> {
        self.symbols.iter()
    }

    /// The number of sections.
    #[must_use]
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// The number of symbols.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Appends a relocation and returns its id.
    ///
    /// # Errors
    ///
    /// Returns an error if the relocation arena is full.
    pub fn add_relocation(&mut self, relocation: Relocation) -> Result<RelocationId> {
        Ok(self.relocations.alloc(relocation)?)
    }

    /// Iterates over `(RelocationId, &Relocation)` pairs in allocation order.
    pub fn relocations(&self) -> impl Iterator<Item = (RelocationId, &Relocation)> {
        self.relocations.iter()
    }

    /// The number of relocations.
    #[must_use]
    pub fn relocation_count(&self) -> usize {
        self.relocations.len()
    }

    /// Appends a segment grouping.
    pub fn add_segment(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    /// The segment groupings, in declaration order.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Records a dynamic import.
    pub fn add_import(&mut self, import: Import) {
        self.imports.push(import);
    }

    /// The dynamic imports, in declaration order.
    #[must_use]
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Records a dynamic export.
    pub fn add_export(&mut self, export: Export) {
        self.exports.push(export);
    }

    /// The dynamic exports, in declaration order.
    #[must_use]
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    /// Shared access to the module's debug information.
    #[must_use]
    pub fn debug(&self) -> &DebugInfo {
        &self.debug
    }

    /// Mutable access to the module's debug information.
    pub fn debug_mut(&mut self) -> &mut DebugInfo {
        &mut self.debug
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ObjectModule, Section, SectionFlags, SectionKind, SymbolBinding, SymbolEntry, SymbolFlags,
        SymbolKind,
    };
    use crate::alloc_prelude::*;
    use crate::target::{BinaryFormat, TargetSpec};

    fn text_section(name: stratum_arena::Symbol, bytes: Vec<u8>) -> Section {
        let size = u64::try_from(bytes.len()).unwrap_or(0);
        Section {
            name,
            kind: SectionKind::Text,
            address: 0x1000,
            align: 16,
            flags: SectionFlags::code(),
            data: bytes,
            size,
        }
    }

    #[test]
    fn builds_sections_and_symbols() {
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        module.set_entry(0x1000);
        let name = module.intern(".text").unwrap();
        let sec = module
            .add_section(text_section(name, vec![0x90, 0x90]))
            .unwrap();
        let sym_name = module.intern("_start").unwrap();
        let sym = module
            .add_symbol(SymbolEntry {
                name: sym_name,
                value: 0x1000,
                size: 2,
                section: Some(sec),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::exported(),
            })
            .unwrap();

        assert_eq!(module.format(), BinaryFormat::Elf);
        assert_eq!(module.entry(), Some(0x1000));
        assert_eq!(module.section_count(), 1);
        assert_eq!(module.symbol_count(), 1);
        assert_eq!(module.section(sec).data, vec![0x90, 0x90]);
        assert_eq!(module.symbol(sym).kind, SymbolKind::Function);
        assert_eq!(module.resolve(module.section(sec).name).unwrap(), ".text");
    }

    #[test]
    fn interner_accessor_resolves_symbols() {
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        let name = module.intern(".rodata").unwrap();
        assert_eq!(module.interner().resolve(name).unwrap(), ".rodata");
    }

    #[test]
    fn flag_presets() {
        assert!(SectionFlags::code().execute);
        assert!(!SectionFlags::code().write);
        assert!(SectionFlags::data().write);
        assert!(!SectionFlags::read_only().write);
    }
}
