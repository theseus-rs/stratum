//! ELF byte-layout constants used by the reader and writer.

/// ELF magic: `\x7fELF`.
pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF32 byte-layout constants.
pub mod elf32 {
    /// Size of the ELF header.
    pub const EHDR_SIZE: u64 = 52;
    /// Size of a program header entry.
    pub const PHDR_SIZE: u64 = 32;
    /// Size of a section header entry.
    pub const SHDR_SIZE: u64 = 40;
    /// Size of a symbol table entry.
    pub const SYM_SIZE: u64 = 16;
    /// Size of a relocation entry without addend.
    pub const REL_SIZE: u64 = 8;
    /// Size of a relocation entry with addend.
    pub const RELA_SIZE: u64 = 12;
}

/// ELF64 byte-layout constants.
pub mod elf64 {
    /// Size of the ELF header.
    pub const EHDR_SIZE: u64 = 64;
    /// Size of a program header entry.
    pub const PHDR_SIZE: u64 = 56;
    /// Size of a section header entry.
    pub const SHDR_SIZE: u64 = 64;
    /// Size of a symbol table entry.
    pub const SYM_SIZE: u64 = 24;
    /// Size of a relocation entry without addend.
    pub const REL_SIZE: u64 = 16;
    /// Size of a relocation entry with addend.
    pub const RELA_SIZE: u64 = 24;
}

/// Page size used to align loadable segments.
pub const PAGE_SIZE: u64 = 0x1000;

/// Default load base for emitted executables.
pub const LOAD_BASE: u64 = 0x40_0000;
