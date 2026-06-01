//! `CodeView` debug-blob constants used by the line/symbol codec.

/// `CV_SIGNATURE_C13`: the modern `CodeView` debug-information signature.
pub const CV_SIGNATURE_C13: u32 = 4;

/// `DEBUG_S_SYMBOLS` subsection: symbol (function) records.
pub const DEBUG_S_SYMBOLS: u32 = 0xF1;
/// `DEBUG_S_LINES` subsection: line-number records.
pub const DEBUG_S_LINES: u32 = 0xF2;
/// `DEBUG_S_STRINGTABLE` subsection: null-terminated source-file strings.
pub const DEBUG_S_STRINGTABLE: u32 = 0xF3;
/// `DEBUG_S_FILECHKSMS` subsection: source-file checksum descriptors.
pub const DEBUG_S_FILECHKSMS: u32 = 0xF4;

/// `S_END`: ends the current `CodeView` symbol scope.
pub const S_END: u16 = 0x0006;
/// `S_FRAMEPROC`: frame metadata associated with a procedure.
pub const S_FRAMEPROC: u16 = 0x1012;
/// `S_GPROC32`: a global 32-bit procedure symbol.
pub const S_GPROC32: u16 = 0x1110;

/// `LF_HaveColumns`: line subsection flag indicating column rows are present.
pub const LF_HAVE_COLUMNS: u16 = 1;
/// `T_NOTYPE`: no type index is associated with the procedure.
pub const T_NOTYPE: u32 = 0;

/// Subsections and symbol records are padded to this alignment.
pub const SUBSECTION_ALIGN: usize = 4;
