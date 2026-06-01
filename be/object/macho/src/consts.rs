//! On-disk constants for the Mach-O container and its embedded code signature.

/// 32-bit little-endian Mach-O magic (`MH_MAGIC`).
pub const MH_MAGIC: u32 = 0xFEED_FACE;
/// 64-bit little-endian Mach-O magic (`MH_MAGIC_64`).
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `CPU_TYPE_I386`.
pub const CPU_TYPE_I386: u32 = 0x0000_0007;
/// `CPU_TYPE_X86_64`.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// `CPU_TYPE_ARM`.
pub const CPU_TYPE_ARM: u32 = 0x0000_000C;
/// `CPU_TYPE_ARM64`.
pub const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// `CPU_SUBTYPE_I386_ALL`.
pub const CPU_SUBTYPE_I386_ALL: u32 = 0x0000_0003;
/// `CPU_SUBTYPE_X86_64_ALL`.
pub const CPU_SUBTYPE_X86_64_ALL: u32 = 0x0000_0003;
/// `CPU_SUBTYPE_ARM_ALL`.
pub const CPU_SUBTYPE_ARM_ALL: u32 = 0x0000_0000;
/// `CPU_SUBTYPE_ARM64_ALL`.
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0x0000_0000;

/// `MH_OBJECT` file type.
pub const MH_OBJECT: u32 = 0x1;
/// `MH_EXECUTE` file type.
pub const MH_EXECUTE: u32 = 0x2;

/// `LC_SEGMENT` load command.
pub const LC_SEGMENT: u32 = 0x1;
/// `LC_SYMTAB` load command.
pub const LC_SYMTAB: u32 = 0x2;
/// `LC_DYSYMTAB` load command.
pub const LC_DYSYMTAB: u32 = 0xB;
/// `LC_LOAD_DYLINKER` load command.
pub const LC_LOAD_DYLINKER: u32 = 0xE;
/// `LC_LOAD_DYLIB` load command.
pub const LC_LOAD_DYLIB: u32 = 0xC;
/// `LC_SEGMENT_64` load command.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_DYLD_INFO_ONLY` load command (`LC_REQ_DYLD | LC_DYLD_INFO`).
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// `LC_MAIN` load command (`LC_REQ_DYLD | 0x28`).
pub const LC_MAIN: u32 = 0x8000_0028;
/// `LC_BUILD_VERSION` load command.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// `LC_CODE_SIGNATURE` load command.
pub const LC_CODE_SIGNATURE: u32 = 0x1D;

/// `MH_NOUNDEFS`.
pub const MH_NOUNDEFS: u32 = 0x1;
/// `MH_DYLDLINK`.
pub const MH_DYLDLINK: u32 = 0x4;
/// `MH_TWOLEVEL`.
pub const MH_TWOLEVEL: u32 = 0x80;
/// `MH_PIE`.
pub const MH_PIE: u32 = 0x20_0000;
/// Default executable flags.
pub const MH_FLAGS: u32 = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
/// `PLATFORM_MACOS`.
pub const PLATFORM_MACOS: u32 = 1;
/// Minimum macOS version encoded as `X.Y.Z` nibbles (11.0.0).
pub const MIN_MACOS_VERSION: u32 = 0x000B_0000;
/// Path to the dynamic linker.
pub const DYLD_PATH: &str = "/usr/lib/dyld";
/// Conventional `libSystem` install name.
pub const LIBSYSTEM_PATH: &str = "/usr/lib/libSystem.B.dylib";

/// `VM_PROT_READ`.
pub const VM_PROT_READ: u32 = 0x1;
/// `VM_PROT_WRITE`.
pub const VM_PROT_WRITE: u32 = 0x2;
/// `VM_PROT_EXECUTE`.
pub const VM_PROT_EXECUTE: u32 = 0x4;

/// `S_REGULAR`.
pub const S_REGULAR: u32 = 0x0;
/// `S_ZEROFILL`.
pub const S_ZEROFILL: u32 = 0x1;
/// `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`.
pub const S_TEXT_FLAGS: u32 = 0x8000_0400;

/// `N_EXT` bit.
pub const N_EXT: u8 = 0x01;
/// `N_TYPE` mask.
pub const N_TYPE: u8 = 0x0E;
/// `N_UNDF` symbol type.
pub const N_UNDF: u8 = 0x00;
/// `N_SECT` symbol type.
pub const N_SECT: u8 = 0x0E;
/// `N_WEAK_DEF` descriptor bit.
pub const N_WEAK_DEF: u16 = 0x0080;
/// `REFERENCE_FLAG_UNDEFINED_NON_LAZY`.
pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0;

/// Size of `mach_header`.
pub const MACH_HEADER_32_SIZE: u32 = 28;
/// Size of `mach_header_64`.
pub const MACH_HEADER_64_SIZE: u32 = 32;
/// Size of a `segment_command` with no sections.
pub const SEGMENT_COMMAND_32_SIZE: u32 = 56;
/// Size of a `segment_command_64` with no sections.
pub const SEGMENT_COMMAND_64_SIZE: u32 = 72;
/// Size of a `section`.
pub const SECTION_32_SIZE: u32 = 68;
/// Size of a `section_64`.
pub const SECTION_64_SIZE: u32 = 80;
/// Size of an `LC_SYMTAB` command.
pub const SYMTAB_COMMAND_SIZE: u32 = 24;
/// Size of an `LC_DYSYMTAB` command.
pub const DYSYMTAB_COMMAND_SIZE: u32 = 80;
/// Size of an `LC_DYLD_INFO_ONLY` command.
pub const DYLD_INFO_COMMAND_SIZE: u32 = 48;
/// Size of an `LC_CODE_SIGNATURE` command.
pub const CODE_SIGNATURE_COMMAND_SIZE: u32 = 16;
/// Size of an `LC_BUILD_VERSION` command with no tools.
pub const BUILD_VERSION_COMMAND_SIZE: u32 = 24;
/// Size of an `LC_MAIN` command.
pub const MAIN_COMMAND_SIZE: u32 = 24;
/// Size of the fixed `LC_LOAD_DYLINKER` command.
pub const DYLINKER_COMMAND_SIZE: u32 = 32;
/// Fixed `LC_LOAD_DYLIB` header bytes before the install-name string.
pub const DYLIB_COMMAND_HEADER_SIZE: u32 = 24;
/// Size of a 64-bit `nlist` entry.
pub const NLIST_64_SIZE: u32 = 16;
/// Size of a 32-bit `nlist` entry.
pub const NLIST_32_SIZE: u32 = 12;
/// Size of a Mach-O relocation entry.
pub const RELOCATION_INFO_SIZE: u32 = 8;

/// arm64 macOS uses 16 KiB virtual pages for segment alignment.
pub const ARM64_PAGE_SIZE: u64 = 0x4000;
/// x86 macOS uses 4 KiB virtual pages.
pub const X86_PAGE_SIZE: u64 = 0x1000;
/// Back-compatible page-size constant used by the arm64 sample.
pub const PAGE_SIZE: u64 = ARM64_PAGE_SIZE;
/// The classic 4 GiB `__PAGEZERO` for 64-bit Mach-O.
pub const PAGEZERO_SIZE: u64 = 0x1_0000_0000;
/// 32-bit `__PAGEZERO` size.
pub const PAGEZERO_32_SIZE: u64 = 0x1000;
/// Load address of 64-bit `__TEXT`.
pub const TEXT_VMADDR: u64 = PAGEZERO_SIZE;
/// Load address of 32-bit `__TEXT`.
pub const TEXT_32_VMADDR: u64 = PAGEZERO_32_SIZE;

/// `CSMAGIC_EMBEDDED_SIGNATURE`.
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
/// `CSMAGIC_CODEDIRECTORY`.
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
/// `CSSLOT_CODEDIRECTORY`.
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
/// `CS_ADHOC` flag.
pub const CS_ADHOC: u32 = 0x0000_0002;
/// `CS_EXECSEG_MAIN_BINARY`.
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
/// `CS_HASHTYPE_SHA256`.
pub const CS_HASHTYPE_SHA256: u8 = 2;
/// SHA-256 digest length.
pub const CS_HASH_SIZE_SHA256: u8 = 32;
/// Code-signature page size is fixed at 4 KiB (log2).
pub const CS_PAGE_SHIFT: u8 = 12;
/// Code-signature page size in bytes.
pub const CS_PAGE_SIZE: u64 = 1 << CS_PAGE_SHIFT;
/// `CodeDirectory` version supporting the exec-segment fields.
pub const CS_CODEDIRECTORY_VERSION: u32 = 0x0002_0400;

// =====================================================================================
// Extended Mach-O specification constants.
//
// The set below rounds out coverage of the Mach-O format beyond the core load commands the
// reader and writer use directly. They are part of the crate's public `consts` API.
// =====================================================================================

// --- Magic numbers ---------------------------------------------------------------------

/// 32-bit big-endian Mach-O magic (`MH_CIGAM`).
pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
/// 64-bit big-endian Mach-O magic (`MH_CIGAM_64`).
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
/// 32-bit fat (universal) magic (`FAT_MAGIC`).
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
/// 32-bit fat (universal) magic, byte-swapped (`FAT_CIGAM`).
pub const FAT_CIGAM: u32 = 0xBEBA_FECA;
/// 64-bit fat (universal) magic (`FAT_MAGIC_64`).
pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// 64-bit fat (universal) magic, byte-swapped (`FAT_CIGAM_64`).
pub const FAT_CIGAM_64: u32 = 0xBFBA_FECA;

// --- File types (MH_*) -----------------------------------------------------------------

/// `MH_FVMLIB` file type.
pub const MH_FVMLIB: u32 = 0x3;
/// `MH_CORE` file type.
pub const MH_CORE: u32 = 0x4;
/// `MH_PRELOAD` file type.
pub const MH_PRELOAD: u32 = 0x5;
/// `MH_DYLIB` file type.
pub const MH_DYLIB: u32 = 0x6;
/// `MH_DYLINKER` file type.
pub const MH_DYLINKER: u32 = 0x7;
/// `MH_BUNDLE` file type.
pub const MH_BUNDLE: u32 = 0x8;
/// `MH_DYLIB_STUB` file type.
pub const MH_DYLIB_STUB: u32 = 0x9;
/// `MH_DSYM` file type.
pub const MH_DSYM: u32 = 0xA;
/// `MH_KEXT_BUNDLE` file type.
pub const MH_KEXT_BUNDLE: u32 = 0xB;
/// `MH_FILESET` file type.
pub const MH_FILESET: u32 = 0xC;
/// `MH_GPU_PROGRAM` file type.
pub const MH_GPU_PROGRAM: u32 = 0xD;
/// `MH_GPU_DYLIB` file type.
pub const MH_GPU_DYLIB: u32 = 0xE;

// --- Header flags (MH_*) ---------------------------------------------------------------

/// `MH_INCRLINK`.
pub const MH_INCRLINK: u32 = 0x2;
/// `MH_BINDATLOAD`.
pub const MH_BINDATLOAD: u32 = 0x8;
/// `MH_PREBOUND`.
pub const MH_PREBOUND: u32 = 0x10;
/// `MH_SPLIT_SEGS`.
pub const MH_SPLIT_SEGS: u32 = 0x20;
/// `MH_LAZY_INIT`.
pub const MH_LAZY_INIT: u32 = 0x40;
/// `MH_FORCE_FLAT`.
pub const MH_FORCE_FLAT: u32 = 0x100;
/// `MH_NOMULTIDEFS`.
pub const MH_NOMULTIDEFS: u32 = 0x200;
/// `MH_NOFIXPREBINDING`.
pub const MH_NOFIXPREBINDING: u32 = 0x400;
/// `MH_PREBINDABLE`.
pub const MH_PREBINDABLE: u32 = 0x800;
/// `MH_ALLMODSBOUND`.
pub const MH_ALLMODSBOUND: u32 = 0x1000;
/// `MH_SUBSECTIONS_VIA_SYMBOLS`.
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;
/// `MH_CANONICAL`.
pub const MH_CANONICAL: u32 = 0x4000;
/// `MH_WEAK_DEFINES`.
pub const MH_WEAK_DEFINES: u32 = 0x8000;
/// `MH_BINDS_TO_WEAK`.
pub const MH_BINDS_TO_WEAK: u32 = 0x1_0000;
/// `MH_ALLOW_STACK_EXECUTION`.
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
/// `MH_ROOT_SAFE`.
pub const MH_ROOT_SAFE: u32 = 0x4_0000;
/// `MH_SETUID_SAFE`.
pub const MH_SETUID_SAFE: u32 = 0x8_0000;
/// `MH_NO_REEXPORTED_DYLIBS`.
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x10_0000;
/// `MH_HAS_TLV_DESCRIPTORS`.
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
/// `MH_NO_HEAP_EXECUTION`.
pub const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;
/// `MH_APP_EXTENSION_SAFE`.
pub const MH_APP_EXTENSION_SAFE: u32 = 0x0200_0000;
/// `MH_NLIST_OUTOFSYNC_WITH_DYLDINFO`.
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO: u32 = 0x0400_0000;
/// `MH_SIM_SUPPORT`.
pub const MH_SIM_SUPPORT: u32 = 0x0800_0000;
/// `MH_DYLIB_IN_CACHE`.
pub const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

// --- CPU types -------------------------------------------------------------------------

/// `CPU_ARCH_ABI64` mask applied to a base CPU type for 64-bit variants.
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
/// `CPU_ARCH_ABI64_32` mask (ILP32 on a 64-bit ISA).
pub const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
/// `CPU_TYPE_ANY`.
pub const CPU_TYPE_ANY: u32 = 0xFFFF_FFFF;
/// `CPU_TYPE_VAX`.
pub const CPU_TYPE_VAX: u32 = 0x1;
/// `CPU_TYPE_MC680x0`.
pub const CPU_TYPE_MC680X0: u32 = 0x6;
/// `CPU_TYPE_MIPS`.
pub const CPU_TYPE_MIPS: u32 = 0x8;
/// `CPU_TYPE_MC98000`.
pub const CPU_TYPE_MC98000: u32 = 0xA;
/// `CPU_TYPE_HPPA`.
pub const CPU_TYPE_HPPA: u32 = 0xB;
/// `CPU_TYPE_MC88000`.
pub const CPU_TYPE_MC88000: u32 = 0xD;
/// `CPU_TYPE_SPARC`.
pub const CPU_TYPE_SPARC: u32 = 0xE;
/// `CPU_TYPE_I860`.
pub const CPU_TYPE_I860: u32 = 0xF;
/// `CPU_TYPE_ALPHA`.
pub const CPU_TYPE_ALPHA: u32 = 0x10;
/// `CPU_TYPE_POWERPC`.
pub const CPU_TYPE_POWERPC: u32 = 0x12;
/// `CPU_TYPE_POWERPC64`.
pub const CPU_TYPE_POWERPC64: u32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
/// `CPU_TYPE_ARM64_32`.
pub const CPU_TYPE_ARM64_32: u32 = 0x0000_000C | CPU_ARCH_ABI64_32;

// --- CPU subtypes ----------------------------------------------------------------------

/// `CPU_SUBTYPE_MASK` (feature/capability bits).
pub const CPU_SUBTYPE_MASK: u32 = 0xFF00_0000;
/// `CPU_SUBTYPE_LIB64` capability bit.
pub const CPU_SUBTYPE_LIB64: u32 = 0x8000_0000;

/// `CPU_SUBTYPE_386`.
pub const CPU_SUBTYPE_386: u32 = 0x3;
/// `CPU_SUBTYPE_486`.
pub const CPU_SUBTYPE_486: u32 = 0x4;
/// `CPU_SUBTYPE_486SX`.
pub const CPU_SUBTYPE_486SX: u32 = 0x84;
/// `CPU_SUBTYPE_PENT`.
pub const CPU_SUBTYPE_PENT: u32 = 0x5;
/// `CPU_SUBTYPE_PENTPRO`.
pub const CPU_SUBTYPE_PENTPRO: u32 = 0x16;
/// `CPU_SUBTYPE_PENTII_M3`.
pub const CPU_SUBTYPE_PENTII_M3: u32 = 0x36;
/// `CPU_SUBTYPE_PENTII_M5`.
pub const CPU_SUBTYPE_PENTII_M5: u32 = 0x56;
/// `CPU_SUBTYPE_CELERON`.
pub const CPU_SUBTYPE_CELERON: u32 = 0x67;
/// `CPU_SUBTYPE_PENTIUM_4`.
pub const CPU_SUBTYPE_PENTIUM_4: u32 = 0xA;

/// `CPU_SUBTYPE_X86_64_H` (Haswell).
pub const CPU_SUBTYPE_X86_64_H: u32 = 0x8;

/// `CPU_SUBTYPE_ARM_V4T`.
pub const CPU_SUBTYPE_ARM_V4T: u32 = 0x5;
/// `CPU_SUBTYPE_ARM_V6`.
pub const CPU_SUBTYPE_ARM_V6: u32 = 0x6;
/// `CPU_SUBTYPE_ARM_V5TEJ`.
pub const CPU_SUBTYPE_ARM_V5TEJ: u32 = 0x7;
/// `CPU_SUBTYPE_ARM_XSCALE`.
pub const CPU_SUBTYPE_ARM_XSCALE: u32 = 0x8;
/// `CPU_SUBTYPE_ARM_V7`.
pub const CPU_SUBTYPE_ARM_V7: u32 = 0x9;
/// `CPU_SUBTYPE_ARM_V7F`.
pub const CPU_SUBTYPE_ARM_V7F: u32 = 0xA;
/// `CPU_SUBTYPE_ARM_V7S`.
pub const CPU_SUBTYPE_ARM_V7S: u32 = 0xB;
/// `CPU_SUBTYPE_ARM_V7K`.
pub const CPU_SUBTYPE_ARM_V7K: u32 = 0xC;
/// `CPU_SUBTYPE_ARM_V6M`.
pub const CPU_SUBTYPE_ARM_V6M: u32 = 0xE;
/// `CPU_SUBTYPE_ARM_V7M`.
pub const CPU_SUBTYPE_ARM_V7M: u32 = 0xF;
/// `CPU_SUBTYPE_ARM_V7EM`.
pub const CPU_SUBTYPE_ARM_V7EM: u32 = 0x10;
/// `CPU_SUBTYPE_ARM_V8`.
pub const CPU_SUBTYPE_ARM_V8: u32 = 0xD;

/// `CPU_SUBTYPE_ARM64_V8`.
pub const CPU_SUBTYPE_ARM64_V8: u32 = 0x1;
/// `CPU_SUBTYPE_ARM64E`.
pub const CPU_SUBTYPE_ARM64E: u32 = 0x2;

/// `CPU_SUBTYPE_POWERPC_ALL`.
pub const CPU_SUBTYPE_POWERPC_ALL: u32 = 0x0;
/// `CPU_SUBTYPE_POWERPC_601`.
pub const CPU_SUBTYPE_POWERPC_601: u32 = 0x1;
/// `CPU_SUBTYPE_POWERPC_603`.
pub const CPU_SUBTYPE_POWERPC_603: u32 = 0x3;
/// `CPU_SUBTYPE_POWERPC_604`.
pub const CPU_SUBTYPE_POWERPC_604: u32 = 0x5;
/// `CPU_SUBTYPE_POWERPC_750`.
pub const CPU_SUBTYPE_POWERPC_750: u32 = 0x9;
/// `CPU_SUBTYPE_POWERPC_7400`.
pub const CPU_SUBTYPE_POWERPC_7400: u32 = 0xA;
/// `CPU_SUBTYPE_POWERPC_970`.
pub const CPU_SUBTYPE_POWERPC_970: u32 = 0x64;

// --- Load commands (LC_*) --------------------------------------------------------------

/// `LC_REQ_DYLD` flag OR-ed into commands `dyld` must understand.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
/// `LC_SYMSEG` load command (obsolete).
pub const LC_SYMSEG: u32 = 0x3;
/// `LC_THREAD` load command.
pub const LC_THREAD: u32 = 0x4;
/// `LC_UNIXTHREAD` load command.
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_LOADFVMLIB` load command (obsolete).
pub const LC_LOADFVMLIB: u32 = 0x6;
/// `LC_IDFVMLIB` load command (obsolete).
pub const LC_IDFVMLIB: u32 = 0x7;
/// `LC_IDENT` load command (obsolete).
pub const LC_IDENT: u32 = 0x8;
/// `LC_FVMFILE` load command (internal).
pub const LC_FVMFILE: u32 = 0x9;
/// `LC_PREPAGE` load command (internal).
pub const LC_PREPAGE: u32 = 0xA;
/// `LC_LOAD_DYLINKER` is defined in the core set; `LC_ID_DYLINKER` identifies a dynamic linker.
pub const LC_ID_DYLINKER: u32 = 0xF;
/// `LC_PREBOUND_DYLIB` load command.
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
/// `LC_ROUTINES` load command.
pub const LC_ROUTINES: u32 = 0x11;
/// `LC_SUB_FRAMEWORK` load command.
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
/// `LC_SUB_UMBRELLA` load command.
pub const LC_SUB_UMBRELLA: u32 = 0x13;
/// `LC_SUB_CLIENT` load command.
pub const LC_SUB_CLIENT: u32 = 0x14;
/// `LC_SUB_LIBRARY` load command.
pub const LC_SUB_LIBRARY: u32 = 0x15;
/// `LC_TWOLEVEL_HINTS` load command.
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
/// `LC_PREBIND_CKSUM` load command.
pub const LC_PREBIND_CKSUM: u32 = 0x17;
/// `LC_LOAD_WEAK_DYLIB` load command (`LC_REQ_DYLD | 0x18`).
pub const LC_LOAD_WEAK_DYLIB: u32 = LC_REQ_DYLD | 0x18;
/// `LC_ID_DYLIB` load command.
pub const LC_ID_DYLIB: u32 = 0xD;
/// `LC_ROUTINES_64` load command.
pub const LC_ROUTINES_64: u32 = 0x1A;
/// `LC_UUID` load command.
pub const LC_UUID: u32 = 0x1B;
/// `LC_RPATH` load command (`LC_REQ_DYLD | 0x1C`).
pub const LC_RPATH: u32 = LC_REQ_DYLD | 0x1C;
/// `LC_SEGMENT_SPLIT_INFO` load command.
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
/// `LC_REEXPORT_DYLIB` load command (`LC_REQ_DYLD | 0x1F`).
pub const LC_REEXPORT_DYLIB: u32 = LC_REQ_DYLD | 0x1F;
/// `LC_LAZY_LOAD_DYLIB` load command.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// `LC_ENCRYPTION_INFO` load command.
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// `LC_DYLD_INFO` load command.
pub const LC_DYLD_INFO: u32 = 0x22;
/// `LC_LOAD_UPWARD_DYLIB` load command (`LC_REQ_DYLD | 0x23`).
pub const LC_LOAD_UPWARD_DYLIB: u32 = LC_REQ_DYLD | 0x23;
/// `LC_VERSION_MIN_MACOSX` load command.
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// `LC_VERSION_MIN_IPHONEOS` load command.
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// `LC_FUNCTION_STARTS` load command.
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_DYLD_ENVIRONMENT` load command.
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
/// `LC_DATA_IN_CODE` load command.
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// `LC_SOURCE_VERSION` load command.
pub const LC_SOURCE_VERSION: u32 = 0x2A;
/// `LC_DYLIB_CODE_SIGN_DRS` load command.
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
/// `LC_ENCRYPTION_INFO_64` load command.
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
/// `LC_LINKER_OPTION` load command.
pub const LC_LINKER_OPTION: u32 = 0x2D;
/// `LC_LINKER_OPTIMIZATION_HINT` load command.
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
/// `LC_VERSION_MIN_TVOS` load command.
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
/// `LC_VERSION_MIN_WATCHOS` load command.
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// `LC_NOTE` load command.
pub const LC_NOTE: u32 = 0x31;
/// `LC_DYLD_EXPORTS_TRIE` load command (`LC_REQ_DYLD | 0x33`).
pub const LC_DYLD_EXPORTS_TRIE: u32 = LC_REQ_DYLD | 0x33;
/// `LC_DYLD_CHAINED_FIXUPS` load command (`LC_REQ_DYLD | 0x34`).
pub const LC_DYLD_CHAINED_FIXUPS: u32 = LC_REQ_DYLD | 0x34;
/// `LC_FILESET_ENTRY` load command (`LC_REQ_DYLD | 0x35`).
pub const LC_FILESET_ENTRY: u32 = LC_REQ_DYLD | 0x35;
/// `LC_ATOM_INFO` load command.
pub const LC_ATOM_INFO: u32 = 0x36;

// --- Section types (low byte of section flags) -----------------------------------------

/// `SECTION_TYPE` mask.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00FF;
/// `SECTION_ATTRIBUTES` mask.
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xFFFF_FF00;
/// `SECTION_ATTRIBUTES_USR` mask.
pub const SECTION_ATTRIBUTES_USR: u32 = 0xFF00_0000;
/// `SECTION_ATTRIBUTES_SYS` mask.
pub const SECTION_ATTRIBUTES_SYS: u32 = 0x00FF_FF00;
/// `S_CSTRING_LITERALS`.
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// `S_4BYTE_LITERALS`.
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// `S_8BYTE_LITERALS`.
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// `S_LITERAL_POINTERS`.
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// `S_NON_LAZY_SYMBOL_POINTERS`.
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// `S_LAZY_SYMBOL_POINTERS`.
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// `S_SYMBOL_STUBS`.
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// `S_MOD_INIT_FUNC_POINTERS`.
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// `S_MOD_TERM_FUNC_POINTERS`.
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
/// `S_COALESCED`.
pub const S_COALESCED: u32 = 0xB;
/// `S_GB_ZEROFILL`.
pub const S_GB_ZEROFILL: u32 = 0xC;
/// `S_INTERPOSING`.
pub const S_INTERPOSING: u32 = 0xD;
/// `S_16BYTE_LITERALS`.
pub const S_16BYTE_LITERALS: u32 = 0xE;
/// `S_DTRACE_DOF`.
pub const S_DTRACE_DOF: u32 = 0xF;
/// `S_LAZY_DYLIB_SYMBOL_POINTERS`.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// `S_THREAD_LOCAL_REGULAR`.
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// `S_THREAD_LOCAL_ZEROFILL`.
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// `S_THREAD_LOCAL_VARIABLES`.
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// `S_THREAD_LOCAL_VARIABLE_POINTERS`.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// `S_THREAD_LOCAL_INIT_FUNCTION_POINTERS`.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
/// `S_INIT_FUNC_OFFSETS`.
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

// --- Section attributes ----------------------------------------------------------------

/// `S_ATTR_PURE_INSTRUCTIONS`.
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
/// `S_ATTR_NO_TOC`.
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
/// `S_ATTR_STRIP_STATIC_SYMS`.
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
/// `S_ATTR_NO_DEAD_STRIP`.
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
/// `S_ATTR_LIVE_SUPPORT`.
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
/// `S_ATTR_SELF_MODIFYING_CODE`.
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
/// `S_ATTR_DEBUG`.
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
/// `S_ATTR_SOME_INSTRUCTIONS`.
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
/// `S_ATTR_EXT_RELOC`.
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
/// `S_ATTR_LOC_RELOC`.
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

// --- Symbol n_type / n_desc ------------------------------------------------------------

/// `N_STAB` mask (debug symbol bits).
pub const N_STAB: u8 = 0xE0;
/// `N_PEXT` bit (private external).
pub const N_PEXT: u8 = 0x10;
/// `N_ABS` symbol type.
pub const N_ABS: u8 = 0x2;
/// `N_PBUD` symbol type (prebound undefined).
pub const N_PBUD: u8 = 0xC;
/// `N_INDR` symbol type (indirect).
pub const N_INDR: u8 = 0xA;

/// `REFERENCE_TYPE` mask.
pub const REFERENCE_TYPE: u16 = 0x7;
/// `REFERENCE_FLAG_UNDEFINED_LAZY`.
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x1;
/// `REFERENCE_FLAG_DEFINED`.
pub const REFERENCE_FLAG_DEFINED: u16 = 0x2;
/// `REFERENCE_FLAG_PRIVATE_DEFINED`.
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16 = 0x3;
/// `REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY`.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 0x4;
/// `REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY`.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16 = 0x5;

/// `REFERENCED_DYNAMICALLY`.
pub const REFERENCED_DYNAMICALLY: u16 = 0x10;
/// `N_DESC_DISCARDED`.
pub const N_DESC_DISCARDED: u16 = 0x20;
/// `N_NO_DEAD_STRIP`.
pub const N_NO_DEAD_STRIP: u16 = 0x20;
/// `N_WEAK_REF`.
pub const N_WEAK_REF: u16 = 0x40;
/// `N_REF_TO_WEAK`.
pub const N_REF_TO_WEAK: u16 = 0x80;
/// `N_ARM_THUMB_DEF`.
pub const N_ARM_THUMB_DEF: u16 = 0x8;
/// `N_SYMBOL_RESOLVER`.
pub const N_SYMBOL_RESOLVER: u16 = 0x100;
/// `N_ALT_ENTRY`.
pub const N_ALT_ENTRY: u16 = 0x200;
/// `N_COLD_FUNC`.
pub const N_COLD_FUNC: u16 = 0x400;

/// `SELF_LIBRARY_ORDINAL`.
pub const SELF_LIBRARY_ORDINAL: u8 = 0x0;
/// `MAX_LIBRARY_ORDINAL`.
pub const MAX_LIBRARY_ORDINAL: u8 = 0xFD;
/// `DYNAMIC_LOOKUP_ORDINAL`.
pub const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xFE;
/// `EXECUTABLE_ORDINAL`.
pub const EXECUTABLE_ORDINAL: u8 = 0xFF;

/// `INDIRECT_SYMBOL_LOCAL`.
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
/// `INDIRECT_SYMBOL_ABS`.
pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

// --- Stab debug symbols ----------------------------------------------------------------

/// `N_GSYM` (global symbol).
pub const N_GSYM: u8 = 0x20;
/// `N_FNAME` (procedure name, f77).
pub const N_FNAME: u8 = 0x22;
/// `N_FUN` (procedure).
pub const N_FUN: u8 = 0x24;
/// `N_STSYM` (static symbol).
pub const N_STSYM: u8 = 0x26;
/// `N_LCSYM` (.lcomm symbol).
pub const N_LCSYM: u8 = 0x28;
/// `N_BNSYM` (begin nsect symbol).
pub const N_BNSYM: u8 = 0x2E;
/// `N_AST` (AST file path).
pub const N_AST: u8 = 0x32;
/// `N_OPT` (emitted with `gcc2_compiled`).
pub const N_OPT: u8 = 0x3C;
/// `N_RSYM` (register symbol).
pub const N_RSYM: u8 = 0x40;
/// `N_SLINE` (source line).
pub const N_SLINE: u8 = 0x44;
/// `N_ENSYM` (end nsect symbol).
pub const N_ENSYM: u8 = 0x4E;
/// `N_SSYM` (structure element).
pub const N_SSYM: u8 = 0x60;
/// `N_SO` (source file name).
pub const N_SO: u8 = 0x64;
/// `N_OSO` (object file name).
pub const N_OSO: u8 = 0x66;
/// `N_LSYM` (local symbol).
pub const N_LSYM: u8 = 0x80;
/// `N_BINCL` (include file beginning).
pub const N_BINCL: u8 = 0x82;
/// `N_SOL` (#included file name).
pub const N_SOL: u8 = 0x84;
/// `N_PARAMS` (compiler parameters).
pub const N_PARAMS: u8 = 0x86;
/// `N_VERSION` (compiler version).
pub const N_VERSION: u8 = 0x88;
/// `N_OLEVEL` (compiler optimization level).
pub const N_OLEVEL: u8 = 0x8A;
/// `N_PSYM` (parameter).
pub const N_PSYM: u8 = 0xA0;
/// `N_EINCL` (include file end).
pub const N_EINCL: u8 = 0xA2;
/// `N_ENTRY` (alternate entry).
pub const N_ENTRY: u8 = 0xA4;
/// `N_LBRAC` (left bracket).
pub const N_LBRAC: u8 = 0xC0;
/// `N_EXCL` (deleted include file).
pub const N_EXCL: u8 = 0xC2;
/// `N_RBRAC` (right bracket).
pub const N_RBRAC: u8 = 0xE0;
/// `N_BCOMM` (begin common).
pub const N_BCOMM: u8 = 0xE2;
/// `N_ECOMM` (end common).
pub const N_ECOMM: u8 = 0xE4;
/// `N_ECOML` (end common (local name)).
pub const N_ECOML: u8 = 0xE8;
/// `N_LENG` (second stab entry with length).
pub const N_LENG: u8 = 0xFE;

// --- Relocation types ------------------------------------------------------------------

/// `GENERIC_RELOC_VANILLA`.
pub const GENERIC_RELOC_VANILLA: u32 = 0x0;
/// `GENERIC_RELOC_PAIR`.
pub const GENERIC_RELOC_PAIR: u32 = 0x1;
/// `GENERIC_RELOC_SECTDIFF`.
pub const GENERIC_RELOC_SECTDIFF: u32 = 0x2;
/// `GENERIC_RELOC_PB_LA_PTR`.
pub const GENERIC_RELOC_PB_LA_PTR: u32 = 0x3;
/// `GENERIC_RELOC_LOCAL_SECTDIFF`.
pub const GENERIC_RELOC_LOCAL_SECTDIFF: u32 = 0x4;
/// `GENERIC_RELOC_TLV`.
pub const GENERIC_RELOC_TLV: u32 = 0x5;

/// `X86_64_RELOC_UNSIGNED`.
pub const X86_64_RELOC_UNSIGNED: u32 = 0x0;
/// `X86_64_RELOC_SIGNED`.
pub const X86_64_RELOC_SIGNED: u32 = 0x1;
/// `X86_64_RELOC_BRANCH`.
pub const X86_64_RELOC_BRANCH: u32 = 0x2;
/// `X86_64_RELOC_GOT_LOAD`.
pub const X86_64_RELOC_GOT_LOAD: u32 = 0x3;
/// `X86_64_RELOC_GOT`.
pub const X86_64_RELOC_GOT: u32 = 0x4;
/// `X86_64_RELOC_SUBTRACTOR`.
pub const X86_64_RELOC_SUBTRACTOR: u32 = 0x5;
/// `X86_64_RELOC_SIGNED_1`.
pub const X86_64_RELOC_SIGNED_1: u32 = 0x6;
/// `X86_64_RELOC_SIGNED_2`.
pub const X86_64_RELOC_SIGNED_2: u32 = 0x7;
/// `X86_64_RELOC_SIGNED_4`.
pub const X86_64_RELOC_SIGNED_4: u32 = 0x8;
/// `X86_64_RELOC_TLV`.
pub const X86_64_RELOC_TLV: u32 = 0x9;

/// `ARM_RELOC_VANILLA`.
pub const ARM_RELOC_VANILLA: u32 = 0x0;
/// `ARM_RELOC_PAIR`.
pub const ARM_RELOC_PAIR: u32 = 0x1;
/// `ARM_RELOC_SECTDIFF`.
pub const ARM_RELOC_SECTDIFF: u32 = 0x2;
/// `ARM_RELOC_LOCAL_SECTDIFF`.
pub const ARM_RELOC_LOCAL_SECTDIFF: u32 = 0x3;
/// `ARM_RELOC_PB_LA_PTR`.
pub const ARM_RELOC_PB_LA_PTR: u32 = 0x4;
/// `ARM_RELOC_BR24`.
pub const ARM_RELOC_BR24: u32 = 0x5;
/// `ARM_THUMB_RELOC_BR22`.
pub const ARM_THUMB_RELOC_BR22: u32 = 0x6;
/// `ARM_THUMB_32BIT_BRANCH`.
pub const ARM_THUMB_32BIT_BRANCH: u32 = 0x7;
/// `ARM_RELOC_HALF`.
pub const ARM_RELOC_HALF: u32 = 0x8;
/// `ARM_RELOC_HALF_SECTDIFF`.
pub const ARM_RELOC_HALF_SECTDIFF: u32 = 0x9;

/// `ARM64_RELOC_UNSIGNED`.
pub const ARM64_RELOC_UNSIGNED: u32 = 0x0;
/// `ARM64_RELOC_SUBTRACTOR`.
pub const ARM64_RELOC_SUBTRACTOR: u32 = 0x1;
/// `ARM64_RELOC_BRANCH26`.
pub const ARM64_RELOC_BRANCH26: u32 = 0x2;
/// `ARM64_RELOC_PAGE21`.
pub const ARM64_RELOC_PAGE21: u32 = 0x3;
/// `ARM64_RELOC_PAGEOFF12`.
pub const ARM64_RELOC_PAGEOFF12: u32 = 0x4;
/// `ARM64_RELOC_GOT_LOAD_PAGE21`.
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u32 = 0x5;
/// `ARM64_RELOC_GOT_LOAD_PAGEOFF12`.
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u32 = 0x6;
/// `ARM64_RELOC_POINTER_TO_GOT`.
pub const ARM64_RELOC_POINTER_TO_GOT: u32 = 0x7;
/// `ARM64_RELOC_TLVP_LOAD_PAGE21`.
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u32 = 0x8;
/// `ARM64_RELOC_TLVP_LOAD_PAGEOFF12`.
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u32 = 0x9;
/// `ARM64_RELOC_ADDEND`.
pub const ARM64_RELOC_ADDEND: u32 = 0xA;

/// `PPC_RELOC_VANILLA`.
pub const PPC_RELOC_VANILLA: u32 = 0x0;
/// `PPC_RELOC_PAIR`.
pub const PPC_RELOC_PAIR: u32 = 0x1;
/// `PPC_RELOC_BR14`.
pub const PPC_RELOC_BR14: u32 = 0x2;
/// `PPC_RELOC_BR24`.
pub const PPC_RELOC_BR24: u32 = 0x3;
/// `PPC_RELOC_HI16`.
pub const PPC_RELOC_HI16: u32 = 0x4;
/// `PPC_RELOC_LO16`.
pub const PPC_RELOC_LO16: u32 = 0x5;

// --- Platforms -------------------------------------------------------------------------

/// `PLATFORM_IOS`.
pub const PLATFORM_IOS: u32 = 2;
/// `PLATFORM_TVOS`.
pub const PLATFORM_TVOS: u32 = 3;
/// `PLATFORM_WATCHOS`.
pub const PLATFORM_WATCHOS: u32 = 4;
/// `PLATFORM_BRIDGEOS`.
pub const PLATFORM_BRIDGEOS: u32 = 5;
/// `PLATFORM_MACCATALYST`.
pub const PLATFORM_MACCATALYST: u32 = 6;
/// `PLATFORM_IOSSIMULATOR`.
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
/// `PLATFORM_TVOSSIMULATOR`.
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
/// `PLATFORM_WATCHOSSIMULATOR`.
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
/// `PLATFORM_DRIVERKIT`.
pub const PLATFORM_DRIVERKIT: u32 = 10;
/// `PLATFORM_FIRMWARE`.
pub const PLATFORM_FIRMWARE: u32 = 13;
/// `PLATFORM_SEPOS`.
pub const PLATFORM_SEPOS: u32 = 14;

// --- Build tools -----------------------------------------------------------------------

/// `TOOL_CLANG`.
pub const TOOL_CLANG: u32 = 1;
/// `TOOL_SWIFT`.
pub const TOOL_SWIFT: u32 = 2;
/// `TOOL_LD`.
pub const TOOL_LD: u32 = 3;
/// `TOOL_LLD`.
pub const TOOL_LLD: u32 = 4;

// --- Rebase / bind / export opcodes ----------------------------------------------------

/// `REBASE_TYPE_POINTER`.
pub const REBASE_TYPE_POINTER: u8 = 1;
/// `REBASE_TYPE_TEXT_ABSOLUTE32`.
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
/// `REBASE_TYPE_TEXT_PCREL32`.
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;
/// `REBASE_OPCODE_MASK`.
pub const REBASE_OPCODE_MASK: u8 = 0xF0;
/// `REBASE_IMMEDIATE_MASK`.
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
/// `REBASE_OPCODE_DONE`.
pub const REBASE_OPCODE_DONE: u8 = 0x00;
/// `REBASE_OPCODE_SET_TYPE_IMM`.
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
/// `REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB`.
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
/// `REBASE_OPCODE_ADD_ADDR_ULEB`.
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
/// `REBASE_OPCODE_ADD_ADDR_IMM_SCALED`.
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
/// `REBASE_OPCODE_DO_REBASE_IMM_TIMES`.
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
/// `REBASE_OPCODE_DO_REBASE_ULEB_TIMES`.
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
/// `REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB`.
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
/// `REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB`.
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

/// `BIND_TYPE_POINTER`.
pub const BIND_TYPE_POINTER: u8 = 1;
/// `BIND_TYPE_TEXT_ABSOLUTE32`.
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
/// `BIND_TYPE_TEXT_PCREL32`.
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;
/// `BIND_SPECIAL_DYLIB_SELF`.
pub const BIND_SPECIAL_DYLIB_SELF: i8 = 0;
/// `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`.
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i8 = -1;
/// `BIND_SPECIAL_DYLIB_FLAT_LOOKUP`.
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i8 = -2;
/// `BIND_SPECIAL_DYLIB_WEAK_LOOKUP`.
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i8 = -3;
/// `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
/// `BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION`.
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;
/// `BIND_OPCODE_MASK`.
pub const BIND_OPCODE_MASK: u8 = 0xF0;
/// `BIND_IMMEDIATE_MASK`.
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
/// `BIND_OPCODE_DONE`.
pub const BIND_OPCODE_DONE: u8 = 0x00;
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM`.
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
/// `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB`.
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
/// `BIND_OPCODE_SET_DYLIB_SPECIAL_IMM`.
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
/// `BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM`.
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
/// `BIND_OPCODE_SET_TYPE_IMM`.
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
/// `BIND_OPCODE_SET_ADDEND_SLEB`.
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
/// `BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB`.
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
/// `BIND_OPCODE_ADD_ADDR_ULEB`.
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
/// `BIND_OPCODE_DO_BIND`.
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB`.
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
/// `BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED`.
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
/// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB`.
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;

/// `EXPORT_SYMBOL_FLAGS_KIND_MASK`.
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u32 = 0x3;
/// `EXPORT_SYMBOL_FLAGS_KIND_REGULAR`.
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u32 = 0x0;
/// `EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL`.
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u32 = 0x1;
/// `EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE`.
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u32 = 0x2;
/// `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`.
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u32 = 0x4;
/// `EXPORT_SYMBOL_FLAGS_REEXPORT`.
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u32 = 0x8;
/// `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`.
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u32 = 0x10;

// --- Chained fixups --------------------------------------------------------------------

/// `DYLD_CHAINED_IMPORT`.
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// `DYLD_CHAINED_IMPORT_ADDEND`.
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// `DYLD_CHAINED_IMPORT_ADDEND64`.
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;
/// `DYLD_CHAINED_PTR_ARM64E`.
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
/// `DYLD_CHAINED_PTR_64`.
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// `DYLD_CHAINED_PTR_32`.
pub const DYLD_CHAINED_PTR_32: u16 = 3;
/// `DYLD_CHAINED_PTR_32_CACHE`.
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
/// `DYLD_CHAINED_PTR_32_FIRMWARE`.
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
/// `DYLD_CHAINED_PTR_64_OFFSET`.
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// `DYLD_CHAINED_PTR_ARM64E_KERNEL`.
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
/// `DYLD_CHAINED_PTR_64_KERNEL_CACHE`.
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND`.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
/// `DYLD_CHAINED_PTR_ARM64E_FIRMWARE`.
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
/// `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE`.
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
/// `DYLD_CHAINED_PTR_ARM64E_USERLAND24`.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

// --- Code signing ----------------------------------------------------------------------

/// `CSMAGIC_REQUIREMENT`.
pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE_0C00;
/// `CSMAGIC_REQUIREMENTS`.
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
/// `CSMAGIC_DETACHED_SIGNATURE`.
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;
/// `CSMAGIC_BLOBWRAPPER`.
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
/// `CSMAGIC_EMBEDDED_ENTITLEMENTS`.
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;
/// `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS`.
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xFADE_7172;

/// `CS_HASHTYPE_SHA1`.
pub const CS_HASHTYPE_SHA1: u8 = 1;
/// `CS_HASHTYPE_SHA256_TRUNCATED`.
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
/// `CS_HASHTYPE_SHA384`.
pub const CS_HASHTYPE_SHA384: u8 = 4;
/// `CS_HASHTYPE_SHA512`.
pub const CS_HASHTYPE_SHA512: u8 = 5;

/// `CSSLOT_INFOSLOT`.
pub const CSSLOT_INFOSLOT: u32 = 1;
/// `CSSLOT_REQUIREMENTS`.
pub const CSSLOT_REQUIREMENTS: u32 = 2;
/// `CSSLOT_RESOURCEDIR`.
pub const CSSLOT_RESOURCEDIR: u32 = 3;
/// `CSSLOT_APPLICATION`.
pub const CSSLOT_APPLICATION: u32 = 4;
/// `CSSLOT_ENTITLEMENTS`.
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
/// `CSSLOT_DER_ENTITLEMENTS`.
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
/// `CSSLOT_ALTERNATE_CODEDIRECTORIES`.
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
/// `CSSLOT_SIGNATURESLOT`.
pub const CSSLOT_SIGNATURESLOT: u32 = 0x1_0000;

/// `CS_VALID`.
pub const CS_VALID: u32 = 0x0000_0001;
/// `CS_GET_TASK_ALLOW`.
pub const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;
/// `CS_INSTALLER`.
pub const CS_INSTALLER: u32 = 0x0000_0008;
/// `CS_FORCED_LV`.
pub const CS_FORCED_LV: u32 = 0x0000_0010;
/// `CS_INVALID_ALLOWED`.
pub const CS_INVALID_ALLOWED: u32 = 0x0000_0020;
/// `CS_HARD`.
pub const CS_HARD: u32 = 0x0000_0100;
/// `CS_KILL`.
pub const CS_KILL: u32 = 0x0000_0200;
/// `CS_CHECK_EXPIRATION`.
pub const CS_CHECK_EXPIRATION: u32 = 0x0000_0400;
/// `CS_RESTRICT`.
pub const CS_RESTRICT: u32 = 0x0000_0800;
/// `CS_ENFORCEMENT`.
pub const CS_ENFORCEMENT: u32 = 0x0000_1000;
/// `CS_REQUIRE_LV`.
pub const CS_REQUIRE_LV: u32 = 0x0000_2000;
/// `CS_RUNTIME`.
pub const CS_RUNTIME: u32 = 0x0001_0000;
/// `CS_LINKER_SIGNED`.
pub const CS_LINKER_SIGNED: u32 = 0x0002_0000;

// --- Additional structure sizes --------------------------------------------------------

/// Size of a `fat_header`.
pub const FAT_HEADER_SIZE: u32 = 8;
/// Size of a `fat_arch`.
pub const FAT_ARCH_SIZE: u32 = 20;
/// Size of a `fat_arch_64`.
pub const FAT_ARCH_64_SIZE: u32 = 32;
/// Size of an `LC_UUID` command.
pub const UUID_COMMAND_SIZE: u32 = 24;
/// Fixed `LC_RPATH` header bytes before the path string.
pub const RPATH_COMMAND_HEADER_SIZE: u32 = 12;
/// Size of an `LC_SOURCE_VERSION` command.
pub const SOURCE_VERSION_COMMAND_SIZE: u32 = 16;
/// Size of an `LC_VERSION_MIN_*` command.
pub const VERSION_MIN_COMMAND_SIZE: u32 = 16;
/// Size of an `LC_ENCRYPTION_INFO` command.
pub const ENCRYPTION_INFO_COMMAND_SIZE: u32 = 20;
/// Size of an `LC_ENCRYPTION_INFO_64` command.
pub const ENCRYPTION_INFO_64_COMMAND_SIZE: u32 = 24;
/// Size of a `linkedit_data_command` (`LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, ...).
pub const LINKEDIT_DATA_COMMAND_SIZE: u32 = 16;
/// Fixed header bytes of an `LC_THREAD`/`LC_UNIXTHREAD` command before the thread state.
pub const THREAD_COMMAND_HEADER_SIZE: u32 = 16;
