//! PDB/MSF constants.

/// MSF 7 magic bytes.
pub const MSF_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0";
/// Canonical block size used by the Stratum writer.
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
/// Fixed PDB stream index.
pub const STREAM_PDB: u32 = 1;
/// Fixed TPI stream index.
pub const STREAM_TPI: u32 = 2;
/// Fixed DBI stream index.
pub const STREAM_DBI: u32 = 3;
/// Fixed IPI stream index.
pub const STREAM_IPI: u32 = 4;
/// PDB stream version commonly used by modern native PDBs.
pub const PDB_VERSION_VC70: u32 = 20_000_404;
/// VC140 feature flag.
pub const FEATURE_VC140: u32 = 20_140_508;
/// Minimal debug info feature flag (`/DEBUG:FASTLINK`).
pub const FEATURE_MINIMAL_DEBUG_INFO: u32 = 0x494E_494D;
/// TPI/IPI stream version used by the writer.
pub const TPI_VERSION_80: u32 = 20_040_203;
/// First `CodeView` user type index.
pub const TYPE_INDEX_BEGIN: u32 = 0x1000;
/// Stratum DBI stream marker.
pub const STRATUM_DBI_MAGIC: &[u8; 4] = b"SDBI";
/// Stratum module stream marker.
pub const STRATUM_MODULE_MAGIC: &[u8; 4] = b"SMOD";
/// Stratum symbol stream marker.
pub const STRATUM_SYMBOL_MAGIC: &[u8; 4] = b"SSYM";
