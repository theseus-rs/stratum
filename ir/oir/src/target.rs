//! Target description: architecture, endianness, and pointer width.
//!
//! A [`TargetSpec`] is the small bundle of facts a codec needs to lay bytes out correctly.
//! It is deliberately data; the same read/write code handles every triple in the build
//! matrix by branching on these values rather than on per-target code paths.

/// Byte order of multi-byte integers in the encoded image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

/// Width of a pointer / native machine word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtrWidth {
    /// 32-bit pointers.
    W32,
    /// 64-bit pointers.
    W64,
}

impl PtrWidth {
    /// The width in bytes (`4` or `8`).
    #[must_use]
    #[inline(never)]
    pub const fn bytes(self) -> u8 {
        match self {
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }
}

/// Instruction-set architecture of the encoded image.
///
/// The variants cover every ISA family in the CI build matrix; the
/// [`Other`](Architecture::Other) arm preserves the raw format-specific machine id for
/// round-tripping images Stratum does not model in detail. Endianness and pointer width are
/// carried separately on [`TargetSpec`], so big-/little-endian and 32-/64-bit flavours of the
/// same ISA share one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// 32-bit x86 (`i386`/`i586`/`i686`).
    X86,
    /// `x86_64` / AMD64.
    X86_64,
    /// 32-bit Arm (`arm`, `armv5te`, `armv7`, `thumb*`).
    Arm,
    /// 64-bit Arm (`aarch64`, `aarch64_be`).
    Aarch64,
    /// 64-bit RISC-V (`riscv64gc`).
    Riscv64,
    /// 32-bit PowerPC (`powerpc`).
    PowerPc,
    /// 64-bit PowerPC (`powerpc64`, `powerpc64le`).
    PowerPc64,
    /// 32-bit MIPS (`mips`, `mipsel`).
    Mips,
    /// 64-bit MIPS (`mips64`, `mips64el`).
    Mips64,
    /// IBM Z (`s390x`).
    S390x,
    /// 64-bit `LoongArch` (`loongarch64`).
    LoongArch64,
    /// 64-bit SPARC (`sparc64`, `sparcv9`).
    Sparc64,
    /// 32-bit WebAssembly.
    Wasm32,
    /// An architecture Stratum does not model, keyed by its raw machine id.
    Other(u32),
}

impl Architecture {
    /// A short, stable lowercase name used in dumps and diagnostics.
    #[must_use]
    #[inline(never)]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
            Self::PowerPc => "powerpc",
            Self::PowerPc64 => "powerpc64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::S390x => "s390x",
            Self::LoongArch64 => "loongarch64",
            Self::Sparc64 => "sparc64",
            Self::Wasm32 => "wasm32",
            Self::Other(_) => "other",
        }
    }
}

/// The architecture, endianness, and pointer width a codec must honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TargetSpec {
    /// Instruction-set architecture.
    pub arch: Architecture,
    /// Byte order.
    pub endian: Endianness,
    /// Pointer width.
    pub ptr_width: PtrWidth,
}

impl TargetSpec {
    /// Creates a target spec.
    #[must_use]
    pub const fn new(arch: Architecture, endian: Endianness, ptr_width: PtrWidth) -> Self {
        Self {
            arch,
            endian,
            ptr_width,
        }
    }

    /// `x86_64-unknown-linux` style: little-endian, 64-bit.
    #[must_use]
    pub const fn x86_64() -> Self {
        Self::new(Architecture::X86_64, Endianness::Little, PtrWidth::W64)
    }

    /// `aarch64` style: little-endian, 64-bit.
    #[must_use]
    pub const fn aarch64() -> Self {
        Self::new(Architecture::Aarch64, Endianness::Little, PtrWidth::W64)
    }

    /// `wasm32`: little-endian, 32-bit.
    #[must_use]
    pub const fn wasm32() -> Self {
        Self::new(Architecture::Wasm32, Endianness::Little, PtrWidth::W32)
    }

    /// 32-bit x86 (`i686`/`i586`): little-endian, 32-bit.
    #[must_use]
    pub const fn x86() -> Self {
        Self::new(Architecture::X86, Endianness::Little, PtrWidth::W32)
    }

    /// 32-bit little-endian Arm (`armv7`/`armv5te`/`thumb*`).
    #[must_use]
    pub const fn arm() -> Self {
        Self::new(Architecture::Arm, Endianness::Little, PtrWidth::W32)
    }

    /// Big-endian 64-bit Arm (`aarch64_be`).
    #[must_use]
    pub const fn aarch64_be() -> Self {
        Self::new(Architecture::Aarch64, Endianness::Big, PtrWidth::W64)
    }

    /// 64-bit little-endian RISC-V (`riscv64gc`).
    #[must_use]
    pub const fn riscv64() -> Self {
        Self::new(Architecture::Riscv64, Endianness::Little, PtrWidth::W64)
    }

    /// 32-bit big-endian PowerPC (`powerpc`).
    #[must_use]
    pub const fn powerpc() -> Self {
        Self::new(Architecture::PowerPc, Endianness::Big, PtrWidth::W32)
    }

    /// 64-bit big-endian PowerPC (`powerpc64`).
    #[must_use]
    pub const fn powerpc64() -> Self {
        Self::new(Architecture::PowerPc64, Endianness::Big, PtrWidth::W64)
    }

    /// 64-bit little-endian PowerPC (`powerpc64le`).
    #[must_use]
    pub const fn powerpc64le() -> Self {
        Self::new(Architecture::PowerPc64, Endianness::Little, PtrWidth::W64)
    }

    /// IBM Z (`s390x`): big-endian, 64-bit.
    #[must_use]
    pub const fn s390x() -> Self {
        Self::new(Architecture::S390x, Endianness::Big, PtrWidth::W64)
    }

    /// 32-bit big-endian MIPS (`mips`).
    #[must_use]
    pub const fn mips() -> Self {
        Self::new(Architecture::Mips, Endianness::Big, PtrWidth::W32)
    }

    /// 32-bit little-endian MIPS (`mipsel`).
    #[must_use]
    pub const fn mipsel() -> Self {
        Self::new(Architecture::Mips, Endianness::Little, PtrWidth::W32)
    }

    /// 64-bit big-endian MIPS (`mips64`).
    #[must_use]
    pub const fn mips64() -> Self {
        Self::new(Architecture::Mips64, Endianness::Big, PtrWidth::W64)
    }

    /// 64-bit little-endian MIPS (`mips64el`).
    #[must_use]
    pub const fn mips64el() -> Self {
        Self::new(Architecture::Mips64, Endianness::Little, PtrWidth::W64)
    }

    /// 64-bit little-endian `LoongArch` (`loongarch64`).
    #[must_use]
    pub const fn loongarch64() -> Self {
        Self::new(Architecture::LoongArch64, Endianness::Little, PtrWidth::W64)
    }

    /// 64-bit big-endian SPARC (`sparc64`/`sparcv9`).
    #[must_use]
    pub const fn sparc64() -> Self {
        Self::new(Architecture::Sparc64, Endianness::Big, PtrWidth::W64)
    }

    /// Derives a target spec from the architecture token of a target triple
    /// (the substring before the first `-`, e.g. `x86_64` in `x86_64-unknown-linux-gnu`).
    ///
    /// Returns `None` for an architecture token Stratum does not recognise.
    #[must_use]
    pub fn from_triple(triple: &str) -> Option<Self> {
        let arch = triple.split('-').next().unwrap_or(triple);
        let spec = match arch {
            "x86_64" | "x86_64h" => Self::x86_64(),
            "i386" | "i486" | "i586" | "i686" => Self::x86(),
            "aarch64" | "arm64" => Self::aarch64(),
            "aarch64_be" => Self::aarch64_be(),
            "riscv64gc" | "riscv64" => Self::riscv64(),
            "powerpc" | "ppc" => Self::powerpc(),
            "powerpc64" | "ppc64" => Self::powerpc64(),
            "powerpc64le" | "ppc64le" => Self::powerpc64le(),
            "s390x" => Self::s390x(),
            "mips" => Self::mips(),
            "mipsel" => Self::mipsel(),
            "mips64" => Self::mips64(),
            "mips64el" => Self::mips64el(),
            "loongarch64" => Self::loongarch64(),
            "sparc64" | "sparcv9" => Self::sparc64(),
            "wasm32" => Self::wasm32(),
            other if is_arm32(other) => Self::arm(),
            _ => return None,
        };
        Some(spec)
    }
}

/// Recognises the 32-bit Arm family arch tokens (`arm`, `armv5te`, `armv7`, `thumbv7m`, ...).
fn is_arm32(arch: &str) -> bool {
    arch.starts_with("arm") || arch.starts_with("thumb")
}

/// The concrete container format an [`ObjectModule`](crate::ObjectModule) was read from or
/// will be written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    /// Executable and Linkable Format (Linux, BSD, etc.).
    Elf,
    /// Mach object (Apple platforms).
    MachO,
    /// Portable Executable / COFF (Windows).
    Pe,
    /// WebAssembly module.
    Wasm,
}

impl BinaryFormat {
    /// A short, stable lowercase name used in dumps and diagnostics.
    #[must_use]
    #[inline(never)]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Pe => "pe",
            Self::Wasm => "wasm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Architecture, BinaryFormat, Endianness, PtrWidth, TargetSpec};

    #[test]
    fn ptr_width_bytes() {
        assert_eq!(PtrWidth::W32.bytes(), 4);
        assert_eq!(PtrWidth::W64.bytes(), 8);
    }

    #[test]
    fn presets_match_expectations() {
        assert_eq!(
            TargetSpec::x86_64(),
            TargetSpec::new(Architecture::X86_64, Endianness::Little, PtrWidth::W64)
        );
        assert_eq!(TargetSpec::aarch64().arch, Architecture::Aarch64);
        assert_eq!(TargetSpec::wasm32().ptr_width, PtrWidth::W32);
    }

    #[test]
    fn format_names_are_stable() {
        assert_eq!(BinaryFormat::Elf.name(), "elf");
        assert_eq!(BinaryFormat::MachO.name(), "macho");
        assert_eq!(BinaryFormat::Pe.name(), "pe");
        assert_eq!(BinaryFormat::Wasm.name(), "wasm");
    }

    #[test]
    fn arch_names_are_stable() {
        assert_eq!(Architecture::X86.name(), "x86");
        assert_eq!(Architecture::X86_64.name(), "x86_64");
        assert_eq!(Architecture::Arm.name(), "arm");
        assert_eq!(Architecture::Aarch64.name(), "aarch64");
        assert_eq!(Architecture::Riscv64.name(), "riscv64");
        assert_eq!(Architecture::PowerPc.name(), "powerpc");
        assert_eq!(Architecture::PowerPc64.name(), "powerpc64");
        assert_eq!(Architecture::Mips.name(), "mips");
        assert_eq!(Architecture::Mips64.name(), "mips64");
        assert_eq!(Architecture::S390x.name(), "s390x");
        assert_eq!(Architecture::LoongArch64.name(), "loongarch64");
        assert_eq!(Architecture::Sparc64.name(), "sparc64");
        assert_eq!(Architecture::Wasm32.name(), "wasm32");
        assert_eq!(Architecture::Other(0x42).name(), "other");
    }

    #[test]
    fn from_triple_maps_arch_endian_and_width() {
        assert_eq!(
            TargetSpec::from_triple("x86_64-unknown-linux-gnu"),
            Some(TargetSpec::x86_64())
        );
        assert_eq!(
            TargetSpec::from_triple("i686-unknown-linux-gnu"),
            Some(TargetSpec::x86())
        );
        assert_eq!(
            TargetSpec::from_triple("aarch64-apple-darwin"),
            Some(TargetSpec::aarch64())
        );
        assert_eq!(
            TargetSpec::from_triple("arm64-apple-darwin"),
            Some(TargetSpec::aarch64())
        );

        let be = TargetSpec::from_triple("aarch64_be-unknown-linux-gnu").unwrap();
        assert_eq!(be.arch, Architecture::Aarch64);
        assert_eq!(be.endian, Endianness::Big);

        assert_eq!(
            TargetSpec::from_triple("riscv64gc-unknown-linux-gnu"),
            Some(TargetSpec::riscv64())
        );
        assert_eq!(
            TargetSpec::from_triple("powerpc-unknown-linux-gnu"),
            Some(TargetSpec::powerpc())
        );
        assert_eq!(
            TargetSpec::from_triple("ppc64-unknown-linux-gnu"),
            Some(TargetSpec::powerpc64())
        );
        let ppcle = TargetSpec::from_triple("powerpc64le-unknown-linux-gnu").unwrap();
        assert_eq!(ppcle.arch, Architecture::PowerPc64);
        assert_eq!(ppcle.endian, Endianness::Little);

        assert_eq!(
            TargetSpec::from_triple("mipsel-unknown-linux-gnu")
                .unwrap()
                .endian,
            Endianness::Little
        );
        assert_eq!(
            TargetSpec::from_triple("mips-unknown-linux-gnu")
                .unwrap()
                .endian,
            Endianness::Big
        );
        assert_eq!(
            TargetSpec::from_triple("mips64-unknown-linux-gnu"),
            Some(TargetSpec::mips64())
        );
        assert_eq!(
            TargetSpec::from_triple("mips64el-unknown-linux-gnu"),
            Some(TargetSpec::mips64el())
        );
        assert_eq!(
            TargetSpec::from_triple("s390x-unknown-linux-gnu")
                .unwrap()
                .endian,
            Endianness::Big
        );
        assert_eq!(
            TargetSpec::from_triple("loongarch64-unknown-linux-gnu"),
            Some(TargetSpec::loongarch64())
        );
        assert_eq!(
            TargetSpec::from_triple("sparcv9-sun-solaris"),
            Some(TargetSpec::sparc64())
        );

        assert_eq!(
            TargetSpec::from_triple("armv7-unknown-linux-gnueabihf")
                .unwrap()
                .arch,
            Architecture::Arm
        );
        assert_eq!(
            TargetSpec::from_triple("thumbv7em-none-eabi").unwrap().arch,
            Architecture::Arm
        );
        assert_eq!(
            TargetSpec::from_triple("wasm32-wasi"),
            Some(TargetSpec::wasm32())
        );

        assert_eq!(TargetSpec::from_triple("nonsense-foo-bar"), None);
    }
}
