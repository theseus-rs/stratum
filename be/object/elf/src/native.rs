//! Lossless ELF-native structures and byte parsing.

use crate::consts::{MAGIC, elf32, elf64};
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use stratum_oir::{
    Architecture, BinaryFormat, ByteReader, Endianness, Error, ObjectModule, PtrWidth, RelocKind,
    Relocation, Result, Section, SectionFlags, SectionId, SectionKind, Segment, SymbolBinding,
    SymbolEntry, SymbolFlags, SymbolId, SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use bitflags::bitflags;

const EI_NIDENT: usize = ElfIdentField::Nident.raw();
const PN_XNUM: u16 = 0xffff;

macro_rules! lossless_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident : $raw:ty {
            $($variant:ident = $value:expr,)*
            ;
            $other:ident($other_ty:ty),
        }
        canonical {
            $($canonical_variant:ident = $canonical_value:expr,)*
        }
        default $default:expr;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        pub enum $name {
            $($variant,)*
            $other($other_ty),
        }

        impl $name {
            #[must_use]
            pub const fn from_raw(raw: $raw) -> Self {
                $(if raw == $canonical_value {
                    return Self::$canonical_variant;
                })*
                Self::$other(raw)
            }

            #[must_use]
            pub const fn raw(self) -> $raw {
                match self {
                    $(Self::$variant => $value,)*
                    Self::$other(raw) => raw,
                }
            }
        }

        impl From<$raw> for $name {
            fn from(raw: $raw) -> Self {
                Self::from_raw(raw)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::from_raw($default)
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.raw() == other.raw()
            }
        }

        impl Eq for $name {}

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.raw().cmp(&other.raw())
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.raw().hash(state);
            }
        }
    };
}

lossless_enum! {
    /// ELF file type.
    pub enum ElfType: u16 {
        None = 0,
        Relocatable = 1,
        Executable = 2,
        Dynamic = 3,
        Core = 4,
        Dyn = 3,
        Exec = 2,
        Hios = 0xfeff,
        Hiproc = 0xffff,
        Loos = 0xfe00,
        Loproc = 0xff00,
        Rel = 1,
        ;
        Other(u16),
    }
    canonical {
        None = 0,
        Relocatable = 1,
        Executable = 2,
        Dynamic = 3,
        Core = 4,
        Hios = 0xfeff,
        Hiproc = 0xffff,
        Loos = 0xfe00,
        Loproc = 0xff00,
    }
    default 0;
}

lossless_enum! {
    /// ELF machine architecture.
    pub enum ElfMachine: u16 {
        None = 0,
        X86 = 3,
        X86_64 = 62,
        Arm = 40,
        Aarch64 = 183,
        Riscv = 243,
        PowerPc = 20,
        PowerPc64 = 21,
        Mips = 8,
        S390 = 22,
        LoongArch = 258,
        SparcV9 = 43,
        X386 = 3,
        X56800Ex = 200,
        X68Hc05 = 72,
        X68Hc08 = 71,
        X68Hc11 = 70,
        X68Hc12 = 53,
        X68Hc16 = 69,
        X68K = 4,
        X78Kor = 199,
        X8051 = 165,
        X860 = 7,
        X88K = 5,
        X960 = 19,
        Alpha = 41,
        AlteraNios2 = 113,
        Amdgpu = 224,
        Arc = 45,
        Arca = 109,
        ArcCompact = 93,
        ArcCompact2 = 195,
        Avr = 83,
        Avr32 = 185,
        Ba1 = 201,
        Ba2 = 202,
        Blackfin = 106,
        Bpf = 247,
        C166 = 116,
        Cdp = 215,
        Ce = 119,
        Cloudshield = 192,
        Coge = 216,
        Coldfire = 52,
        Cool = 217,
        Corea1St = 193,
        Corea2Nd = 194,
        Cr = 103,
        Cr16 = 177,
        Craynv2 = 172,
        Cris = 76,
        Crx = 114,
        Csky = 252,
        CsrKalimba = 219,
        Cuda = 190,
        CypressM8C = 161,
        D10V = 85,
        D30V = 86,
        Dsp24 = 136,
        Dspic30F = 118,
        Dxp = 112,
        Ecog1 = 168,
        Ecog16 = 176,
        Ecog1X = 168,
        Ecog2 = 134,
        Etpu = 178,
        Excess = 111,
        F2Mc16 = 104,
        Firepath = 78,
        Fr20 = 37,
        Fr30 = 84,
        Fx66 = 66,
        H8S = 48,
        H8300 = 46,
        H8300H = 47,
        H8500 = 49,
        Hexagon = 164,
        Huany = 81,
        Iamcu = 6,
        Ia64 = 50,
        Intel205 = 205,
        Intel206 = 206,
        Intel207 = 207,
        Intel208 = 208,
        Intel209 = 209,
        Ip2K = 101,
        Javelin = 77,
        K10M = 181,
        Km32 = 210,
        Kmx16 = 212,
        Kmx32 = 211,
        Kmx8 = 213,
        Kvarc = 214,
        L10M = 180,
        Lanai = 244,
        Latticemico32 = 138,
        Loongarch = 258,
        M16C = 117,
        M32 = 1,
        M32C = 120,
        M32R = 88,
        Manik = 171,
        Max = 102,
        Maxq30 = 169,
        MchpPic = 204,
        McstElbrus = 175,
        Me16 = 59,
        Metag = 174,
        Microblaze = 189,
        MipsRs3Le = 10,
        MipsX = 51,
        Mma = 54,
        MmdspPlus = 160,
        Mmix = 80,
        Mn10200 = 90,
        Mn10300 = 89,
        Msp430 = 105,
        Ncpu = 56,
        Ndr1 = 57,
        Nds32 = 167,
        Norc = 218,
        Ns32K = 97,
        Open8 = 196,
        Openrisc = 92,
        Parisc = 15,
        Pcp = 55,
        Pdp10 = 64,
        Pdp11 = 65,
        Pdsp = 63,
        Pj = 91,
        Ppc = 20,
        Ppc64 = 21,
        Prism = 82,
        R32C = 162,
        Rce = 39,
        Rh32 = 38,
        Rl78 = 197,
        Rs08 = 132,
        Rx = 173,
        S370 = 9,
        Score7 = 135,
        Sep = 108,
        SeC17 = 139,
        SeC33 = 107,
        Sh = 42,
        Sharc = 133,
        Sle9X = 179,
        Snp1K = 99,
        Sparc = 2,
        Sparc32Plus = 18,
        Sparcv9 = 43,
        Spu = 23,
        St100 = 60,
        St19 = 74,
        St200 = 100,
        St7 = 68,
        St9Plus = 67,
        Starcore = 58,
        Stm8 = 186,
        Stxp7X = 166,
        Svx = 73,
        Tile64 = 187,
        Tilegx = 191,
        Tilepro = 188,
        Tinyj = 61,
        TiC2000 = 141,
        TiC5500 = 142,
        TiC6000 = 140,
        TmmGpp = 96,
        Tpc = 98,
        Tricore = 44,
        Trimedia = 163,
        Tsk3000 = 131,
        Unicore = 110,
        V800 = 36,
        V850 = 87,
        Vax = 75,
        Ve = 251,
        Videocore = 95,
        Videocore3 = 137,
        Videocore5 = 198,
        Vpp500 = 17,
        X8664 = 62,
        Xcore = 203,
        Xgate = 115,
        Ximo16 = 170,
        Xtensa = 94,
        Zsp = 79,
        ;
        Other(u16),
    }
    canonical {
        None = 0,
        X86 = 3,
        X86_64 = 62,
        Arm = 40,
        Aarch64 = 183,
        Riscv = 243,
        PowerPc = 20,
        PowerPc64 = 21,
        Mips = 8,
        S390 = 22,
        LoongArch = 258,
        SparcV9 = 43,
        X56800Ex = 200,
        X68Hc05 = 72,
        X68Hc08 = 71,
        X68Hc11 = 70,
        X68Hc12 = 53,
        X68Hc16 = 69,
        X68K = 4,
        X78Kor = 199,
        X8051 = 165,
        X860 = 7,
        X88K = 5,
        X960 = 19,
        Alpha = 41,
        AlteraNios2 = 113,
        Amdgpu = 224,
        Arc = 45,
        Arca = 109,
        ArcCompact = 93,
        ArcCompact2 = 195,
        Avr = 83,
        Avr32 = 185,
        Ba1 = 201,
        Ba2 = 202,
        Blackfin = 106,
        Bpf = 247,
        C166 = 116,
        Cdp = 215,
        Ce = 119,
        Cloudshield = 192,
        Coge = 216,
        Coldfire = 52,
        Cool = 217,
        Corea1St = 193,
        Corea2Nd = 194,
        Cr = 103,
        Cr16 = 177,
        Craynv2 = 172,
        Cris = 76,
        Crx = 114,
        Csky = 252,
        CsrKalimba = 219,
        Cuda = 190,
        CypressM8C = 161,
        D10V = 85,
        D30V = 86,
        Dsp24 = 136,
        Dspic30F = 118,
        Dxp = 112,
        Ecog1 = 168,
        Ecog16 = 176,
        Ecog2 = 134,
        Etpu = 178,
        Excess = 111,
        F2Mc16 = 104,
        Firepath = 78,
        Fr20 = 37,
        Fr30 = 84,
        Fx66 = 66,
        H8S = 48,
        H8300 = 46,
        H8300H = 47,
        H8500 = 49,
        Hexagon = 164,
        Huany = 81,
        Iamcu = 6,
        Ia64 = 50,
        Intel205 = 205,
        Intel206 = 206,
        Intel207 = 207,
        Intel208 = 208,
        Intel209 = 209,
        Ip2K = 101,
        Javelin = 77,
        K10M = 181,
        Km32 = 210,
        Kmx16 = 212,
        Kmx32 = 211,
        Kmx8 = 213,
        Kvarc = 214,
        L10M = 180,
        Lanai = 244,
        Latticemico32 = 138,
        M16C = 117,
        M32 = 1,
        M32C = 120,
        M32R = 88,
        Manik = 171,
        Max = 102,
        Maxq30 = 169,
        MchpPic = 204,
        McstElbrus = 175,
        Me16 = 59,
        Metag = 174,
        Microblaze = 189,
        MipsRs3Le = 10,
        MipsX = 51,
        Mma = 54,
        MmdspPlus = 160,
        Mmix = 80,
        Mn10200 = 90,
        Mn10300 = 89,
        Msp430 = 105,
        Ncpu = 56,
        Ndr1 = 57,
        Nds32 = 167,
        Norc = 218,
        Ns32K = 97,
        Open8 = 196,
        Openrisc = 92,
        Parisc = 15,
        Pcp = 55,
        Pdp10 = 64,
        Pdp11 = 65,
        Pdsp = 63,
        Pj = 91,
        Prism = 82,
        R32C = 162,
        Rce = 39,
        Rh32 = 38,
        Rl78 = 197,
        Rs08 = 132,
        Rx = 173,
        S370 = 9,
        Score7 = 135,
        Sep = 108,
        SeC17 = 139,
        SeC33 = 107,
        Sh = 42,
        Sharc = 133,
        Sle9X = 179,
        Snp1K = 99,
        Sparc = 2,
        Sparc32Plus = 18,
        Spu = 23,
        St100 = 60,
        St19 = 74,
        St200 = 100,
        St7 = 68,
        St9Plus = 67,
        Starcore = 58,
        Stm8 = 186,
        Stxp7X = 166,
        Svx = 73,
        Tile64 = 187,
        Tilegx = 191,
        Tilepro = 188,
        Tinyj = 61,
        TiC2000 = 141,
        TiC5500 = 142,
        TiC6000 = 140,
        TmmGpp = 96,
        Tpc = 98,
        Tricore = 44,
        Trimedia = 163,
        Tsk3000 = 131,
        Unicore = 110,
        V800 = 36,
        V850 = 87,
        Vax = 75,
        Ve = 251,
        Videocore = 95,
        Videocore3 = 137,
        Videocore5 = 198,
        Vpp500 = 17,
        Xcore = 203,
        Xgate = 115,
        Ximo16 = 170,
        Xtensa = 94,
        Zsp = 79,
    }
    default 0;
}

lossless_enum! {
    /// ELF OS ABI.
    pub enum ElfOsAbi: u8 {
        SystemV = 0,
        HpUx = 1,
        NetBsd = 2,
        Gnu = 3,
        Solaris = 6,
        Aix = 7,
        Irix = 8,
        FreeBsd = 9,
        OpenBsd = 12,
        Standalone = 255,
        AmdgpuHsa = 64,
        AmdgpuMesa3D = 66,
        AmdgpuPal = 65,
        Arm = 97,
        ArmFdpic = 65,
        Aros = 15,
        C6000Elfabi = 64,
        C6000Linux = 65,
        Cloudabi = 17,
        Cuda = 51,
        Fenixos = 16,
        FirstArch = 64,
        Freebsd = 9,
        Hpux = 1,
        Hurd = 4,
        LastArch = 255,
        Linux = 3,
        Modesto = 11,
        Netbsd = 2,
        None = 0,
        Nsk = 14,
        Openbsd = 12,
        Openvms = 13,
        Tru64 = 10,
        ;
        Other(u8),
    }
    canonical {
        SystemV = 0,
        HpUx = 1,
        NetBsd = 2,
        Gnu = 3,
        Solaris = 6,
        Aix = 7,
        Irix = 8,
        FreeBsd = 9,
        OpenBsd = 12,
        Standalone = 255,
        AmdgpuHsa = 64,
        AmdgpuMesa3D = 66,
        AmdgpuPal = 65,
        Arm = 97,
        Aros = 15,
        Cloudabi = 17,
        Cuda = 51,
        Fenixos = 16,
        Hurd = 4,
        Modesto = 11,
        Nsk = 14,
        Openvms = 13,
        Tru64 = 10,
    }
    default 0;
}

lossless_enum! {
    /// ELF object class.
    pub enum ElfClass: u8 {
        None = 0,
        Class32 = 1,
        Class64 = 2,
        X32 = 1,
        X64 = 2,
        ;
        Other(u8),
    }
    canonical {
        None = 0,
        Class32 = 1,
        Class64 = 2,
    }
    default 0;
}

lossless_enum! {
    /// ELF data encoding.
    pub enum ElfDataEncoding: u8 {
        None = 0,
        Little = 1,
        Big = 2,
        X2Lsb = 1,
        X2Msb = 2,
        ;
        Other(u8),
    }
    canonical {
        None = 0,
        Little = 1,
        Big = 2,
    }
    default 0;
}

lossless_enum! {
    /// ELF version value.
    pub enum ElfVersion: u8 {
        None = 0,
        Current = 1,
        ;
        Other(u8),
    }
    canonical {
        None = 0,
        Current = 1,
    }
    default 0;
}

lossless_enum! {
    /// ELF ABI version value.
    pub enum ElfAbiVersion: u8 {
        AmdgpuHsaV2 = 0,
        AmdgpuHsaV3 = 1,
        AmdgpuHsaV4 = 2,
        AmdgpuHsaV5 = 3,
        AmdgpuHsaV6 = 4,
        ;
        Other(u8),
    }
    canonical {
        AmdgpuHsaV2 = 0,
        AmdgpuHsaV3 = 1,
        AmdgpuHsaV4 = 2,
        AmdgpuHsaV5 = 3,
        AmdgpuHsaV6 = 4,
    }
    default 0;
}

lossless_enum! {
    /// ELF identification byte index.
    pub enum ElfIdentField: usize {
        Abiversion = 8,
        Class = 4,
        Data = 5,
        Mag0 = 0,
        Mag1 = 1,
        Mag2 = 2,
        Mag3 = 3,
        Nident = 16,
        Osabi = 7,
        Pad = 9,
        Version = 6,
        ;
        Other(usize),
    }
    canonical {
        Abiversion = 8,
        Class = 4,
        Data = 5,
        Mag0 = 0,
        Mag1 = 1,
        Mag2 = 2,
        Mag3 = 3,
        Nident = 16,
        Osabi = 7,
        Pad = 9,
        Version = 6,
    }
    default 0;
}

lossless_enum! {
    /// ELF program header type.
    pub enum ElfSegmentType: u32 {
        Null = 0,
        Load = 1,
        Dynamic = 2,
        Note = 4,
        Aarch64MemtagMte = 0x7000_0002,
        ArmArchext = 0x7000_0000,
        ArmExidx = 0x7000_0001,
        ArmUnwind = 0x7000_0001,
        GnuEhFrame = 0x6474_e550,
        GnuProperty = 0x6474_e553,
        GnuRelro = 0x6474_e552,
        GnuStack = 0x6474_e551,
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Interp = 3,
        Loos = 0x6000_0000,
        Loproc = 0x7000_0000,
        MipsAbiflags = 0x7000_0003,
        MipsOptions = 0x7000_0002,
        MipsReginfo = 0x7000_0000,
        MipsRtproc = 0x7000_0001,
        OpenbsdBootdata = 0x65a4_1be6,
        OpenbsdMutable = 0x65a3_dbe5,
        OpenbsdNobtcfi = 0x65a3_dbe8,
        OpenbsdRandomize = 0x65a3_dbe6,
        OpenbsdSyscalls = 0x65a3_dbe9,
        OpenbsdWxneeded = 0x65a3_dbe7,
        Phdr = 6,
        RiscvAttributes = 0x7000_0003,
        Shlib = 5,
        SunwEhFrame = 0x6474_e550,
        SunwUnwind = 0x6464_e550,
        Tls = 7,
        ;
        Other(u32),
    }
    canonical {
        Null = 0,
        Load = 1,
        Dynamic = 2,
        Note = 4,
        Aarch64MemtagMte = 0x7000_0002,
        ArmArchext = 0x7000_0000,
        ArmExidx = 0x7000_0001,
        GnuEhFrame = 0x6474_e550,
        GnuProperty = 0x6474_e553,
        GnuRelro = 0x6474_e552,
        GnuStack = 0x6474_e551,
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Interp = 3,
        Loos = 0x6000_0000,
        MipsAbiflags = 0x7000_0003,
        OpenbsdBootdata = 0x65a4_1be6,
        OpenbsdMutable = 0x65a3_dbe5,
        OpenbsdNobtcfi = 0x65a3_dbe8,
        OpenbsdRandomize = 0x65a3_dbe6,
        OpenbsdSyscalls = 0x65a3_dbe9,
        OpenbsdWxneeded = 0x65a3_dbe7,
        Phdr = 6,
        Shlib = 5,
        SunwUnwind = 0x6464_e550,
        Tls = 7,
    }
    default 0;
}

lossless_enum! {
    /// ELF section header type.
    pub enum ElfSectionType: u32 {
        Null = 0,
        Progbits = 1,
        Symtab = 2,
        Strtab = 3,
        Rela = 4,
        Dynamic = 6,
        Note = 7,
        Nobits = 8,
        Rel = 9,
        Dynsym = 11,
        Aarch64Attributes = 0x7000_0003,
        Aarch64AuthRelr = 0x7000_0004,
        Aarch64MemtagGlobalsDynamic = 0x7000_0008,
        Aarch64MemtagGlobalsStatic = 0x7000_0007,
        AndroidRel = 0x6000_0001,
        AndroidRela = 0x6000_0002,
        AndroidRelr = 0x6fff_ff00,
        ArmAttributes = 0x7000_0003,
        ArmDebugoverlay = 0x7000_0004,
        ArmExidx = 0x7000_0001,
        ArmOverlaysection = 0x7000_0005,
        ArmPreemptmap = 0x7000_0002,
        Crel = 0x4000_0014,
        CskyAttributes = 0x7000_0001,
        FiniArray = 15,
        GnuAttributes = 0x6fff_fff5,
        GnuHash = 0x6fff_fff6,
        Group = 17,
        Hash = 5,
        HexagonAttributes = 0x7000_0003,
        HexOrdered = 0x7000_0000,
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Hiuser = 0xffff_ffff,
        InitArray = 14,
        LlvmAddrsig = 0x6fff_4c03,
        LlvmBbAddrMap = 0x6fff_4c0a,
        LlvmCallGraphProfile = 0x6fff_4c09,
        LlvmJtSizes = 0x6fff_4c0d,
        LlvmLinkerOptions = 0x6fff_4c01,
        LlvmLto = 0x6fff_4c0c,
        LlvmOdrtab = 0x6fff_4c00,
        LlvmOffloading = 0x6fff_4c0b,
        LlvmPartEhdr = 0x6fff_4c06,
        LlvmPartPhdr = 0x6fff_4c07,
        LlvmSympart = 0x6fff_4c05,
        Loos = 0x6000_0000,
        Loproc = 0x7000_0000,
        Louser = 0x8000_0000,
        MipsAbiflags = 0x7000_002a,
        MipsDwarf = 0x7000_001e,
        MipsOptions = 0x7000_000d,
        MipsReginfo = 0x7000_0006,
        Msp430Attributes = 0x7000_0003,
        PreinitArray = 16,
        Relr = 19,
        RiscvAttributes = 0x7000_0003,
        Shlib = 10,
        SymtabShndx = 18,
        X8664Unwind = 0x7000_0001,
        ;
        Other(u32),
    }
    canonical {
        Null = 0,
        Progbits = 1,
        Symtab = 2,
        Strtab = 3,
        Rela = 4,
        Dynamic = 6,
        Note = 7,
        Nobits = 8,
        Rel = 9,
        Dynsym = 11,
        Aarch64Attributes = 0x7000_0003,
        Aarch64AuthRelr = 0x7000_0004,
        Aarch64MemtagGlobalsDynamic = 0x7000_0008,
        Aarch64MemtagGlobalsStatic = 0x7000_0007,
        AndroidRel = 0x6000_0001,
        AndroidRela = 0x6000_0002,
        AndroidRelr = 0x6fff_ff00,
        ArmExidx = 0x7000_0001,
        ArmOverlaysection = 0x7000_0005,
        ArmPreemptmap = 0x7000_0002,
        Crel = 0x4000_0014,
        FiniArray = 15,
        GnuAttributes = 0x6fff_fff5,
        GnuHash = 0x6fff_fff6,
        Group = 17,
        Hash = 5,
        HexOrdered = 0x7000_0000,
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Hiuser = 0xffff_ffff,
        InitArray = 14,
        LlvmAddrsig = 0x6fff_4c03,
        LlvmBbAddrMap = 0x6fff_4c0a,
        LlvmCallGraphProfile = 0x6fff_4c09,
        LlvmJtSizes = 0x6fff_4c0d,
        LlvmLinkerOptions = 0x6fff_4c01,
        LlvmLto = 0x6fff_4c0c,
        LlvmOdrtab = 0x6fff_4c00,
        LlvmOffloading = 0x6fff_4c0b,
        LlvmPartEhdr = 0x6fff_4c06,
        LlvmPartPhdr = 0x6fff_4c07,
        LlvmSympart = 0x6fff_4c05,
        Loos = 0x6000_0000,
        Louser = 0x8000_0000,
        MipsAbiflags = 0x7000_002a,
        MipsDwarf = 0x7000_001e,
        MipsOptions = 0x7000_000d,
        MipsReginfo = 0x7000_0006,
        PreinitArray = 16,
        Relr = 19,
        Shlib = 10,
        SymtabShndx = 18,
    }
    default 0;
}

lossless_enum! {
    /// ELF special section index.
    pub enum ElfSectionIndex: u32 {
        Abs = 0xfff1,
        AmdgpuLds = 0xff00,
        Common = 0xfff2,
        HexagonScommon = 0xff00,
        HexagonScommon1 = 0xff01,
        HexagonScommon2 = 0xff02,
        HexagonScommon4 = 0xff03,
        HexagonScommon8 = 0xff04,
        Hios = 0xff3f,
        Hiproc = 0xff1f,
        Hireserve = 0xffff,
        Loos = 0xff20,
        Loproc = 0xff00,
        Loreserve = 0xff00,
        MipsAcommon = 0xff00,
        MipsData = 0xff02,
        MipsScommon = 0xff03,
        MipsSundefined = 0xff04,
        MipsText = 0xff01,
        Undef = 0,
        Xindex = 0xffff,
        ;
        Other(u32),
    }
    canonical {
        Abs = 0xfff1,
        AmdgpuLds = 0xff00,
        Common = 0xfff2,
        HexagonScommon1 = 0xff01,
        HexagonScommon2 = 0xff02,
        HexagonScommon4 = 0xff03,
        HexagonScommon8 = 0xff04,
        Hios = 0xff3f,
        Hiproc = 0xff1f,
        Hireserve = 0xffff,
        Loos = 0xff20,
        Undef = 0,
    }
    default 0;
}

lossless_enum! {
    /// ELF symbol binding.
    pub enum ElfSymbolBind: u8 {
        Local = 0,
        Global = 1,
        Weak = 2,
        GnuUnique = 10,
        Hios = 12,
        Hiproc = 15,
        Loos = 10,
        Loproc = 13,
        ;
        Other(u8),
    }
    canonical {
        Local = 0,
        Global = 1,
        Weak = 2,
        GnuUnique = 10,
        Hios = 12,
        Hiproc = 15,
        Loproc = 13,
    }
    default 0;
}

lossless_enum! {
    /// ELF symbol type.
    pub enum ElfSymbolType: u8 {
        NoType = 0,
        Object = 1,
        Function = 2,
        Section = 3,
        File = 4,
        Common = 5,
        Tls = 6,
        AmdgpuHsaKernel = 10,
        Func = 2,
        GnuIfunc = 10,
        Hios = 12,
        Hiproc = 15,
        Loos = 10,
        Loproc = 13,
        Notype = 0,
        ;
        Other(u8),
    }
    canonical {
        NoType = 0,
        Object = 1,
        Function = 2,
        Section = 3,
        File = 4,
        Common = 5,
        Tls = 6,
        AmdgpuHsaKernel = 10,
        Hios = 12,
        Hiproc = 15,
        Loproc = 13,
    }
    default 0;
}

lossless_enum! {
    /// ELF symbol visibility.
    pub enum ElfSymbolVisibility: u8 {
        Default = 0,
        Internal = 1,
        Hidden = 2,
        Protected = 3,
        ;
        Other(u8),
    }
    canonical {
        Default = 0,
        Internal = 1,
        Hidden = 2,
        Protected = 3,
    }
    default 0;
}

lossless_enum! {
    /// ELF relocation type. Values are machine-specific.
    pub enum ElfRelocationType: u32 {
        None = 0,
        R38616 = 20,
        R38632 = 1,
        R38632Plt = 11,
        R3868 = 22,
        R386Copy = 5,
        R386GlobDat = 6,
        R386Got32 = 3,
        R386Got32X = 43,
        R386Gotoff = 9,
        R386Gotpc = 10,
        R386Irelative = 42,
        R386JumpSlot = 7,
        R386None = 0,
        R386Pc16 = 21,
        R386Pc32 = 2,
        R386Pc8 = 23,
        R386Plt32 = 4,
        R386Relative = 8,
        R386TlsDesc = 41,
        R386TlsDescCall = 40,
        R386TlsDtpmod32 = 35,
        R386TlsDtpoff32 = 36,
        R386TlsGd = 18,
        R386TlsGd32 = 24,
        R386TlsGdCall = 26,
        R386TlsGdPop = 27,
        R386TlsGdPush = 25,
        R386TlsGotdesc = 39,
        R386TlsGotie = 16,
        R386TlsIe = 15,
        R386TlsIe32 = 33,
        R386TlsLdm = 19,
        R386TlsLdm32 = 28,
        R386TlsLdmCall = 30,
        R386TlsLdmPop = 31,
        R386TlsLdmPush = 29,
        R386TlsLdo32 = 32,
        R386TlsLe = 17,
        R386TlsLe32 = 34,
        R386TlsTpoff = 14,
        R386TlsTpoff32 = 37,
        R39012 = 2,
        R39016 = 3,
        R39020 = 57,
        R39032 = 4,
        R39064 = 22,
        R3908 = 1,
        R390Copy = 9,
        R390GlobDat = 10,
        R390Got12 = 6,
        R390Got16 = 15,
        R390Got20 = 58,
        R390Got32 = 7,
        R390Got64 = 24,
        R390Gotent = 26,
        R390Gotoff = 13,
        R390Gotoff16 = 27,
        R390Gotoff64 = 28,
        R390Gotpc = 14,
        R390Gotpcdbl = 21,
        R390Gotplt12 = 29,
        R390Gotplt16 = 30,
        R390Gotplt20 = 59,
        R390Gotplt32 = 31,
        R390Gotplt64 = 32,
        R390Gotpltent = 33,
        R390Irelative = 61,
        R390JmpSlot = 11,
        R390None = 0,
        R390Pc12Dbl = 62,
        R390Pc16 = 16,
        R390Pc16Dbl = 17,
        R390Pc24Dbl = 64,
        R390Pc32 = 5,
        R390Pc32Dbl = 19,
        R390Pc64 = 23,
        R390Plt12Dbl = 63,
        R390Plt16Dbl = 18,
        R390Plt24Dbl = 65,
        R390Plt32 = 8,
        R390Plt32Dbl = 20,
        R390Plt64 = 25,
        R390Pltoff16 = 34,
        R390Pltoff32 = 35,
        R390Pltoff64 = 36,
        R390Relative = 12,
        R390TlsDtpmod = 54,
        R390TlsDtpoff = 55,
        R390TlsGd32 = 40,
        R390TlsGd64 = 41,
        R390TlsGdcall = 38,
        R390TlsGotie12 = 42,
        R390TlsGotie20 = 60,
        R390TlsGotie32 = 43,
        R390TlsGotie64 = 44,
        R390TlsIe32 = 47,
        R390TlsIe64 = 48,
        R390TlsIeent = 49,
        R390TlsLdcall = 39,
        R390TlsLdm32 = 45,
        R390TlsLdm64 = 46,
        R390TlsLdo32 = 52,
        R390TlsLdo64 = 53,
        R390TlsLe32 = 50,
        R390TlsLe64 = 51,
        R390TlsLoad = 37,
        R390TlsTpoff = 56,
        R68K16 = 2,
        R68K32 = 1,
        R68K8 = 3,
        R68KCopy = 19,
        R68KGlobDat = 20,
        R68KGnuVtentry = 24,
        R68KGnuVtinherit = 23,
        R68KGotoff16 = 11,
        R68KGotoff32 = 10,
        R68KGotoff8 = 12,
        R68KGotpcrel16 = 8,
        R68KGotpcrel32 = 7,
        R68KGotpcrel8 = 9,
        R68KJmpSlot = 21,
        R68KNone = 0,
        R68KPc16 = 5,
        R68KPc32 = 4,
        R68KPc8 = 6,
        R68KPlt16 = 14,
        R68KPlt32 = 13,
        R68KPlt8 = 15,
        R68KPltoff16 = 17,
        R68KPltoff32 = 16,
        R68KPltoff8 = 18,
        R68KRelative = 22,
        R68KTlsDtpmod32 = 40,
        R68KTlsDtprel32 = 41,
        R68KTlsGd16 = 26,
        R68KTlsGd32 = 25,
        R68KTlsGd8 = 27,
        R68KTlsIe16 = 35,
        R68KTlsIe32 = 34,
        R68KTlsIe8 = 36,
        R68KTlsLdm16 = 29,
        R68KTlsLdm32 = 28,
        R68KTlsLdm8 = 30,
        R68KTlsLdo16 = 32,
        R68KTlsLdo32 = 31,
        R68KTlsLdo8 = 33,
        R68KTlsLe16 = 38,
        R68KTlsLe32 = 37,
        R68KTlsLe8 = 39,
        R68KTlsTprel32 = 42,
        RAarch64Abs16 = 259,
        RAarch64Abs32 = 258,
        RAarch64Abs64 = 257,
        RAarch64AddAbsLo12Nc = 277,
        RAarch64AdrGotPage = 311,
        RAarch64AdrPrelLo21 = 274,
        RAarch64AdrPrelPgHi21 = 275,
        RAarch64AdrPrelPgHi21Nc = 276,
        RAarch64AuthAbs64 = 580,
        RAarch64AuthAdrGotPage = 590,
        RAarch64AuthGlobDat = 1042,
        RAarch64AuthGotAddLo12Nc = 593,
        RAarch64AuthGotAdrPrelLo21 = 594,
        RAarch64AuthGotLdPrel19 = 588,
        RAarch64AuthIrelative = 1044,
        RAarch64AuthLd64GotoffLo15 = 589,
        RAarch64AuthLd64GotpageLo15 = 592,
        RAarch64AuthLd64GotLo12Nc = 591,
        RAarch64AuthMovwGotoffG0 = 581,
        RAarch64AuthMovwGotoffG0Nc = 582,
        RAarch64AuthMovwGotoffG1 = 583,
        RAarch64AuthMovwGotoffG1Nc = 584,
        RAarch64AuthMovwGotoffG2 = 585,
        RAarch64AuthMovwGotoffG2Nc = 586,
        RAarch64AuthMovwGotoffG3 = 587,
        RAarch64AuthRelative = 1041,
        RAarch64AuthTlsdesc = 1043,
        RAarch64AuthTlsdescAddLo12 = 597,
        RAarch64AuthTlsdescAdrPage21 = 595,
        RAarch64AuthTlsdescLd64Lo12 = 596,
        RAarch64Call26 = 283,
        RAarch64Condbr19 = 280,
        RAarch64Copy = 1024,
        RAarch64GlobDat = 1025,
        RAarch64Gotpcrel32 = 315,
        RAarch64Gotrel32 = 308,
        RAarch64Gotrel64 = 307,
        RAarch64GotLdPrel19 = 309,
        RAarch64Irelative = 1032,
        RAarch64Jump26 = 282,
        RAarch64JumpSlot = 1026,
        RAarch64Ld64GotoffLo15 = 310,
        RAarch64Ld64GotpageLo15 = 313,
        RAarch64Ld64GotLo12Nc = 312,
        RAarch64Ldst128AbsLo12Nc = 299,
        RAarch64Ldst16AbsLo12Nc = 284,
        RAarch64Ldst32AbsLo12Nc = 285,
        RAarch64Ldst64AbsLo12Nc = 286,
        RAarch64Ldst8AbsLo12Nc = 278,
        RAarch64LdPrelLo19 = 273,
        RAarch64MovwGotoffG0 = 300,
        RAarch64MovwGotoffG0Nc = 301,
        RAarch64MovwGotoffG1 = 302,
        RAarch64MovwGotoffG1Nc = 303,
        RAarch64MovwGotoffG2 = 304,
        RAarch64MovwGotoffG2Nc = 305,
        RAarch64MovwGotoffG3 = 306,
        RAarch64MovwPrelG0 = 287,
        RAarch64MovwPrelG0Nc = 288,
        RAarch64MovwPrelG1 = 289,
        RAarch64MovwPrelG1Nc = 290,
        RAarch64MovwPrelG2 = 291,
        RAarch64MovwPrelG2Nc = 292,
        RAarch64MovwPrelG3 = 293,
        RAarch64MovwSabsG0 = 270,
        RAarch64MovwSabsG1 = 271,
        RAarch64MovwSabsG2 = 272,
        RAarch64MovwUabsG0 = 263,
        RAarch64MovwUabsG0Nc = 264,
        RAarch64MovwUabsG1 = 265,
        RAarch64MovwUabsG1Nc = 266,
        RAarch64MovwUabsG2 = 267,
        RAarch64MovwUabsG2Nc = 268,
        RAarch64MovwUabsG3 = 269,
        RAarch64None = 0,
        RAarch64P32Abs16 = 2,
        RAarch64P32Abs32 = 1,
        RAarch64P32AddAbsLo12Nc = 12,
        RAarch64P32AdrGotPage = 26,
        RAarch64P32AdrPrelLo21 = 10,
        RAarch64P32AdrPrelPgHi21 = 11,
        RAarch64P32Call26 = 21,
        RAarch64P32Condbr19 = 19,
        RAarch64P32Copy = 180,
        RAarch64P32GlobDat = 181,
        RAarch64P32GotLdPrel19 = 25,
        RAarch64P32Irelative = 188,
        RAarch64P32Jump26 = 20,
        RAarch64P32JumpSlot = 182,
        RAarch64P32Ld32GotpageLo14 = 28,
        RAarch64P32Ld32GotLo12Nc = 27,
        RAarch64P32Ldst128AbsLo12Nc = 17,
        RAarch64P32Ldst16AbsLo12Nc = 14,
        RAarch64P32Ldst32AbsLo12Nc = 15,
        RAarch64P32Ldst64AbsLo12Nc = 16,
        RAarch64P32Ldst8AbsLo12Nc = 13,
        RAarch64P32LdPrelLo19 = 9,
        RAarch64P32MovwPrelG0 = 22,
        RAarch64P32MovwPrelG0Nc = 23,
        RAarch64P32MovwPrelG1 = 24,
        RAarch64P32MovwSabsG0 = 8,
        RAarch64P32MovwUabsG0 = 5,
        RAarch64P32MovwUabsG0Nc = 6,
        RAarch64P32MovwUabsG1 = 7,
        RAarch64P32None = 0,
        RAarch64P32Plt32 = 29,
        RAarch64P32Prel16 = 4,
        RAarch64P32Prel32 = 3,
        RAarch64P32Relative = 183,
        RAarch64P32Tlsdesc = 187,
        RAarch64P32TlsdescAddLo12 = 126,
        RAarch64P32TlsdescAdrPage21 = 124,
        RAarch64P32TlsdescAdrPrel21 = 123,
        RAarch64P32TlsdescCall = 127,
        RAarch64P32TlsdescLd32Lo12 = 125,
        RAarch64P32TlsdescLdPrel19 = 122,
        RAarch64P32TlsgdAddLo12Nc = 82,
        RAarch64P32TlsgdAdrPage21 = 81,
        RAarch64P32TlsgdAdrPrel21 = 80,
        RAarch64P32TlsieAdrGottprelPage21 = 103,
        RAarch64P32TlsieLd32GottprelLo12Nc = 104,
        RAarch64P32TlsieLdGottprelPrel19 = 105,
        RAarch64P32TlsldAddDtprelHi12 = 90,
        RAarch64P32TlsldAddDtprelLo12 = 91,
        RAarch64P32TlsldAddDtprelLo12Nc = 92,
        RAarch64P32TlsldAddLo12Nc = 85,
        RAarch64P32TlsldAdrPage21 = 84,
        RAarch64P32TlsldAdrPrel21 = 83,
        RAarch64P32TlsldLdst128DtprelLo12 = 101,
        RAarch64P32TlsldLdst128DtprelLo12Nc = 102,
        RAarch64P32TlsldLdst16DtprelLo12 = 95,
        RAarch64P32TlsldLdst16DtprelLo12Nc = 96,
        RAarch64P32TlsldLdst32DtprelLo12 = 97,
        RAarch64P32TlsldLdst32DtprelLo12Nc = 98,
        RAarch64P32TlsldLdst64DtprelLo12 = 99,
        RAarch64P32TlsldLdst64DtprelLo12Nc = 100,
        RAarch64P32TlsldLdst8DtprelLo12 = 93,
        RAarch64P32TlsldLdst8DtprelLo12Nc = 94,
        RAarch64P32TlsldLdPrel19 = 86,
        RAarch64P32TlsldMovwDtprelG0 = 88,
        RAarch64P32TlsldMovwDtprelG0Nc = 89,
        RAarch64P32TlsldMovwDtprelG1 = 87,
        RAarch64P32TlsleAddTprelHi12 = 109,
        RAarch64P32TlsleAddTprelLo12 = 110,
        RAarch64P32TlsleAddTprelLo12Nc = 111,
        RAarch64P32TlsleLdst128TprelLo12 = 120,
        RAarch64P32TlsleLdst128TprelLo12Nc = 121,
        RAarch64P32TlsleLdst16TprelLo12 = 114,
        RAarch64P32TlsleLdst16TprelLo12Nc = 115,
        RAarch64P32TlsleLdst32TprelLo12 = 116,
        RAarch64P32TlsleLdst32TprelLo12Nc = 117,
        RAarch64P32TlsleLdst64TprelLo12 = 118,
        RAarch64P32TlsleLdst64TprelLo12Nc = 119,
        RAarch64P32TlsleLdst8TprelLo12 = 112,
        RAarch64P32TlsleLdst8TprelLo12Nc = 113,
        RAarch64P32TlsleMovwTprelG0 = 107,
        RAarch64P32TlsleMovwTprelG0Nc = 108,
        RAarch64P32TlsleMovwTprelG1 = 106,
        RAarch64P32TlsDtpmod = 185,
        RAarch64P32TlsDtprel = 184,
        RAarch64P32TlsTprel = 186,
        RAarch64P32Tstbr14 = 18,
        RAarch64Plt32 = 314,
        RAarch64Prel16 = 262,
        RAarch64Prel32 = 261,
        RAarch64Prel64 = 260,
        RAarch64Relative = 1027,
        RAarch64Tlsdesc = 1031,
        RAarch64TlsdescAdd = 568,
        RAarch64TlsdescAddLo12 = 564,
        RAarch64TlsdescAdrPage21 = 562,
        RAarch64TlsdescAdrPrel21 = 561,
        RAarch64TlsdescCall = 569,
        RAarch64TlsdescLd64Lo12 = 563,
        RAarch64TlsdescLdr = 567,
        RAarch64TlsdescLdPrel19 = 560,
        RAarch64TlsdescOffG0Nc = 566,
        RAarch64TlsdescOffG1 = 565,
        RAarch64TlsgdAddLo12Nc = 514,
        RAarch64TlsgdAdrPage21 = 513,
        RAarch64TlsgdAdrPrel21 = 512,
        RAarch64TlsgdMovwG0Nc = 516,
        RAarch64TlsgdMovwG1 = 515,
        RAarch64TlsieAdrGottprelPage21 = 541,
        RAarch64TlsieLd64GottprelLo12Nc = 542,
        RAarch64TlsieLdGottprelPrel19 = 543,
        RAarch64TlsieMovwGottprelG0Nc = 540,
        RAarch64TlsieMovwGottprelG1 = 539,
        RAarch64TlsldAddDtprelHi12 = 528,
        RAarch64TlsldAddDtprelLo12 = 529,
        RAarch64TlsldAddDtprelLo12Nc = 530,
        RAarch64TlsldAddLo12Nc = 519,
        RAarch64TlsldAdrPage21 = 518,
        RAarch64TlsldAdrPrel21 = 517,
        RAarch64TlsldLdst128DtprelLo12 = 572,
        RAarch64TlsldLdst128DtprelLo12Nc = 573,
        RAarch64TlsldLdst16DtprelLo12 = 533,
        RAarch64TlsldLdst16DtprelLo12Nc = 534,
        RAarch64TlsldLdst32DtprelLo12 = 535,
        RAarch64TlsldLdst32DtprelLo12Nc = 536,
        RAarch64TlsldLdst64DtprelLo12 = 537,
        RAarch64TlsldLdst64DtprelLo12Nc = 538,
        RAarch64TlsldLdst8DtprelLo12 = 531,
        RAarch64TlsldLdst8DtprelLo12Nc = 532,
        RAarch64TlsldLdPrel19 = 522,
        RAarch64TlsldMovwDtprelG0 = 526,
        RAarch64TlsldMovwDtprelG0Nc = 527,
        RAarch64TlsldMovwDtprelG1 = 524,
        RAarch64TlsldMovwDtprelG1Nc = 525,
        RAarch64TlsldMovwDtprelG2 = 523,
        RAarch64TlsldMovwG0Nc = 521,
        RAarch64TlsldMovwG1 = 520,
        RAarch64TlsleAddTprelHi12 = 549,
        RAarch64TlsleAddTprelLo12 = 550,
        RAarch64TlsleAddTprelLo12Nc = 551,
        RAarch64TlsleLdst128TprelLo12 = 570,
        RAarch64TlsleLdst128TprelLo12Nc = 571,
        RAarch64TlsleLdst16TprelLo12 = 554,
        RAarch64TlsleLdst16TprelLo12Nc = 555,
        RAarch64TlsleLdst32TprelLo12 = 556,
        RAarch64TlsleLdst32TprelLo12Nc = 557,
        RAarch64TlsleLdst64TprelLo12 = 558,
        RAarch64TlsleLdst64TprelLo12Nc = 559,
        RAarch64TlsleLdst8TprelLo12 = 552,
        RAarch64TlsleLdst8TprelLo12Nc = 553,
        RAarch64TlsleMovwTprelG0 = 547,
        RAarch64TlsleMovwTprelG0Nc = 548,
        RAarch64TlsleMovwTprelG1 = 545,
        RAarch64TlsleMovwTprelG1Nc = 546,
        RAarch64TlsleMovwTprelG2 = 544,
        RAarch64TlsDtpmod64 = 1028,
        RAarch64TlsDtprel64 = 1029,
        RAarch64TlsTprel64 = 1030,
        RAarch64Tstbr14 = 279,
        RAcSectoffS9 = 38,
        RAcSectoffS91 = 39,
        RAcSectoffS92 = 40,
        RAcSectoffU8 = 35,
        RAcSectoffU81 = 36,
        RAcSectoffU82 = 37,
        RAmdgpuAbs32 = 6,
        RAmdgpuAbs32Hi = 2,
        RAmdgpuAbs32Lo = 1,
        RAmdgpuAbs64 = 3,
        RAmdgpuGotpcrel = 7,
        RAmdgpuGotpcrel32Hi = 9,
        RAmdgpuGotpcrel32Lo = 8,
        RAmdgpuNone = 0,
        RAmdgpuRel16 = 14,
        RAmdgpuRel32 = 4,
        RAmdgpuRel32Hi = 11,
        RAmdgpuRel32Lo = 10,
        RAmdgpuRel64 = 5,
        RAmdgpuRelative64 = 13,
        RArc16 = 2,
        RArc24 = 3,
        RArc32 = 4,
        RArc32Me = 27,
        RArc32MeS = 105,
        RArc32Pcrel = 49,
        RArc8 = 1,
        RArcCopy = 53,
        RArcGlobDat = 54,
        RArcGot32 = 59,
        RArcGotoff = 57,
        RArcGotpc = 58,
        RArcGotpc32 = 51,
        RArcJliSectoff = 63,
        RArcJmpSlot = 55,
        RArcN16 = 9,
        RArcN24 = 10,
        RArcN32 = 11,
        RArcN32Me = 28,
        RArcN8 = 8,
        RArcNone = 0,
        RArcNpsCmem16 = 78,
        RArcPc32 = 50,
        RArcPlt32 = 52,
        RArcRelative = 56,
        RArcS13Pcrel = 25,
        RArcS21HPcrel = 14,
        RArcS21HPcrelPlt = 77,
        RArcS21WPcrel = 15,
        RArcS21WPcrelPlt = 60,
        RArcS25HPcrel = 16,
        RArcS25HPcrelPlt = 61,
        RArcS25WPcrel = 17,
        RArcS25WPcrelPlt = 76,
        RArcSda = 12,
        RArcSda16Ld = 22,
        RArcSda16Ld1 = 23,
        RArcSda16Ld2 = 24,
        RArcSda16St2 = 48,
        RArcSda32 = 18,
        RArcSda32Me = 30,
        RArcSda12 = 45,
        RArcSdaLdst = 19,
        RArcSdaLdst1 = 20,
        RArcSdaLdst2 = 21,
        RArcSectoff = 13,
        RArcSectoff1 = 43,
        RArcSectoff2 = 44,
        RArcSectoffMe = 29,
        RArcSectoffMe1 = 41,
        RArcSectoffMe2 = 42,
        RArcTlsDtpmod = 66,
        RArcTlsDtpoff = 67,
        RArcTlsDtpoffS9 = 73,
        RArcTlsGdCall = 71,
        RArcTlsGdGot = 69,
        RArcTlsGdLd = 70,
        RArcTlsIeGot = 72,
        RArcTlsLe32 = 75,
        RArcTlsLeS9 = 74,
        RArcTlsTpoff = 68,
        RArcW = 26,
        RArcWMe = 31,
        RArmAbs12 = 6,
        RArmAbs16 = 5,
        RArmAbs32 = 2,
        RArmAbs32Noi = 55,
        RArmAbs8 = 8,
        RArmAluPcrel158 = 33,
        RArmAluPcrel2315 = 34,
        RArmAluPcrel70 = 32,
        RArmAluPcG0 = 58,
        RArmAluPcG0Nc = 57,
        RArmAluPcG1 = 60,
        RArmAluPcG1Nc = 59,
        RArmAluPcG2 = 61,
        RArmAluSbrel1912Nc = 36,
        RArmAluSbrel2720Ck = 37,
        RArmAluSbG0 = 71,
        RArmAluSbG0Nc = 70,
        RArmAluSbG1 = 73,
        RArmAluSbG1Nc = 72,
        RArmAluSbG2 = 74,
        RArmBaseAbs = 31,
        RArmBasePrel = 25,
        RArmBrelAdj = 12,
        RArmCall = 28,
        RArmCopy = 20,
        RArmFuncdesc = 163,
        RArmFuncdescValue = 164,
        RArmGlobDat = 21,
        RArmGnuVtentry = 100,
        RArmGnuVtinherit = 101,
        RArmGotfuncdesc = 161,
        RArmGotoff12 = 98,
        RArmGotoff32 = 24,
        RArmGotofffuncdesc = 162,
        RArmGotrelax = 99,
        RArmGotAbs = 95,
        RArmGotBrel = 26,
        RArmGotBrel12 = 97,
        RArmGotPrel = 96,
        RArmIrelative = 160,
        RArmJump24 = 29,
        RArmJumpSlot = 22,
        RArmLdcPcG0 = 67,
        RArmLdcPcG1 = 68,
        RArmLdcPcG2 = 69,
        RArmLdcSbG0 = 81,
        RArmLdcSbG1 = 82,
        RArmLdcSbG2 = 83,
        RArmLdrsPcG0 = 64,
        RArmLdrsPcG1 = 65,
        RArmLdrsPcG2 = 66,
        RArmLdrsSbG0 = 78,
        RArmLdrsSbG1 = 79,
        RArmLdrsSbG2 = 80,
        RArmLdrPcG0 = 4,
        RArmLdrPcG1 = 62,
        RArmLdrPcG2 = 63,
        RArmLdrSbrel110Nc = 35,
        RArmLdrSbG0 = 75,
        RArmLdrSbG1 = 76,
        RArmLdrSbG2 = 77,
        RArmMeToo = 128,
        RArmMovtAbs = 44,
        RArmMovtBrel = 85,
        RArmMovtPrel = 46,
        RArmMovwAbsNc = 43,
        RArmMovwBrel = 86,
        RArmMovwBrelNc = 84,
        RArmMovwPrelNc = 45,
        RArmNone = 0,
        RArmPc24 = 1,
        RArmPlt32 = 27,
        RArmPlt32Abs = 94,
        RArmPrel31 = 42,
        RArmPrivate0 = 112,
        RArmPrivate1 = 113,
        RArmPrivate10 = 122,
        RArmPrivate11 = 123,
        RArmPrivate12 = 124,
        RArmPrivate13 = 125,
        RArmPrivate14 = 126,
        RArmPrivate15 = 127,
        RArmPrivate2 = 114,
        RArmPrivate3 = 115,
        RArmPrivate4 = 116,
        RArmPrivate5 = 117,
        RArmPrivate6 = 118,
        RArmPrivate7 = 119,
        RArmPrivate8 = 120,
        RArmPrivate9 = 121,
        RArmRel32 = 3,
        RArmRel32Noi = 56,
        RArmRelative = 23,
        RArmSbrel31 = 39,
        RArmSbrel32 = 9,
        RArmTarget1 = 38,
        RArmTarget2 = 41,
        RArmThmAbs5 = 7,
        RArmThmAluAbsG0Nc = 132,
        RArmThmAluAbsG1Nc = 133,
        RArmThmAluAbsG2Nc = 134,
        RArmThmAluAbsG3 = 135,
        RArmThmAluPrel110 = 53,
        RArmThmBf12 = 137,
        RArmThmBf16 = 136,
        RArmThmBf18 = 138,
        RArmThmCall = 10,
        RArmThmJump11 = 102,
        RArmThmJump19 = 51,
        RArmThmJump24 = 30,
        RArmThmJump6 = 52,
        RArmThmJump8 = 103,
        RArmThmMovtAbs = 48,
        RArmThmMovtBrel = 88,
        RArmThmMovtPrel = 50,
        RArmThmMovwAbsNc = 47,
        RArmThmMovwBrel = 89,
        RArmThmMovwBrelNc = 87,
        RArmThmMovwPrelNc = 49,
        RArmThmPc12 = 54,
        RArmThmPc8 = 11,
        RArmThmSwi8 = 14,
        RArmThmTlsCall = 93,
        RArmThmTlsDescseq16 = 129,
        RArmThmTlsDescseq32 = 130,
        RArmThmXpc22 = 16,
        RArmTlsCall = 91,
        RArmTlsDesc = 13,
        RArmTlsDescseq = 92,
        RArmTlsDtpmod32 = 17,
        RArmTlsDtpoff32 = 18,
        RArmTlsGd32 = 104,
        RArmTlsGd32Fdpic = 165,
        RArmTlsGotdesc = 90,
        RArmTlsIe12Gp = 111,
        RArmTlsIe32 = 107,
        RArmTlsIe32Fdpic = 167,
        RArmTlsLdm32 = 105,
        RArmTlsLdm32Fdpic = 166,
        RArmTlsLdo12 = 109,
        RArmTlsLdo32 = 106,
        RArmTlsLe12 = 110,
        RArmTlsLe32 = 108,
        RArmTlsTpoff32 = 19,
        RArmV4Bx = 40,
        RArmXpc25 = 15,
        RAvr13Pcrel = 3,
        RAvr16 = 4,
        RAvr16Pm = 5,
        RAvr32 = 1,
        RAvr6 = 20,
        RAvr6Adiw = 21,
        RAvr7Pcrel = 2,
        RAvr8 = 26,
        RAvr8Hi8 = 28,
        RAvr8Hlo8 = 29,
        RAvr8Lo8 = 27,
        RAvrCall = 18,
        RAvrDiff16 = 31,
        RAvrDiff32 = 32,
        RAvrDiff8 = 30,
        RAvrHh8Ldi = 8,
        RAvrHh8LdiNeg = 11,
        RAvrHh8LdiPm = 14,
        RAvrHh8LdiPmNeg = 17,
        RAvrHi8Ldi = 7,
        RAvrHi8LdiGs = 25,
        RAvrHi8LdiNeg = 10,
        RAvrHi8LdiPm = 13,
        RAvrHi8LdiPmNeg = 16,
        RAvrLdi = 19,
        RAvrLdsSts16 = 33,
        RAvrLo8Ldi = 6,
        RAvrLo8LdiGs = 24,
        RAvrLo8LdiNeg = 9,
        RAvrLo8LdiPm = 12,
        RAvrLo8LdiPmNeg = 15,
        RAvrMs8Ldi = 22,
        RAvrMs8LdiNeg = 23,
        RAvrNone = 0,
        RAvrPort5 = 35,
        RAvrPort6 = 34,
        RBpf6432 = 10,
        RBpf6464 = 1,
        RBpf64Abs32 = 3,
        RBpf64Abs64 = 2,
        RBpf64Nodyld32 = 4,
        RBpfNone = 0,
        RCkcoreAddr32 = 1,
        RCkcoreAddrgot = 17,
        RCkcoreAddrgotHi16 = 36,
        RCkcoreAddrgotLo16 = 37,
        RCkcoreAddrplt = 18,
        RCkcoreAddrpltHi16 = 38,
        RCkcoreAddrpltLo16 = 39,
        RCkcoreAddrHi16 = 24,
        RCkcoreAddrLo16 = 25,
        RCkcoreCallgraph = 61,
        RCkcoreCopy = 10,
        RCkcoreDoffsetImm18 = 44,
        RCkcoreDoffsetImm182 = 45,
        RCkcoreDoffsetImm184 = 46,
        RCkcoreDoffsetLo16 = 42,
        RCkcoreGlobDat = 11,
        RCkcoreGnuVtentry = 8,
        RCkcoreGnuVtinherit = 7,
        RCkcoreGot12 = 30,
        RCkcoreGot32 = 15,
        RCkcoreGotoff = 13,
        RCkcoreGotoffHi16 = 28,
        RCkcoreGotoffImm18 = 47,
        RCkcoreGotoffLo16 = 29,
        RCkcoreGotpc = 14,
        RCkcoreGotpcHi16 = 26,
        RCkcoreGotpcLo16 = 27,
        RCkcoreGotHi16 = 31,
        RCkcoreGotImm184 = 48,
        RCkcoreGotLo16 = 32,
        RCkcoreIrelative = 62,
        RCkcoreJumpSlot = 12,
        RCkcoreNojsri = 60,
        RCkcoreNone = 0,
        RCkcorePcrel32 = 5,
        RCkcorePcrelBloopImm124 = 64,
        RCkcorePcrelBloopImm44 = 63,
        RCkcorePcrelFlrwImm84 = 59,
        RCkcorePcrelImm102 = 22,
        RCkcorePcrelImm104 = 23,
        RCkcorePcrelImm112 = 3,
        RCkcorePcrelImm162 = 20,
        RCkcorePcrelImm164 = 21,
        RCkcorePcrelImm182 = 43,
        RCkcorePcrelImm262 = 19,
        RCkcorePcrelImm42 = 4,
        RCkcorePcrelImm74 = 50,
        RCkcorePcrelImm84 = 2,
        RCkcorePcrelJsrImm112 = 6,
        RCkcorePcrelJsrImm262 = 40,
        RCkcorePcrelVlrwImm121 = 65,
        RCkcorePcrelVlrwImm122 = 66,
        RCkcorePcrelVlrwImm124 = 67,
        RCkcorePcrelVlrwImm128 = 68,
        RCkcorePlt12 = 33,
        RCkcorePlt32 = 16,
        RCkcorePltHi16 = 34,
        RCkcorePltImm184 = 49,
        RCkcorePltLo16 = 35,
        RCkcoreRelative = 9,
        RCkcoreTlsDtpmod32 = 56,
        RCkcoreTlsDtpoff32 = 57,
        RCkcoreTlsGd32 = 53,
        RCkcoreTlsIe32 = 52,
        RCkcoreTlsLdm32 = 54,
        RCkcoreTlsLdo32 = 55,
        RCkcoreTlsLe32 = 51,
        RCkcoreTlsTpoff32 = 58,
        RCkcoreToffsetLo16 = 41,
        RHex10X = 26,
        RHex11X = 25,
        RHex12X = 24,
        RHex16 = 7,
        RHex16X = 23,
        RHex23Reg = 94,
        RHex27Reg = 99,
        RHex32 = 6,
        RHex326X = 17,
        RHex32Pcrel = 31,
        RHex6PcrelX = 65,
        RHex6X = 30,
        RHex7X = 29,
        RHex8 = 8,
        RHex8X = 28,
        RHex9X = 27,
        RHexB13Pcrel = 14,
        RHexB13PcrelX = 20,
        RHexB15Pcrel = 2,
        RHexB15PcrelX = 19,
        RHexB22Pcrel = 1,
        RHexB22PcrelX = 18,
        RHexB32PcrelX = 16,
        RHexB7Pcrel = 3,
        RHexB7PcrelX = 22,
        RHexB9Pcrel = 15,
        RHexB9PcrelX = 21,
        RHexCopy = 32,
        RHexDtpmod32 = 44,
        RHexDtprel11X = 74,
        RHexDtprel16 = 48,
        RHexDtprel16X = 73,
        RHexDtprel32 = 47,
        RHexDtprel326X = 72,
        RHexDtprelHi16 = 46,
        RHexDtprelLo16 = 45,
        RHexGdGot11X = 77,
        RHexGdGot16 = 53,
        RHexGdGot16X = 76,
        RHexGdGot32 = 52,
        RHexGdGot326X = 75,
        RHexGdGotHi16 = 51,
        RHexGdGotLo16 = 50,
        RHexGdPltB22Pcrel = 49,
        RHexGdPltB22PcrelX = 95,
        RHexGdPltB32PcrelX = 96,
        RHexGlobDat = 33,
        RHexGotrel11X = 68,
        RHexGotrel16X = 67,
        RHexGotrel32 = 39,
        RHexGotrel326X = 66,
        RHexGotrelHi16 = 38,
        RHexGotrelLo16 = 37,
        RHexGot11X = 71,
        RHexGot16 = 43,
        RHexGot16X = 70,
        RHexGot32 = 42,
        RHexGot326X = 69,
        RHexGotHi16 = 41,
        RHexGotLo16 = 40,
        RHexGprel160 = 9,
        RHexGprel161 = 10,
        RHexGprel162 = 11,
        RHexGprel163 = 12,
        RHexHi16 = 5,
        RHexHl16 = 13,
        RHexIe16X = 79,
        RHexIe32 = 56,
        RHexIe326X = 78,
        RHexIeGot11X = 82,
        RHexIeGot16 = 60,
        RHexIeGot16X = 81,
        RHexIeGot32 = 59,
        RHexIeGot326X = 80,
        RHexIeGotHi16 = 58,
        RHexIeGotLo16 = 57,
        RHexIeHi16 = 55,
        RHexIeLo16 = 54,
        RHexJmpSlot = 34,
        RHexLdGot11X = 93,
        RHexLdGot16 = 90,
        RHexLdGot16X = 92,
        RHexLdGot32 = 89,
        RHexLdGot326X = 91,
        RHexLdGotHi16 = 88,
        RHexLdGotLo16 = 87,
        RHexLdPltB22Pcrel = 86,
        RHexLdPltB22PcrelX = 97,
        RHexLdPltB32PcrelX = 98,
        RHexLo16 = 4,
        RHexNone = 0,
        RHexPltB22Pcrel = 36,
        RHexRelative = 35,
        RHexTprel11X = 85,
        RHexTprel16 = 64,
        RHexTprel16X = 84,
        RHexTprel32 = 63,
        RHexTprel326X = 83,
        RHexTprelHi16 = 62,
        RHexTprelLo16 = 61,
        RLanai21 = 1,
        RLanai21F = 2,
        RLanai25 = 3,
        RLanai32 = 4,
        RLanaiHi16 = 5,
        RLanaiLo16 = 6,
        RLanaiNone = 0,
        RLarch32 = 1,
        RLarch32Pcrel = 99,
        RLarch64 = 2,
        RLarch64Pcrel = 109,
        RLarchAbs64Hi12 = 70,
        RLarchAbs64Lo20 = 69,
        RLarchAbsHi20 = 67,
        RLarchAbsLo12 = 68,
        RLarchAdd16 = 48,
        RLarchAdd24 = 49,
        RLarchAdd32 = 50,
        RLarchAdd6 = 105,
        RLarchAdd64 = 51,
        RLarchAdd8 = 47,
        RLarchAddUleb128 = 107,
        RLarchAlign = 102,
        RLarchB16 = 64,
        RLarchB21 = 65,
        RLarchB26 = 66,
        RLarchCall36 = 110,
        RLarchCopy = 4,
        RLarchGnuVtentry = 58,
        RLarchGnuVtinherit = 57,
        RLarchGot64Hi12 = 82,
        RLarchGot64Lo20 = 81,
        RLarchGot64PcHi12 = 78,
        RLarchGot64PcLo20 = 77,
        RLarchGotHi20 = 79,
        RLarchGotLo12 = 80,
        RLarchGotPcHi20 = 75,
        RLarchGotPcLo12 = 76,
        RLarchIrelative = 12,
        RLarchJumpSlot = 5,
        RLarchMarkLa = 20,
        RLarchMarkPcrel = 21,
        RLarchNone = 0,
        RLarchPcala64Hi12 = 74,
        RLarchPcala64Lo20 = 73,
        RLarchPcalaHi20 = 71,
        RLarchPcalaLo12 = 72,
        RLarchPcrel20S2 = 103,
        RLarchRelative = 3,
        RLarchRelax = 100,
        RLarchSopAdd = 35,
        RLarchSopAnd = 36,
        RLarchSopAssert = 30,
        RLarchSopIfElse = 37,
        RLarchSopNot = 31,
        RLarchSopPop32S0101016S2 = 45,
        RLarchSopPop32S051016S2 = 44,
        RLarchSopPop32S1012 = 40,
        RLarchSopPop32S1016 = 41,
        RLarchSopPop32S1016S2 = 42,
        RLarchSopPop32S105 = 38,
        RLarchSopPop32S520 = 43,
        RLarchSopPop32U = 46,
        RLarchSopPop32U1012 = 39,
        RLarchSopPushAbsolute = 23,
        RLarchSopPushDup = 24,
        RLarchSopPushGprel = 25,
        RLarchSopPushPcrel = 22,
        RLarchSopPushPltPcrel = 29,
        RLarchSopPushTlsGd = 28,
        RLarchSopPushTlsGot = 27,
        RLarchSopPushTlsTprel = 26,
        RLarchSopSl = 33,
        RLarchSopSr = 34,
        RLarchSopSub = 32,
        RLarchSub16 = 53,
        RLarchSub24 = 54,
        RLarchSub32 = 55,
        RLarchSub6 = 106,
        RLarchSub64 = 56,
        RLarchSub8 = 52,
        RLarchSubUleb128 = 108,
        RLarchTlsDesc32 = 13,
        RLarchTlsDesc64 = 14,
        RLarchTlsDesc64Hi12 = 118,
        RLarchTlsDesc64Lo20 = 117,
        RLarchTlsDesc64PcHi12 = 114,
        RLarchTlsDesc64PcLo20 = 113,
        RLarchTlsDescCall = 120,
        RLarchTlsDescHi20 = 115,
        RLarchTlsDescLd = 119,
        RLarchTlsDescLo12 = 116,
        RLarchTlsDescPcrel20S2 = 126,
        RLarchTlsDescPcHi20 = 111,
        RLarchTlsDescPcLo12 = 112,
        RLarchTlsDtpmod32 = 6,
        RLarchTlsDtpmod64 = 7,
        RLarchTlsDtprel32 = 8,
        RLarchTlsDtprel64 = 9,
        RLarchTlsGdHi20 = 98,
        RLarchTlsGdPcrel20S2 = 125,
        RLarchTlsGdPcHi20 = 97,
        RLarchTlsIe64Hi12 = 94,
        RLarchTlsIe64Lo20 = 93,
        RLarchTlsIe64PcHi12 = 90,
        RLarchTlsIe64PcLo20 = 89,
        RLarchTlsIeHi20 = 91,
        RLarchTlsIeLo12 = 92,
        RLarchTlsIePcHi20 = 87,
        RLarchTlsIePcLo12 = 88,
        RLarchTlsLdHi20 = 96,
        RLarchTlsLdPcrel20S2 = 124,
        RLarchTlsLdPcHi20 = 95,
        RLarchTlsLe64Hi12 = 86,
        RLarchTlsLe64Lo20 = 85,
        RLarchTlsLeAddR = 122,
        RLarchTlsLeHi20 = 83,
        RLarchTlsLeHi20R = 121,
        RLarchTlsLeLo12 = 84,
        RLarchTlsLeLo12R = 123,
        RLarchTlsTprel32 = 10,
        RLarchTlsTprel64 = 11,
        RMicromips26S1 = 133,
        RMicromipsCall16 = 142,
        RMicromipsCallHi16 = 153,
        RMicromipsCallLo16 = 154,
        RMicromipsGot16 = 138,
        RMicromipsGotDisp = 145,
        RMicromipsGotHi16 = 148,
        RMicromipsGotLo16 = 149,
        RMicromipsGotOfst = 147,
        RMicromipsGotPage = 146,
        RMicromipsGprel16 = 136,
        RMicromipsGprel7S2 = 172,
        RMicromipsHi0Lo16 = 157,
        RMicromipsHi16 = 134,
        RMicromipsHigher = 151,
        RMicromipsHighest = 152,
        RMicromipsJalr = 156,
        RMicromipsLiteral = 137,
        RMicromipsLo16 = 135,
        RMicromipsPc10S1 = 140,
        RMicromipsPc16S1 = 141,
        RMicromipsPc18S3 = 176,
        RMicromipsPc19S2 = 177,
        RMicromipsPc21S1 = 174,
        RMicromipsPc23S2 = 173,
        RMicromipsPc26S1 = 175,
        RMicromipsPc7S1 = 139,
        RMicromipsScnDisp = 155,
        RMicromipsSub = 150,
        RMicromipsTlsDtprelHi16 = 164,
        RMicromipsTlsDtprelLo16 = 165,
        RMicromipsTlsGd = 162,
        RMicromipsTlsGottprel = 166,
        RMicromipsTlsLdm = 163,
        RMicromipsTlsTprelHi16 = 169,
        RMicromipsTlsTprelLo16 = 170,
        RMips1626 = 100,
        RMips16Call16 = 103,
        RMips16Got16 = 102,
        RMips16Gprel = 101,
        RMips16Hi16 = 104,
        RMips16Lo16 = 105,
        RMips16TlsDtprelHi16 = 108,
        RMips16TlsDtprelLo16 = 109,
        RMips16TlsGd = 106,
        RMips16TlsGottprel = 110,
        RMips16TlsLdm = 107,
        RMips16TlsTprelHi16 = 111,
        RMips16TlsTprelLo16 = 112,
        RMips16 = 1,
        RMips26 = 4,
        RMips32 = 2,
        RMips64 = 18,
        RMipsAddImmediate = 34,
        RMipsCall16 = 11,
        RMipsCallHi16 = 30,
        RMipsCallLo16 = 31,
        RMipsCopy = 126,
        RMipsDelete = 27,
        RMipsEh = 249,
        RMipsGlobDat = 51,
        RMipsGot16 = 9,
        RMipsGotDisp = 19,
        RMipsGotHi16 = 22,
        RMipsGotLo16 = 23,
        RMipsGotOfst = 21,
        RMipsGotPage = 20,
        RMipsGprel16 = 7,
        RMipsGprel32 = 12,
        RMipsHi16 = 5,
        RMipsHigher = 28,
        RMipsHighest = 29,
        RMipsInsertA = 25,
        RMipsInsertB = 26,
        RMipsJalr = 37,
        RMipsJumpSlot = 127,
        RMipsLiteral = 8,
        RMipsLo16 = 6,
        RMipsNone = 0,
        RMipsNum = 218,
        RMipsPc16 = 10,
        RMipsPc18S3 = 62,
        RMipsPc19S2 = 63,
        RMipsPc21S2 = 60,
        RMipsPc26S2 = 61,
        RMipsPc32 = 248,
        RMipsPchi16 = 64,
        RMipsPclo16 = 65,
        RMipsPjump = 35,
        RMipsRel16 = 33,
        RMipsRel32 = 3,
        RMipsRelgot = 36,
        RMipsScnDisp = 32,
        RMipsShift5 = 16,
        RMipsShift6 = 17,
        RMipsSub = 24,
        RMipsTlsDtpmod32 = 38,
        RMipsTlsDtpmod64 = 40,
        RMipsTlsDtprel32 = 39,
        RMipsTlsDtprel64 = 41,
        RMipsTlsDtprelHi16 = 44,
        RMipsTlsDtprelLo16 = 45,
        RMipsTlsGd = 42,
        RMipsTlsGottprel = 46,
        RMipsTlsLdm = 43,
        RMipsTlsTprel32 = 47,
        RMipsTlsTprel64 = 48,
        RMipsTlsTprelHi16 = 49,
        RMipsTlsTprelLo16 = 50,
        RMipsUnused1 = 13,
        RMipsUnused2 = 14,
        RMipsUnused3 = 15,
        RMsp43010Pcrel = 2,
        RMsp43016 = 3,
        RMsp43016Byte = 5,
        RMsp43016Pcrel = 4,
        RMsp43016PcrelByte = 6,
        RMsp4302XPcrel = 7,
        RMsp43032 = 1,
        RMsp4308 = 9,
        RMsp430None = 0,
        RMsp430RlPcrel = 8,
        RMsp430SymDiff = 10,
        RPpc64Addr14 = 7,
        RPpc64Addr14Brntaken = 9,
        RPpc64Addr14Brtaken = 8,
        RPpc64Addr16 = 3,
        RPpc64Addr16Ds = 56,
        RPpc64Addr16Ha = 6,
        RPpc64Addr16Hi = 5,
        RPpc64Addr16High = 110,
        RPpc64Addr16Higha = 111,
        RPpc64Addr16Higher = 39,
        RPpc64Addr16Highera = 40,
        RPpc64Addr16Highest = 41,
        RPpc64Addr16Highesta = 42,
        RPpc64Addr16Lo = 4,
        RPpc64Addr16LoDs = 57,
        RPpc64Addr24 = 2,
        RPpc64Addr32 = 1,
        RPpc64Addr64 = 38,
        RPpc64Copy = 19,
        RPpc64Dtpmod64 = 68,
        RPpc64Dtprel16 = 74,
        RPpc64Dtprel16Ds = 101,
        RPpc64Dtprel16Ha = 77,
        RPpc64Dtprel16Hi = 76,
        RPpc64Dtprel16High = 114,
        RPpc64Dtprel16Higha = 115,
        RPpc64Dtprel16Higher = 103,
        RPpc64Dtprel16Highera = 104,
        RPpc64Dtprel16Highest = 105,
        RPpc64Dtprel16Highesta = 106,
        RPpc64Dtprel16Lo = 75,
        RPpc64Dtprel16LoDs = 102,
        RPpc64Dtprel34 = 147,
        RPpc64Dtprel64 = 78,
        RPpc64GlobDat = 20,
        RPpc64Got16 = 14,
        RPpc64Got16Ds = 58,
        RPpc64Got16Ha = 17,
        RPpc64Got16Hi = 16,
        RPpc64Got16Lo = 15,
        RPpc64Got16LoDs = 59,
        RPpc64GotDtprel16Ds = 91,
        RPpc64GotDtprel16Ha = 94,
        RPpc64GotDtprel16Hi = 93,
        RPpc64GotDtprel16LoDs = 92,
        RPpc64GotPcrel34 = 133,
        RPpc64GotTlsgd16 = 79,
        RPpc64GotTlsgd16Ha = 82,
        RPpc64GotTlsgd16Hi = 81,
        RPpc64GotTlsgd16Lo = 80,
        RPpc64GotTlsgdPcrel34 = 148,
        RPpc64GotTlsld16 = 83,
        RPpc64GotTlsld16Ha = 86,
        RPpc64GotTlsld16Hi = 85,
        RPpc64GotTlsld16Lo = 84,
        RPpc64GotTlsldPcrel34 = 149,
        RPpc64GotTprel16Ds = 87,
        RPpc64GotTprel16Ha = 90,
        RPpc64GotTprel16Hi = 89,
        RPpc64GotTprel16LoDs = 88,
        RPpc64GotTprelPcrel34 = 150,
        RPpc64Irelative = 248,
        RPpc64JmpSlot = 21,
        RPpc64None = 0,
        RPpc64Pcrel34 = 132,
        RPpc64PcrelOpt = 123,
        RPpc64Rel14 = 11,
        RPpc64Rel14Brntaken = 13,
        RPpc64Rel14Brtaken = 12,
        RPpc64Rel16 = 249,
        RPpc64Rel16Ha = 252,
        RPpc64Rel16Hi = 251,
        RPpc64Rel16Lo = 250,
        RPpc64Rel24 = 10,
        RPpc64Rel24Notoc = 116,
        RPpc64Rel32 = 26,
        RPpc64Rel64 = 44,
        RPpc64Relative = 22,
        RPpc64Tls = 67,
        RPpc64Tlsgd = 107,
        RPpc64Tlsld = 108,
        RPpc64Toc = 51,
        RPpc64Toc16 = 47,
        RPpc64Toc16Ds = 63,
        RPpc64Toc16Ha = 50,
        RPpc64Toc16Hi = 49,
        RPpc64Toc16Lo = 48,
        RPpc64Toc16LoDs = 64,
        RPpc64Tprel16 = 69,
        RPpc64Tprel16Ds = 95,
        RPpc64Tprel16Ha = 72,
        RPpc64Tprel16Hi = 71,
        RPpc64Tprel16High = 112,
        RPpc64Tprel16Higha = 113,
        RPpc64Tprel16Higher = 97,
        RPpc64Tprel16Highera = 98,
        RPpc64Tprel16Highest = 99,
        RPpc64Tprel16Highesta = 100,
        RPpc64Tprel16Lo = 70,
        RPpc64Tprel16LoDs = 96,
        RPpc64Tprel34 = 146,
        RPpc64Tprel64 = 73,
        RPpcAddr14 = 7,
        RPpcAddr14Brntaken = 9,
        RPpcAddr14Brtaken = 8,
        RPpcAddr16 = 3,
        RPpcAddr16Ha = 6,
        RPpcAddr16Hi = 5,
        RPpcAddr16Lo = 4,
        RPpcAddr24 = 2,
        RPpcAddr30 = 37,
        RPpcAddr32 = 1,
        RPpcCopy = 19,
        RPpcDtpmod32 = 68,
        RPpcDtprel16 = 74,
        RPpcDtprel16Ha = 77,
        RPpcDtprel16Hi = 76,
        RPpcDtprel16Lo = 75,
        RPpcDtprel32 = 78,
        RPpcGlobDat = 20,
        RPpcGot16 = 14,
        RPpcGot16Ha = 17,
        RPpcGot16Hi = 16,
        RPpcGot16Lo = 15,
        RPpcGotDtprel16 = 91,
        RPpcGotDtprel16Ha = 94,
        RPpcGotDtprel16Hi = 93,
        RPpcGotDtprel16Lo = 92,
        RPpcGotTlsgd16 = 79,
        RPpcGotTlsgd16Ha = 82,
        RPpcGotTlsgd16Hi = 81,
        RPpcGotTlsgd16Lo = 80,
        RPpcGotTlsld16 = 83,
        RPpcGotTlsld16Ha = 86,
        RPpcGotTlsld16Hi = 85,
        RPpcGotTlsld16Lo = 84,
        RPpcGotTprel16 = 87,
        RPpcGotTprel16Ha = 90,
        RPpcGotTprel16Hi = 89,
        RPpcGotTprel16Lo = 88,
        RPpcIrelative = 248,
        RPpcJmpSlot = 21,
        RPpcLocal24Pc = 23,
        RPpcNone = 0,
        RPpcPlt16Ha = 31,
        RPpcPlt16Hi = 30,
        RPpcPlt16Lo = 29,
        RPpcPlt32 = 27,
        RPpcPltrel24 = 18,
        RPpcPltrel32 = 28,
        RPpcRel14 = 11,
        RPpcRel14Brntaken = 13,
        RPpcRel14Brtaken = 12,
        RPpcRel16 = 249,
        RPpcRel16Ha = 252,
        RPpcRel16Hi = 251,
        RPpcRel16Lo = 250,
        RPpcRel24 = 10,
        RPpcRel32 = 26,
        RPpcRelative = 22,
        RPpcSdarel16 = 32,
        RPpcSectoff = 33,
        RPpcSectoffHa = 36,
        RPpcSectoffHi = 35,
        RPpcSectoffLo = 34,
        RPpcTls = 67,
        RPpcTlsgd = 95,
        RPpcTlsld = 96,
        RPpcTprel16 = 69,
        RPpcTprel16Ha = 72,
        RPpcTprel16Hi = 71,
        RPpcTprel16Lo = 70,
        RPpcTprel32 = 73,
        RPpcUaddr16 = 25,
        RPpcUaddr32 = 24,
        RRiscv32 = 1,
        RRiscv32Pcrel = 57,
        RRiscv64 = 2,
        RRiscvAdd16 = 34,
        RRiscvAdd32 = 35,
        RRiscvAdd64 = 36,
        RRiscvAdd8 = 33,
        RRiscvAlign = 43,
        RRiscvBranch = 16,
        RRiscvCall = 18,
        RRiscvCallPlt = 19,
        RRiscvCopy = 4,
        RRiscvCustom192 = 192,
        RRiscvCustom193 = 193,
        RRiscvCustom194 = 194,
        RRiscvCustom195 = 195,
        RRiscvCustom196 = 196,
        RRiscvCustom197 = 197,
        RRiscvCustom198 = 198,
        RRiscvCustom199 = 199,
        RRiscvCustom200 = 200,
        RRiscvCustom201 = 201,
        RRiscvCustom202 = 202,
        RRiscvCustom203 = 203,
        RRiscvCustom204 = 204,
        RRiscvCustom205 = 205,
        RRiscvCustom206 = 206,
        RRiscvCustom207 = 207,
        RRiscvCustom208 = 208,
        RRiscvCustom209 = 209,
        RRiscvCustom210 = 210,
        RRiscvCustom211 = 211,
        RRiscvCustom212 = 212,
        RRiscvCustom213 = 213,
        RRiscvCustom214 = 214,
        RRiscvCustom215 = 215,
        RRiscvCustom216 = 216,
        RRiscvCustom217 = 217,
        RRiscvCustom218 = 218,
        RRiscvCustom219 = 219,
        RRiscvCustom220 = 220,
        RRiscvCustom221 = 221,
        RRiscvCustom222 = 222,
        RRiscvCustom223 = 223,
        RRiscvCustom224 = 224,
        RRiscvCustom225 = 225,
        RRiscvCustom226 = 226,
        RRiscvCustom227 = 227,
        RRiscvCustom228 = 228,
        RRiscvCustom229 = 229,
        RRiscvCustom230 = 230,
        RRiscvCustom231 = 231,
        RRiscvCustom232 = 232,
        RRiscvCustom233 = 233,
        RRiscvCustom234 = 234,
        RRiscvCustom235 = 235,
        RRiscvCustom236 = 236,
        RRiscvCustom237 = 237,
        RRiscvCustom238 = 238,
        RRiscvCustom239 = 239,
        RRiscvCustom240 = 240,
        RRiscvCustom241 = 241,
        RRiscvCustom242 = 242,
        RRiscvCustom243 = 243,
        RRiscvCustom244 = 244,
        RRiscvCustom245 = 245,
        RRiscvCustom246 = 246,
        RRiscvCustom247 = 247,
        RRiscvCustom248 = 248,
        RRiscvCustom249 = 249,
        RRiscvCustom250 = 250,
        RRiscvCustom251 = 251,
        RRiscvCustom252 = 252,
        RRiscvCustom253 = 253,
        RRiscvCustom254 = 254,
        RRiscvCustom255 = 255,
        RRiscvGot32Pcrel = 41,
        RRiscvGotHi20 = 20,
        RRiscvHi20 = 26,
        RRiscvIrelative = 58,
        RRiscvJal = 17,
        RRiscvJumpSlot = 5,
        RRiscvLo12I = 27,
        RRiscvLo12S = 28,
        RRiscvNone = 0,
        RRiscvPcrelHi20 = 23,
        RRiscvPcrelLo12I = 24,
        RRiscvPcrelLo12S = 25,
        RRiscvPlt32 = 59,
        RRiscvRelative = 3,
        RRiscvRelax = 51,
        RRiscvRvcBranch = 44,
        RRiscvRvcJump = 45,
        RRiscvSet16 = 55,
        RRiscvSet32 = 56,
        RRiscvSet6 = 53,
        RRiscvSet8 = 54,
        RRiscvSetUleb128 = 60,
        RRiscvSub16 = 38,
        RRiscvSub32 = 39,
        RRiscvSub6 = 52,
        RRiscvSub64 = 40,
        RRiscvSub8 = 37,
        RRiscvSubUleb128 = 61,
        RRiscvTlsdesc = 12,
        RRiscvTlsdescAddLo12 = 64,
        RRiscvTlsdescCall = 65,
        RRiscvTlsdescHi20 = 62,
        RRiscvTlsdescLoadLo12 = 63,
        RRiscvTlsDtpmod32 = 6,
        RRiscvTlsDtpmod64 = 7,
        RRiscvTlsDtprel32 = 8,
        RRiscvTlsDtprel64 = 9,
        RRiscvTlsGdHi20 = 22,
        RRiscvTlsGotHi20 = 21,
        RRiscvTlsTprel32 = 10,
        RRiscvTlsTprel64 = 11,
        RRiscvTprelAdd = 32,
        RRiscvTprelHi20 = 29,
        RRiscvTprelLo12I = 30,
        RRiscvTprelLo12S = 31,
        RRiscvVendor = 191,
        RSparc10 = 30,
        RSparc11 = 31,
        RSparc13 = 11,
        RSparc16 = 2,
        RSparc22 = 10,
        RSparc32 = 3,
        RSparc5 = 44,
        RSparc6 = 45,
        RSparc64 = 32,
        RSparc7 = 43,
        RSparc8 = 1,
        RSparcCopy = 19,
        RSparcDisp16 = 5,
        RSparcDisp32 = 6,
        RSparcDisp64 = 46,
        RSparcDisp8 = 4,
        RSparcGlobDat = 20,
        RSparcGot10 = 13,
        RSparcGot13 = 14,
        RSparcGot22 = 15,
        RSparcGotdataHix22 = 80,
        RSparcGotdataLox10 = 81,
        RSparcGotdataOp = 84,
        RSparcGotdataOpHix22 = 82,
        RSparcGotdataOpLox10 = 83,
        RSparcH44 = 50,
        RSparcHh22 = 34,
        RSparcHi22 = 9,
        RSparcHiplt22 = 25,
        RSparcHix22 = 48,
        RSparcHm10 = 35,
        RSparcJmpSlot = 21,
        RSparcL44 = 52,
        RSparcLm22 = 36,
        RSparcLo10 = 12,
        RSparcLoplt10 = 26,
        RSparcLox10 = 49,
        RSparcM44 = 51,
        RSparcNone = 0,
        RSparcOlo10 = 33,
        RSparcPc10 = 16,
        RSparcPc22 = 17,
        RSparcPcplt10 = 29,
        RSparcPcplt22 = 28,
        RSparcPcplt32 = 27,
        RSparcPcHh22 = 37,
        RSparcPcHm10 = 38,
        RSparcPcLm22 = 39,
        RSparcPlt32 = 24,
        RSparcPlt64 = 47,
        RSparcRegister = 53,
        RSparcRelative = 22,
        RSparcTlsDtpmod32 = 74,
        RSparcTlsDtpmod64 = 75,
        RSparcTlsDtpoff32 = 76,
        RSparcTlsDtpoff64 = 77,
        RSparcTlsGdAdd = 58,
        RSparcTlsGdCall = 59,
        RSparcTlsGdHi22 = 56,
        RSparcTlsGdLo10 = 57,
        RSparcTlsIeAdd = 71,
        RSparcTlsIeHi22 = 67,
        RSparcTlsIeLd = 69,
        RSparcTlsIeLdx = 70,
        RSparcTlsIeLo10 = 68,
        RSparcTlsLdmAdd = 62,
        RSparcTlsLdmCall = 63,
        RSparcTlsLdmHi22 = 60,
        RSparcTlsLdmLo10 = 61,
        RSparcTlsLdoAdd = 66,
        RSparcTlsLdoHix22 = 64,
        RSparcTlsLdoLox10 = 65,
        RSparcTlsLeHix22 = 72,
        RSparcTlsLeLox10 = 73,
        RSparcTlsTpoff32 = 78,
        RSparcTlsTpoff64 = 79,
        RSparcUa16 = 55,
        RSparcUa32 = 23,
        RSparcUa64 = 54,
        RSparcWdisp16 = 40,
        RSparcWdisp19 = 41,
        RSparcWdisp22 = 8,
        RSparcWdisp30 = 7,
        RSparcWplt30 = 18,
        RVeCallHi32 = 35,
        RVeCallLo32 = 36,
        RVeCopy = 20,
        RVeDtpmod64 = 22,
        RVeDtpoff32 = 29,
        RVeDtpoff64 = 23,
        RVeGlobDat = 18,
        RVeGot32 = 8,
        RVeGotoff32 = 11,
        RVeGotoffHi32 = 12,
        RVeGotoffLo32 = 13,
        RVeGotHi32 = 9,
        RVeGotLo32 = 10,
        RVeHi32 = 4,
        RVeJumpSlot = 19,
        RVeLo32 = 5,
        RVeNone = 0,
        RVePcHi32 = 6,
        RVePcLo32 = 7,
        RVePlt32 = 14,
        RVePltHi32 = 15,
        RVePltLo32 = 16,
        RVeReflong = 1,
        RVeRefquad = 2,
        RVeRelative = 17,
        RVeSrel32 = 3,
        RVeTlsGdHi32 = 25,
        RVeTlsGdLo32 = 26,
        RVeTlsIeHi32 = 30,
        RVeTlsIeLo32 = 31,
        RVeTlsLdHi32 = 27,
        RVeTlsLdLo32 = 28,
        RVeTpoff32 = 34,
        RVeTpoff64 = 24,
        RVeTpoffHi32 = 32,
        RVeTpoffLo32 = 33,
        RX866416 = 12,
        RX866432 = 10,
        RX866432S = 11,
        RX866464 = 1,
        RX86648 = 14,
        RX8664Code4Gotpc32Tlsdesc = 45,
        RX8664Code4Gotpcrelx = 43,
        RX8664Code4Gottpoff = 44,
        RX8664Code6Gottpoff = 50,
        RX8664Copy = 5,
        RX8664Dtpmod64 = 16,
        RX8664Dtpoff32 = 21,
        RX8664Dtpoff64 = 17,
        RX8664GlobDat = 6,
        RX8664Got32 = 3,
        RX8664Got64 = 27,
        RX8664Gotoff64 = 25,
        RX8664Gotpc32 = 26,
        RX8664Gotpc32Tlsdesc = 34,
        RX8664Gotpc64 = 29,
        RX8664Gotpcrel = 9,
        RX8664Gotpcrel64 = 28,
        RX8664Gotpcrelx = 41,
        RX8664Gotplt64 = 30,
        RX8664Gottpoff = 22,
        RX8664Irelative = 37,
        RX8664JumpSlot = 7,
        RX8664None = 0,
        RX8664Pc16 = 13,
        RX8664Pc32 = 2,
        RX8664Pc64 = 24,
        RX8664Pc8 = 15,
        RX8664Plt32 = 4,
        RX8664Pltoff64 = 31,
        RX8664Relative = 8,
        RX8664RexGotpcrelx = 42,
        RX8664Size32 = 32,
        RX8664Size64 = 33,
        RX8664Tlsdesc = 36,
        RX8664TlsdescCall = 35,
        RX8664Tlsgd = 19,
        RX8664Tlsld = 20,
        RX8664Tpoff32 = 23,
        RX8664Tpoff64 = 18,
        RXtensa32 = 1,
        RXtensa32Pcrel = 14,
        RXtensaAsmExpand = 11,
        RXtensaAsmSimplify = 12,
        RXtensaDiff16 = 18,
        RXtensaDiff32 = 19,
        RXtensaDiff8 = 17,
        RXtensaGlobDat = 3,
        RXtensaGnuVtentry = 16,
        RXtensaGnuVtinherit = 15,
        RXtensaJmpSlot = 4,
        RXtensaNone = 0,
        RXtensaOp0 = 8,
        RXtensaOp1 = 9,
        RXtensaOp2 = 10,
        RXtensaPlt = 6,
        RXtensaRelative = 5,
        RXtensaRtld = 2,
        RXtensaSlot0Alt = 35,
        RXtensaSlot0Op = 20,
        RXtensaSlot10Alt = 45,
        RXtensaSlot10Op = 30,
        RXtensaSlot11Alt = 46,
        RXtensaSlot11Op = 31,
        RXtensaSlot12Alt = 47,
        RXtensaSlot12Op = 32,
        RXtensaSlot13Alt = 48,
        RXtensaSlot13Op = 33,
        RXtensaSlot14Alt = 49,
        RXtensaSlot14Op = 34,
        RXtensaSlot1Alt = 36,
        RXtensaSlot1Op = 21,
        RXtensaSlot2Alt = 37,
        RXtensaSlot2Op = 22,
        RXtensaSlot3Alt = 38,
        RXtensaSlot3Op = 23,
        RXtensaSlot4Alt = 39,
        RXtensaSlot4Op = 24,
        RXtensaSlot5Alt = 40,
        RXtensaSlot5Op = 25,
        RXtensaSlot6Alt = 41,
        RXtensaSlot6Op = 26,
        RXtensaSlot7Alt = 42,
        RXtensaSlot7Op = 27,
        RXtensaSlot8Alt = 43,
        RXtensaSlot8Op = 28,
        RXtensaSlot9Alt = 44,
        RXtensaSlot9Op = 29,
        RXtensaTlsdescArg = 51,
        RXtensaTlsdescFn = 50,
        RXtensaTlsArg = 55,
        RXtensaTlsCall = 56,
        RXtensaTlsDtpoff = 52,
        RXtensaTlsFunc = 54,
        RXtensaTlsTpoff = 53,
        ;
        Other(u32),
    }
    canonical {
        None = 0,
        R38616 = 20,
        R38632 = 1,
        R38632Plt = 11,
        R3868 = 22,
        R386Copy = 5,
        R386GlobDat = 6,
        R386Got32 = 3,
        R386Got32X = 43,
        R386Gotoff = 9,
        R386Gotpc = 10,
        R386Irelative = 42,
        R386JumpSlot = 7,
        R386Pc16 = 21,
        R386Pc32 = 2,
        R386Pc8 = 23,
        R386Plt32 = 4,
        R386Relative = 8,
        R386TlsDesc = 41,
        R386TlsDescCall = 40,
        R386TlsDtpmod32 = 35,
        R386TlsDtpoff32 = 36,
        R386TlsGd = 18,
        R386TlsGd32 = 24,
        R386TlsGdCall = 26,
        R386TlsGdPop = 27,
        R386TlsGdPush = 25,
        R386TlsGotdesc = 39,
        R386TlsGotie = 16,
        R386TlsIe = 15,
        R386TlsIe32 = 33,
        R386TlsLdm = 19,
        R386TlsLdm32 = 28,
        R386TlsLdmCall = 30,
        R386TlsLdmPop = 31,
        R386TlsLdmPush = 29,
        R386TlsLdo32 = 32,
        R386TlsLe = 17,
        R386TlsLe32 = 34,
        R386TlsTpoff = 14,
        R386TlsTpoff32 = 37,
        R39020 = 57,
        R390Got20 = 58,
        R390Gotoff = 13,
        R390Gotplt20 = 59,
        R390Irelative = 61,
        R390Pc12Dbl = 62,
        R390Pc24Dbl = 64,
        R390Plt12Dbl = 63,
        R390Plt24Dbl = 65,
        R390Relative = 12,
        R390TlsDtpmod = 54,
        R390TlsDtpoff = 55,
        R390TlsGdcall = 38,
        R390TlsGotie20 = 60,
        R390TlsGotie64 = 44,
        R390TlsIe32 = 47,
        R390TlsIe64 = 48,
        R390TlsIeent = 49,
        R390TlsLdm32 = 45,
        R390TlsLdm64 = 46,
        R390TlsLdo32 = 52,
        R390TlsLdo64 = 53,
        R390TlsLe32 = 50,
        R390TlsLe64 = 51,
        R390TlsTpoff = 56,
        RAarch64Abs16 = 259,
        RAarch64Abs32 = 258,
        RAarch64Abs64 = 257,
        RAarch64AddAbsLo12Nc = 277,
        RAarch64AdrGotPage = 311,
        RAarch64AdrPrelLo21 = 274,
        RAarch64AdrPrelPgHi21 = 275,
        RAarch64AdrPrelPgHi21Nc = 276,
        RAarch64AuthAbs64 = 580,
        RAarch64AuthAdrGotPage = 590,
        RAarch64AuthGlobDat = 1042,
        RAarch64AuthGotAddLo12Nc = 593,
        RAarch64AuthGotAdrPrelLo21 = 594,
        RAarch64AuthGotLdPrel19 = 588,
        RAarch64AuthIrelative = 1044,
        RAarch64AuthLd64GotoffLo15 = 589,
        RAarch64AuthLd64GotpageLo15 = 592,
        RAarch64AuthLd64GotLo12Nc = 591,
        RAarch64AuthMovwGotoffG0 = 581,
        RAarch64AuthMovwGotoffG0Nc = 582,
        RAarch64AuthMovwGotoffG1 = 583,
        RAarch64AuthMovwGotoffG1Nc = 584,
        RAarch64AuthMovwGotoffG2 = 585,
        RAarch64AuthMovwGotoffG2Nc = 586,
        RAarch64AuthMovwGotoffG3 = 587,
        RAarch64AuthRelative = 1041,
        RAarch64AuthTlsdesc = 1043,
        RAarch64AuthTlsdescAddLo12 = 597,
        RAarch64AuthTlsdescAdrPage21 = 595,
        RAarch64AuthTlsdescLd64Lo12 = 596,
        RAarch64Call26 = 283,
        RAarch64Condbr19 = 280,
        RAarch64Copy = 1024,
        RAarch64GlobDat = 1025,
        RAarch64Gotpcrel32 = 315,
        RAarch64Gotrel32 = 308,
        RAarch64Gotrel64 = 307,
        RAarch64GotLdPrel19 = 309,
        RAarch64Irelative = 1032,
        RAarch64Jump26 = 282,
        RAarch64JumpSlot = 1026,
        RAarch64Ld64GotoffLo15 = 310,
        RAarch64Ld64GotpageLo15 = 313,
        RAarch64Ld64GotLo12Nc = 312,
        RAarch64Ldst128AbsLo12Nc = 299,
        RAarch64Ldst16AbsLo12Nc = 284,
        RAarch64Ldst32AbsLo12Nc = 285,
        RAarch64Ldst64AbsLo12Nc = 286,
        RAarch64Ldst8AbsLo12Nc = 278,
        RAarch64LdPrelLo19 = 273,
        RAarch64MovwGotoffG0 = 300,
        RAarch64MovwGotoffG0Nc = 301,
        RAarch64MovwGotoffG1 = 302,
        RAarch64MovwGotoffG1Nc = 303,
        RAarch64MovwGotoffG2 = 304,
        RAarch64MovwGotoffG2Nc = 305,
        RAarch64MovwGotoffG3 = 306,
        RAarch64MovwPrelG0 = 287,
        RAarch64MovwPrelG0Nc = 288,
        RAarch64MovwPrelG1 = 289,
        RAarch64MovwPrelG1Nc = 290,
        RAarch64MovwPrelG2 = 291,
        RAarch64MovwPrelG2Nc = 292,
        RAarch64MovwPrelG3 = 293,
        RAarch64MovwSabsG0 = 270,
        RAarch64MovwSabsG1 = 271,
        RAarch64MovwSabsG2 = 272,
        RAarch64MovwUabsG0 = 263,
        RAarch64MovwUabsG0Nc = 264,
        RAarch64MovwUabsG1 = 265,
        RAarch64MovwUabsG1Nc = 266,
        RAarch64MovwUabsG2 = 267,
        RAarch64MovwUabsG2Nc = 268,
        RAarch64MovwUabsG3 = 269,
        RAarch64P32Copy = 180,
        RAarch64P32GlobDat = 181,
        RAarch64P32Irelative = 188,
        RAarch64P32JumpSlot = 182,
        RAarch64P32Relative = 183,
        RAarch64P32Tlsdesc = 187,
        RAarch64P32TlsdescAddLo12 = 126,
        RAarch64P32TlsdescAdrPage21 = 124,
        RAarch64P32TlsdescAdrPrel21 = 123,
        RAarch64P32TlsdescCall = 127,
        RAarch64P32TlsdescLd32Lo12 = 125,
        RAarch64P32TlsdescLdPrel19 = 122,
        RAarch64P32TlsgdAddLo12Nc = 82,
        RAarch64P32TlsgdAdrPage21 = 81,
        RAarch64P32TlsgdAdrPrel21 = 80,
        RAarch64P32TlsieAdrGottprelPage21 = 103,
        RAarch64P32TlsieLd32GottprelLo12Nc = 104,
        RAarch64P32TlsieLdGottprelPrel19 = 105,
        RAarch64P32TlsldAddDtprelHi12 = 90,
        RAarch64P32TlsldAddDtprelLo12 = 91,
        RAarch64P32TlsldAddDtprelLo12Nc = 92,
        RAarch64P32TlsldAddLo12Nc = 85,
        RAarch64P32TlsldAdrPage21 = 84,
        RAarch64P32TlsldAdrPrel21 = 83,
        RAarch64P32TlsldLdst128DtprelLo12 = 101,
        RAarch64P32TlsldLdst128DtprelLo12Nc = 102,
        RAarch64P32TlsldLdst16DtprelLo12 = 95,
        RAarch64P32TlsldLdst16DtprelLo12Nc = 96,
        RAarch64P32TlsldLdst32DtprelLo12 = 97,
        RAarch64P32TlsldLdst32DtprelLo12Nc = 98,
        RAarch64P32TlsldLdst64DtprelLo12 = 99,
        RAarch64P32TlsldLdst64DtprelLo12Nc = 100,
        RAarch64P32TlsldLdst8DtprelLo12 = 93,
        RAarch64P32TlsldLdst8DtprelLo12Nc = 94,
        RAarch64P32TlsldLdPrel19 = 86,
        RAarch64P32TlsldMovwDtprelG0 = 88,
        RAarch64P32TlsldMovwDtprelG0Nc = 89,
        RAarch64P32TlsldMovwDtprelG1 = 87,
        RAarch64P32TlsleAddTprelHi12 = 109,
        RAarch64P32TlsleAddTprelLo12 = 110,
        RAarch64P32TlsleAddTprelLo12Nc = 111,
        RAarch64P32TlsleLdst128TprelLo12 = 120,
        RAarch64P32TlsleLdst128TprelLo12Nc = 121,
        RAarch64P32TlsleLdst16TprelLo12 = 114,
        RAarch64P32TlsleLdst16TprelLo12Nc = 115,
        RAarch64P32TlsleLdst32TprelLo12 = 116,
        RAarch64P32TlsleLdst32TprelLo12Nc = 117,
        RAarch64P32TlsleLdst64TprelLo12 = 118,
        RAarch64P32TlsleLdst64TprelLo12Nc = 119,
        RAarch64P32TlsleLdst8TprelLo12 = 112,
        RAarch64P32TlsleLdst8TprelLo12Nc = 113,
        RAarch64P32TlsleMovwTprelG0 = 107,
        RAarch64P32TlsleMovwTprelG0Nc = 108,
        RAarch64P32TlsleMovwTprelG1 = 106,
        RAarch64P32TlsDtpmod = 185,
        RAarch64P32TlsDtprel = 184,
        RAarch64P32TlsTprel = 186,
        RAarch64Plt32 = 314,
        RAarch64Prel16 = 262,
        RAarch64Prel32 = 261,
        RAarch64Prel64 = 260,
        RAarch64Relative = 1027,
        RAarch64Tlsdesc = 1031,
        RAarch64TlsdescAdd = 568,
        RAarch64TlsdescAddLo12 = 564,
        RAarch64TlsdescAdrPage21 = 562,
        RAarch64TlsdescAdrPrel21 = 561,
        RAarch64TlsdescCall = 569,
        RAarch64TlsdescLd64Lo12 = 563,
        RAarch64TlsdescLdr = 567,
        RAarch64TlsdescLdPrel19 = 560,
        RAarch64TlsdescOffG0Nc = 566,
        RAarch64TlsdescOffG1 = 565,
        RAarch64TlsgdAddLo12Nc = 514,
        RAarch64TlsgdAdrPage21 = 513,
        RAarch64TlsgdAdrPrel21 = 512,
        RAarch64TlsgdMovwG0Nc = 516,
        RAarch64TlsgdMovwG1 = 515,
        RAarch64TlsieAdrGottprelPage21 = 541,
        RAarch64TlsieLd64GottprelLo12Nc = 542,
        RAarch64TlsieLdGottprelPrel19 = 543,
        RAarch64TlsieMovwGottprelG0Nc = 540,
        RAarch64TlsieMovwGottprelG1 = 539,
        RAarch64TlsldAddDtprelHi12 = 528,
        RAarch64TlsldAddDtprelLo12 = 529,
        RAarch64TlsldAddDtprelLo12Nc = 530,
        RAarch64TlsldAddLo12Nc = 519,
        RAarch64TlsldAdrPage21 = 518,
        RAarch64TlsldAdrPrel21 = 517,
        RAarch64TlsldLdst128DtprelLo12 = 572,
        RAarch64TlsldLdst128DtprelLo12Nc = 573,
        RAarch64TlsldLdst16DtprelLo12 = 533,
        RAarch64TlsldLdst16DtprelLo12Nc = 534,
        RAarch64TlsldLdst32DtprelLo12 = 535,
        RAarch64TlsldLdst32DtprelLo12Nc = 536,
        RAarch64TlsldLdst64DtprelLo12 = 537,
        RAarch64TlsldLdst64DtprelLo12Nc = 538,
        RAarch64TlsldLdst8DtprelLo12 = 531,
        RAarch64TlsldLdst8DtprelLo12Nc = 532,
        RAarch64TlsldLdPrel19 = 522,
        RAarch64TlsldMovwDtprelG0 = 526,
        RAarch64TlsldMovwDtprelG0Nc = 527,
        RAarch64TlsldMovwDtprelG1 = 524,
        RAarch64TlsldMovwDtprelG1Nc = 525,
        RAarch64TlsldMovwDtprelG2 = 523,
        RAarch64TlsldMovwG0Nc = 521,
        RAarch64TlsldMovwG1 = 520,
        RAarch64TlsleAddTprelHi12 = 549,
        RAarch64TlsleAddTprelLo12 = 550,
        RAarch64TlsleAddTprelLo12Nc = 551,
        RAarch64TlsleLdst128TprelLo12 = 570,
        RAarch64TlsleLdst128TprelLo12Nc = 571,
        RAarch64TlsleLdst16TprelLo12 = 554,
        RAarch64TlsleLdst16TprelLo12Nc = 555,
        RAarch64TlsleLdst32TprelLo12 = 556,
        RAarch64TlsleLdst32TprelLo12Nc = 557,
        RAarch64TlsleLdst64TprelLo12 = 558,
        RAarch64TlsleLdst64TprelLo12Nc = 559,
        RAarch64TlsleLdst8TprelLo12 = 552,
        RAarch64TlsleLdst8TprelLo12Nc = 553,
        RAarch64TlsleMovwTprelG0 = 547,
        RAarch64TlsleMovwTprelG0Nc = 548,
        RAarch64TlsleMovwTprelG1 = 545,
        RAarch64TlsleMovwTprelG1Nc = 546,
        RAarch64TlsleMovwTprelG2 = 544,
        RAarch64TlsDtpmod64 = 1028,
        RAarch64TlsDtprel64 = 1029,
        RAarch64TlsTprel64 = 1030,
        RAarch64Tstbr14 = 279,
        RArcNpsCmem16 = 78,
        RArcS21HPcrelPlt = 77,
        RArcS25WPcrelPlt = 76,
        RArcTlsDtpmod = 66,
        RArcTlsDtpoff = 67,
        RArcTlsDtpoffS9 = 73,
        RArcTlsGdCall = 71,
        RArcTlsGdGot = 69,
        RArcTlsGdLd = 70,
        RArcTlsIeGot = 72,
        RArcTlsLe32 = 75,
        RArcTlsLeS9 = 74,
        RArcTlsTpoff = 68,
        RArmFuncdesc = 163,
        RArmFuncdescValue = 164,
        RArmGotfuncdesc = 161,
        RArmGotofffuncdesc = 162,
        RArmIrelative = 160,
        RArmLdrsSbG1 = 79,
        RArmMeToo = 128,
        RArmThmAluAbsG0Nc = 132,
        RArmThmAluAbsG1Nc = 133,
        RArmThmAluAbsG2Nc = 134,
        RArmThmAluAbsG3 = 135,
        RArmThmBf12 = 137,
        RArmThmBf16 = 136,
        RArmThmBf18 = 138,
        RArmThmTlsDescseq16 = 129,
        RArmThmTlsDescseq32 = 130,
        RArmTlsGd32Fdpic = 165,
        RArmTlsIe32Fdpic = 167,
        RArmTlsLdm32Fdpic = 166,
        RMicromipsCall16 = 142,
        RMicromipsCallHi16 = 153,
        RMicromipsCallLo16 = 154,
        RMicromipsGotDisp = 145,
        RMicromipsGotHi16 = 148,
        RMicromipsGotLo16 = 149,
        RMicromipsGotOfst = 147,
        RMicromipsGotPage = 146,
        RMicromipsGprel7S2 = 172,
        RMicromipsHi0Lo16 = 157,
        RMicromipsHigher = 151,
        RMicromipsHighest = 152,
        RMicromipsJalr = 156,
        RMicromipsPc10S1 = 140,
        RMicromipsPc16S1 = 141,
        RMicromipsPc18S3 = 176,
        RMicromipsPc19S2 = 177,
        RMicromipsPc21S1 = 174,
        RMicromipsPc23S2 = 173,
        RMicromipsPc26S1 = 175,
        RMicromipsPc7S1 = 139,
        RMicromipsScnDisp = 155,
        RMicromipsSub = 150,
        RMicromipsTlsTprelHi16 = 169,
        RMicromipsTlsTprelLo16 = 170,
        RMipsEh = 249,
        RMipsNum = 218,
        RMipsPc32 = 248,
        RPpc64Rel16Ha = 252,
        RPpc64Rel16Hi = 251,
        RPpc64Rel16Lo = 250,
        RRiscvCustom192 = 192,
        RRiscvCustom193 = 193,
        RRiscvCustom194 = 194,
        RRiscvCustom195 = 195,
        RRiscvCustom196 = 196,
        RRiscvCustom197 = 197,
        RRiscvCustom198 = 198,
        RRiscvCustom199 = 199,
        RRiscvCustom200 = 200,
        RRiscvCustom201 = 201,
        RRiscvCustom202 = 202,
        RRiscvCustom203 = 203,
        RRiscvCustom204 = 204,
        RRiscvCustom205 = 205,
        RRiscvCustom206 = 206,
        RRiscvCustom207 = 207,
        RRiscvCustom208 = 208,
        RRiscvCustom209 = 209,
        RRiscvCustom210 = 210,
        RRiscvCustom211 = 211,
        RRiscvCustom212 = 212,
        RRiscvCustom213 = 213,
        RRiscvCustom214 = 214,
        RRiscvCustom215 = 215,
        RRiscvCustom216 = 216,
        RRiscvCustom217 = 217,
        RRiscvCustom219 = 219,
        RRiscvCustom220 = 220,
        RRiscvCustom221 = 221,
        RRiscvCustom222 = 222,
        RRiscvCustom223 = 223,
        RRiscvCustom224 = 224,
        RRiscvCustom225 = 225,
        RRiscvCustom226 = 226,
        RRiscvCustom227 = 227,
        RRiscvCustom228 = 228,
        RRiscvCustom229 = 229,
        RRiscvCustom230 = 230,
        RRiscvCustom231 = 231,
        RRiscvCustom232 = 232,
        RRiscvCustom233 = 233,
        RRiscvCustom234 = 234,
        RRiscvCustom235 = 235,
        RRiscvCustom236 = 236,
        RRiscvCustom237 = 237,
        RRiscvCustom238 = 238,
        RRiscvCustom239 = 239,
        RRiscvCustom240 = 240,
        RRiscvCustom241 = 241,
        RRiscvCustom242 = 242,
        RRiscvCustom243 = 243,
        RRiscvCustom244 = 244,
        RRiscvCustom245 = 245,
        RRiscvCustom246 = 246,
        RRiscvCustom247 = 247,
        RRiscvCustom253 = 253,
        RRiscvCustom254 = 254,
        RRiscvCustom255 = 255,
        RRiscvVendor = 191,
    }
    default 0;
}

lossless_enum! {
    /// ELF dynamic table tag.
    pub enum ElfDynamicTag: i64 {
        Null = 0,
        Needed = 1,
        PltRelSize = 2,
        PltGot = 3,
        Hash = 4,
        StringTable = 5,
        SymbolTable = 6,
        Rela = 7,
        RelaSize = 8,
        RelaEntrySize = 9,
        StringSize = 10,
        SymbolEntrySize = 11,
        Init = 12,
        Fini = 13,
        Soname = 14,
        Rpath = 15,
        Symbolic = 16,
        Rel = 17,
        RelSize = 18,
        RelEntrySize = 19,
        PltRel = 20,
        Debug = 21,
        TextRel = 22,
        JmpRel = 23,
        BindNow = 24,
        InitArray = 25,
        FiniArray = 26,
        InitArraySize = 27,
        FiniArraySize = 28,
        Runpath = 29,
        Flags = 30,
        Aarch64AuthRelr = 0x7000_0012,
        Aarch64AuthRelrent = 0x7000_0013,
        Aarch64AuthRelrsz = 0x7000_0011,
        Aarch64BtiPlt = 0x7000_0001,
        Aarch64MemtagGlobals = 0x7000_000d,
        Aarch64MemtagGlobalssz = 0x7000_000f,
        Aarch64MemtagHeap = 0x7000_000b,
        Aarch64MemtagMode = 0x7000_0009,
        Aarch64MemtagStack = 0x7000_000c,
        Aarch64PacPlt = 0x7000_0003,
        Aarch64VariantPcs = 0x7000_0005,
        AndroidRel = 0x6000_000f,
        AndroidRela = 0x6000_0011,
        AndroidRelasz = 0x6000_0012,
        AndroidRelr = 0x6fff_e000,
        AndroidRelrent = 0x6fff_e003,
        AndroidRelrsz = 0x6fff_e001,
        AndroidRelsz = 0x6000_0010,
        Auxiliary = 0x7fff_fffd,
        Crel = 0x4000_0026,
        Filter = 0x7fff_ffff,
        FiniArraysz = 28,
        Flags1 = 0x6fff_fffb,
        GnuHash = 0x6fff_fef5,
        HexagonPlt = 0x7000_0002,
        HexagonSymsz = 0x7000_0000,
        HexagonVer = 0x7000_0001,
        InitArraysz = 27,
        Jmprel = 23,
        MipsAuxDynamic = 0x7000_0031,
        MipsBaseAddress = 0x7000_0006,
        MipsCompactSize = 0x7000_002f,
        MipsConflict = 0x7000_0008,
        MipsConflictno = 0x7000_000b,
        MipsCxxFlags = 0x7000_0022,
        MipsDeltaClass = 0x7000_0017,
        MipsDeltaClasssym = 0x7000_0020,
        MipsDeltaClasssymNo = 0x7000_0021,
        MipsDeltaClassNo = 0x7000_0018,
        MipsDeltaInstance = 0x7000_0019,
        MipsDeltaInstanceNo = 0x7000_001a,
        MipsDeltaReloc = 0x7000_001b,
        MipsDeltaRelocNo = 0x7000_001c,
        MipsDeltaSym = 0x7000_001d,
        MipsDeltaSymNo = 0x7000_001e,
        MipsDynstrAlign = 0x7000_002b,
        MipsFlags = 0x7000_0005,
        MipsGotsym = 0x7000_0013,
        MipsGpValue = 0x7000_0030,
        MipsHiddenGotidx = 0x7000_0027,
        MipsHipageno = 0x7000_0014,
        MipsIchecksum = 0x7000_0003,
        MipsInterface = 0x7000_002a,
        MipsInterfaceSize = 0x7000_002c,
        MipsIversion = 0x7000_0004,
        MipsLiblist = 0x7000_0009,
        MipsLiblistno = 0x7000_0010,
        MipsLocalpageGotidx = 0x7000_0025,
        MipsLocalGotidx = 0x7000_0026,
        MipsLocalGotno = 0x7000_000a,
        MipsMsym = 0x7000_0007,
        MipsOptions = 0x7000_0029,
        MipsPerfSuffix = 0x7000_002e,
        MipsPixieInit = 0x7000_0023,
        MipsPltgot = 0x7000_0032,
        MipsProtectedGotidx = 0x7000_0028,
        MipsRldMap = 0x7000_0016,
        MipsRldMapRel = 0x7000_0035,
        MipsRldTextResolveAddr = 0x7000_002d,
        MipsRldVersion = 0x7000_0001,
        MipsRwplt = 0x7000_0034,
        MipsSymbolLib = 0x7000_0024,
        MipsSymtabno = 0x7000_0011,
        MipsTimeStamp = 0x7000_0002,
        MipsUnrefextno = 0x7000_0012,
        MipsXhash = 0x7000_0036,
        Pltgot = 3,
        Pltrel = 20,
        Pltrelsz = 2,
        Ppc64Glink = 0x7000_0000,
        Ppc64Opt = 0x7000_0003,
        PpcGot = 0x7000_0000,
        PpcOpt = 0x7000_0001,
        PreinitArray = 32,
        PreinitArraysz = 33,
        Relacount = 0x6fff_fff9,
        Relaent = 9,
        Relasz = 8,
        Relcount = 0x6fff_fffa,
        Relent = 19,
        Relr = 36,
        Relrent = 37,
        Relrsz = 35,
        Relsz = 18,
        RiscvVariantCc = 0x7000_0001,
        Strsz = 10,
        Strtab = 5,
        Syment = 11,
        Symtab = 6,
        SymtabShndx = 34,
        Textrel = 22,
        TlsdescGot = 0x6fff_fef7,
        TlsdescPlt = 0x6fff_fef6,
        Used = 0x7fff_fffe,
        Verdef = 0x6fff_fffc,
        Verdefnum = 0x6fff_fffd,
        Verneed = 0x6fff_fffe,
        Verneednum = 0x6fff_ffff,
        Versym = 0x6fff_fff0,
        ;
        Other(i64),
    }
    canonical {
        Null = 0,
        Needed = 1,
        PltRelSize = 2,
        PltGot = 3,
        Hash = 4,
        StringTable = 5,
        SymbolTable = 6,
        Rela = 7,
        RelaSize = 8,
        RelaEntrySize = 9,
        StringSize = 10,
        SymbolEntrySize = 11,
        Init = 12,
        Fini = 13,
        Soname = 14,
        Rpath = 15,
        Symbolic = 16,
        Rel = 17,
        RelSize = 18,
        RelEntrySize = 19,
        PltRel = 20,
        Debug = 21,
        TextRel = 22,
        JmpRel = 23,
        BindNow = 24,
        InitArray = 25,
        FiniArray = 26,
        InitArraySize = 27,
        FiniArraySize = 28,
        Runpath = 29,
        Flags = 30,
        Aarch64AuthRelr = 0x7000_0012,
        Aarch64AuthRelrent = 0x7000_0013,
        Aarch64AuthRelrsz = 0x7000_0011,
        Aarch64BtiPlt = 0x7000_0001,
        Aarch64MemtagGlobals = 0x7000_000d,
        Aarch64MemtagGlobalssz = 0x7000_000f,
        Aarch64MemtagHeap = 0x7000_000b,
        Aarch64MemtagMode = 0x7000_0009,
        Aarch64MemtagStack = 0x7000_000c,
        Aarch64PacPlt = 0x7000_0003,
        Aarch64VariantPcs = 0x7000_0005,
        AndroidRel = 0x6000_000f,
        AndroidRela = 0x6000_0011,
        AndroidRelasz = 0x6000_0012,
        AndroidRelr = 0x6fff_e000,
        AndroidRelrent = 0x6fff_e003,
        AndroidRelrsz = 0x6fff_e001,
        AndroidRelsz = 0x6000_0010,
        Auxiliary = 0x7fff_fffd,
        Crel = 0x4000_0026,
        Filter = 0x7fff_ffff,
        Flags1 = 0x6fff_fffb,
        GnuHash = 0x6fff_fef5,
        HexagonPlt = 0x7000_0002,
        HexagonSymsz = 0x7000_0000,
        MipsAuxDynamic = 0x7000_0031,
        MipsBaseAddress = 0x7000_0006,
        MipsCompactSize = 0x7000_002f,
        MipsConflict = 0x7000_0008,
        MipsCxxFlags = 0x7000_0022,
        MipsDeltaClass = 0x7000_0017,
        MipsDeltaClasssym = 0x7000_0020,
        MipsDeltaClasssymNo = 0x7000_0021,
        MipsDeltaClassNo = 0x7000_0018,
        MipsDeltaInstance = 0x7000_0019,
        MipsDeltaInstanceNo = 0x7000_001a,
        MipsDeltaReloc = 0x7000_001b,
        MipsDeltaRelocNo = 0x7000_001c,
        MipsDeltaSym = 0x7000_001d,
        MipsDeltaSymNo = 0x7000_001e,
        MipsDynstrAlign = 0x7000_002b,
        MipsGpValue = 0x7000_0030,
        MipsHiddenGotidx = 0x7000_0027,
        MipsHipageno = 0x7000_0014,
        MipsInterface = 0x7000_002a,
        MipsInterfaceSize = 0x7000_002c,
        MipsIversion = 0x7000_0004,
        MipsLiblistno = 0x7000_0010,
        MipsLocalpageGotidx = 0x7000_0025,
        MipsLocalGotidx = 0x7000_0026,
        MipsLocalGotno = 0x7000_000a,
        MipsMsym = 0x7000_0007,
        MipsOptions = 0x7000_0029,
        MipsPerfSuffix = 0x7000_002e,
        MipsPixieInit = 0x7000_0023,
        MipsPltgot = 0x7000_0032,
        MipsProtectedGotidx = 0x7000_0028,
        MipsRldMap = 0x7000_0016,
        MipsRldMapRel = 0x7000_0035,
        MipsRldTextResolveAddr = 0x7000_002d,
        MipsRwplt = 0x7000_0034,
        MipsSymbolLib = 0x7000_0024,
        MipsXhash = 0x7000_0036,
        PreinitArray = 32,
        PreinitArraysz = 33,
        Relacount = 0x6fff_fff9,
        Relcount = 0x6fff_fffa,
        Relr = 36,
        Relrent = 37,
        Relrsz = 35,
        SymtabShndx = 34,
        TlsdescGot = 0x6fff_fef7,
        TlsdescPlt = 0x6fff_fef6,
        Used = 0x7fff_fffe,
        Verdef = 0x6fff_fffc,
        Verdefnum = 0x6fff_fffd,
        Verneed = 0x6fff_fffe,
        Verneednum = 0x6fff_ffff,
        Versym = 0x6fff_fff0,
    }
    default 0;
}

lossless_enum! {
    /// ELF note type.
    pub enum ElfNoteType: u32 {
        X386Ioperm = 513,
        X386Tls = 512,
        AmdgpuMetadata = 32,
        AmdHsaCodeObjectVersion = 1,
        AmdHsaHsail = 2,
        AmdHsaIsaName = 11,
        AmdHsaIsaVersion = 3,
        AmdHsaMetadata = 10,
        AmdPalMetadata = 12,
        AndroidTypeIdent = 1,
        AndroidTypeKuser = 3,
        AndroidTypeMemtag = 4,
        Arch = 2,
        ArmFpmr = 1038,
        ArmGcs = 1040,
        ArmHwBreak = 1026,
        ArmHwWatch = 1027,
        ArmPacMask = 1030,
        ArmSsve = 1035,
        ArmSve = 1029,
        ArmTaggedAddrCtrl = 1033,
        ArmTls = 1025,
        ArmVfp = 1024,
        ArmZa = 1036,
        ArmZt = 1037,
        Auxv = 6,
        File = 0x4649_4c45,
        Fpregs = 12,
        Fpregset = 2,
        FreebsdAbiTag = 1,
        FreebsdArchTag = 3,
        FreebsdFctlAsgDisable = 32,
        FreebsdFctlAslrDisable = 1,
        FreebsdFctlLa48 = 16,
        FreebsdFctlProtmaxDisable = 2,
        FreebsdFctlStkgapDisable = 4,
        FreebsdFctlWxneeded = 8,
        FreebsdFeatureCtl = 4,
        FreebsdNoinitTag = 2,
        FreebsdProcstatAuxv = 16,
        FreebsdProcstatFiles = 9,
        FreebsdProcstatGroups = 11,
        FreebsdProcstatOsrel = 14,
        FreebsdProcstatProc = 8,
        FreebsdProcstatPsstrings = 15,
        FreebsdProcstatRlimit = 13,
        FreebsdProcstatUmask = 12,
        FreebsdProcstatVmmap = 10,
        FreebsdThrmisc = 7,
        GnuAbiTag = 1,
        GnuBuildAttributeFunc = 257,
        GnuBuildAttributeOpen = 256,
        GnuBuildId = 3,
        GnuGoldVersion = 4,
        GnuHwcap = 2,
        GnuPropertyType0 = 5,
        LlvmHwasanGlobals = 3,
        LlvmOpenmpOffloadProducer = 2,
        LlvmOpenmpOffloadProducerVersion = 3,
        LlvmOpenmpOffloadVersion = 1,
        Lwpsinfo = 17,
        Lwpstatus = 16,
        MemtagHeap = 4,
        MemtagLevelAsync = 1,
        MemtagLevelMask = 3,
        MemtagLevelNone = 0,
        MemtagLevelSync = 2,
        MemtagStack = 8,
        NetbsdcoreAuxv = 2,
        NetbsdcoreLwpstatus = 24,
        NetbsdcoreProcinfo = 1,
        OpenbsdAuxv = 11,
        OpenbsdFpregs = 21,
        OpenbsdProcinfo = 10,
        OpenbsdRegs = 20,
        OpenbsdWcookie = 23,
        OpenbsdXfpregs = 22,
        PpcDscr = 261,
        PpcEbb = 262,
        PpcPmu = 263,
        PpcPpr = 260,
        PpcTar = 259,
        PpcTmCdscr = 271,
        PpcTmCfpr = 265,
        PpcTmCgpr = 264,
        PpcTmCppr = 270,
        PpcTmCtar = 269,
        PpcTmCvmx = 266,
        PpcTmCvsx = 267,
        PpcTmSpr = 268,
        PpcVmx = 256,
        PpcVsx = 258,
        Prpsinfo = 3,
        Prstatus = 1,
        Prxfpreg = 0x46e6_2b7f,
        Psinfo = 13,
        Pstatus = 10,
        S390Ctrs = 772,
        S390GsBc = 780,
        S390GsCb = 779,
        S390HighGprs = 768,
        S390LastBreak = 774,
        S390Prefix = 773,
        S390SystemCall = 775,
        S390Tdb = 776,
        S390Timer = 769,
        S390Todcmp = 770,
        S390Todpreg = 771,
        S390VxrsHigh = 778,
        S390VxrsLow = 777,
        Siginfo = 0x5349_4749,
        Taskstruct = 4,
        Version = 1,
        Win32Pstatus = 18,
        X86Xstate = 514,
        ;
        Other(u32),
    }
    canonical {
        X386Ioperm = 513,
        X386Tls = 512,
        AmdgpuMetadata = 32,
        AmdHsaCodeObjectVersion = 1,
        AmdHsaHsail = 2,
        AmdHsaIsaName = 11,
        AmdHsaIsaVersion = 3,
        AmdHsaMetadata = 10,
        AmdPalMetadata = 12,
        AndroidTypeMemtag = 4,
        ArmFpmr = 1038,
        ArmGcs = 1040,
        ArmHwBreak = 1026,
        ArmHwWatch = 1027,
        ArmPacMask = 1030,
        ArmSsve = 1035,
        ArmSve = 1029,
        ArmTaggedAddrCtrl = 1033,
        ArmTls = 1025,
        ArmVfp = 1024,
        ArmZa = 1036,
        ArmZt = 1037,
        Auxv = 6,
        File = 0x4649_4c45,
        FreebsdFctlLa48 = 16,
        FreebsdFctlWxneeded = 8,
        FreebsdProcstatFiles = 9,
        FreebsdProcstatOsrel = 14,
        FreebsdProcstatPsstrings = 15,
        FreebsdProcstatRlimit = 13,
        FreebsdThrmisc = 7,
        GnuBuildAttributeFunc = 257,
        GnuBuildAttributeOpen = 256,
        GnuPropertyType0 = 5,
        Lwpsinfo = 17,
        MemtagLevelNone = 0,
        NetbsdcoreLwpstatus = 24,
        OpenbsdFpregs = 21,
        OpenbsdRegs = 20,
        OpenbsdWcookie = 23,
        OpenbsdXfpregs = 22,
        PpcDscr = 261,
        PpcEbb = 262,
        PpcPmu = 263,
        PpcPpr = 260,
        PpcTar = 259,
        PpcTmCdscr = 271,
        PpcTmCfpr = 265,
        PpcTmCgpr = 264,
        PpcTmCppr = 270,
        PpcTmCtar = 269,
        PpcTmCvmx = 266,
        PpcTmCvsx = 267,
        PpcTmSpr = 268,
        PpcVsx = 258,
        Prxfpreg = 0x46e6_2b7f,
        S390Ctrs = 772,
        S390GsBc = 780,
        S390GsCb = 779,
        S390HighGprs = 768,
        S390LastBreak = 774,
        S390Prefix = 773,
        S390SystemCall = 775,
        S390Tdb = 776,
        S390Timer = 769,
        S390Todcmp = 770,
        S390Todpreg = 771,
        S390VxrsHigh = 778,
        S390VxrsLow = 777,
        Siginfo = 0x5349_4749,
        Win32Pstatus = 18,
        X86Xstate = 514,
    }
    default 0;
}

lossless_enum! {
    /// `AArch64` pointer-authentication platform value.
    pub enum ElfAarch64PauthPlatform: u32 {
        Baremetal = 1,
        Invalid = 0,
        LlvmLinux = 0x1000_0002,
        LlvmLinuxVersionAuthtraps = 3,
        LlvmLinuxVersionCalls = 1,
        LlvmLinuxVersionFptrtypediscr = 11,
        LlvmLinuxVersionGot = 8,
        LlvmLinuxVersionGotos = 9,
        LlvmLinuxVersionInitfini = 6,
        LlvmLinuxVersionInitfiniaddrdisc = 7,
        LlvmLinuxVersionIntrinsics = 0,
        LlvmLinuxVersionReturns = 2,
        LlvmLinuxVersionTypeinfovptrdiscr = 10,
        LlvmLinuxVersionVptraddrdiscr = 4,
        LlvmLinuxVersionVptrtypediscr = 5,
        ;
        Other(u32),
    }
    canonical {
        Baremetal = 1,
        Invalid = 0,
        LlvmLinux = 0x1000_0002,
        LlvmLinuxVersionAuthtraps = 3,
        LlvmLinuxVersionFptrtypediscr = 11,
        LlvmLinuxVersionGot = 8,
        LlvmLinuxVersionGotos = 9,
        LlvmLinuxVersionInitfini = 6,
        LlvmLinuxVersionInitfiniaddrdisc = 7,
        LlvmLinuxVersionReturns = 2,
        LlvmLinuxVersionTypeinfovptrdiscr = 10,
        LlvmLinuxVersionVptraddrdiscr = 4,
        LlvmLinuxVersionVptrtypediscr = 5,
    }
    default 0;
}

lossless_enum! {
    /// ELF compressed-section algorithm.
    pub enum ElfCompressionType: u32 {
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Loos = 0x6000_0000,
        Loproc = 0x7000_0000,
        Zlib = 1,
        Zstd = 2,
        ;
        Other(u32),
    }
    canonical {
        Hios = 0x6fff_ffff,
        Hiproc = 0x7fff_ffff,
        Loos = 0x6000_0000,
        Loproc = 0x7000_0000,
        Zlib = 1,
        Zstd = 2,
    }
    default 0;
}

lossless_enum! {
    /// GNU ABI note operating-system tag.
    pub enum ElfGnuAbiTag: u32 {
        Freebsd = 3,
        Hurd = 1,
        Linux = 0,
        Nacl = 6,
        Netbsd = 4,
        Solaris = 2,
        Syllable = 5,
        ;
        Other(u32),
    }
    canonical {
        Freebsd = 3,
        Hurd = 1,
        Linux = 0,
        Nacl = 6,
        Netbsd = 4,
        Solaris = 2,
        Syllable = 5,
    }
    default 0;
}

lossless_enum! {
    /// GNU property note type or feature value.
    pub enum ElfGnuProperty: u32 {
        Aarch64Feature1And = 0xc000_0000,
        Aarch64Feature1Bti = 1,
        Aarch64Feature1Gcs = 4,
        Aarch64Feature1Pac = 2,
        Aarch64FeaturePauth = 0xc000_0001,
        NoCopyOnProtected = 2,
        StackSize = 1,
        X86Feature1And = 0xc000_0002,
        X86Feature1Ibt = 1,
        X86Feature1Shstk = 2,
        X86Feature2Fxsr = 64,
        X86Feature2Mmx = 4,
        X86Feature2Needed = 0xc000_8001,
        X86Feature2Used = 0xc001_0001,
        X86Feature2X86 = 1,
        X86Feature2X87 = 2,
        X86Feature2Xmm = 8,
        X86Feature2Xsave = 128,
        X86Feature2Xsavec = 512,
        X86Feature2Xsaveopt = 256,
        X86Feature2Ymm = 16,
        X86Feature2Zmm = 32,
        X86Isa1Baseline = 1,
        X86Isa1Needed = 0xc000_8002,
        X86Isa1Used = 0xc001_0002,
        X86Isa1V2 = 2,
        X86Isa1V3 = 4,
        X86Isa1V4 = 8,
        X86Uint32OrAndLo = 0xc001_0000,
        X86Uint32OrLo = 0xc000_8000,
        ;
        Other(u32),
    }
    canonical {
        Aarch64Feature1And = 0xc000_0000,
        Aarch64Feature1Bti = 1,
        Aarch64Feature1Gcs = 4,
        Aarch64Feature1Pac = 2,
        Aarch64FeaturePauth = 0xc000_0001,
        X86Feature1And = 0xc000_0002,
        X86Feature2Fxsr = 64,
        X86Feature2Needed = 0xc000_8001,
        X86Feature2Used = 0xc001_0001,
        X86Feature2Xmm = 8,
        X86Feature2Xsave = 128,
        X86Feature2Xsavec = 512,
        X86Feature2Xsaveopt = 256,
        X86Feature2Ymm = 16,
        X86Feature2Zmm = 32,
        X86Isa1Needed = 0xc000_8002,
        X86Isa1Used = 0xc001_0002,
        X86Uint32OrAndLo = 0xc001_0000,
        X86Uint32OrLo = 0xc000_8000,
    }
    default 0;
}

lossless_enum! {
    /// ELF symbol-version index or mask.
    pub enum ElfVersionIndex: u32 {
        Hidden = 0x8000,
        Version = 0x7fff,
        Global = 1,
        Local = 0,
        ;
        Other(u32),
    }
    canonical {
        Hidden = 0x8000,
        Version = 0x7fff,
        Global = 1,
        Local = 0,
    }
    default 0;
}

lossless_enum! {
    /// MIPS options descriptor kind.
    pub enum ElfMipsOptionKind: u64 {
        Exceptions = 2,
        Fill = 5,
        GpGroup = 9,
        Hwand = 7,
        Hwor = 8,
        Hwpatch = 4,
        Ident = 10,
        Null = 0,
        Pad = 3,
        Pagesize = 11,
        Reginfo = 1,
        Tags = 6,
        ;
        Other(u64),
    }
    canonical {
        Exceptions = 2,
        Fill = 5,
        GpGroup = 9,
        Hwand = 7,
        Hwor = 8,
        Hwpatch = 4,
        Ident = 10,
        Null = 0,
        Pad = 3,
        Pagesize = 11,
        Reginfo = 1,
        Tags = 6,
    }
    default 0;
}

lossless_enum! {
    /// MIPS runtime symbol table code.
    pub enum ElfMipsRuntimeSymbol: u64 {
        Gp = 1,
        Gp0 = 2,
        Loc = 3,
        Undef = 0,
        ;
        Other(u64),
    }
    canonical {
        Gp = 1,
        Gp0 = 2,
        Loc = 3,
        Undef = 0,
    }
    default 0;
}

lossless_enum! {
    /// ELF symbol entry size value.
    pub enum ElfSymbolEntrySize: u64 {
        X32 = 16,
        X64 = 24,
        ;
        Other(u64),
    }
    canonical {
        X32 = 16,
        X64 = 24,
    }
    default 0;
}

lossless_enum! {
    /// FDO note type value.
    pub enum ElfFdoNote: u64 {
        PackagingMetadata = 0xcafe_1a7e,
        ;
        Other(u64),
    }
    canonical {
        PackagingMetadata = 0xcafe_1a7e,
    }
    default 0;
}

bitflags! {
    /// ELF program header flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfSegmentFlags: u32 {
        const PF_MASKOS = 0xff0_0000;
        const PF_MASKPROC = 0xf000_0000;
        const PF_R = 4;
        const PF_W = 2;
        const PF_X = 1;
    }
}

impl ElfSegmentFlags {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.bits()
    }
}

impl From<u32> for ElfSegmentFlags {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF section header flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfSectionFlags: u64 {
        const SHF_ALLOC = 2;
        const SHF_ARM_PURECODE = 0x2000_0000;
        const SHF_COMPRESSED = 2048;
        const SHF_EXCLUDE = 0x8000_0000;
        const SHF_EXECINSTR = 4;
        const SHF_GNU_RETAIN = 0x20_0000;
        const SHF_GROUP = 512;
        const SHF_HEX_GPREL = 0x1000_0000;
        const SHF_INFO_LINK = 64;
        const SHF_LINK_ORDER = 128;
        const SHF_MASKOS = 0xff0_0000;
        const SHF_MASKPROC = 0xf000_0000;
        const SHF_MERGE = 16;
        const SHF_MIPS_ADDR = 0x4000_0000;
        const SHF_MIPS_GPREL = 0x1000_0000;
        const SHF_MIPS_LOCAL = 0x400_0000;
        const SHF_MIPS_MERGE = 0x2000_0000;
        const SHF_MIPS_NAMES = 0x200_0000;
        const SHF_MIPS_NODUPES = 0x100_0000;
        const SHF_MIPS_NOSTRIP = 0x800_0000;
        const SHF_MIPS_STRING = 0x8000_0000;
        const SHF_OS_NONCONFORMING = 256;
        const SHF_STRINGS = 32;
        const SHF_SUNW_NODISCARD = 0x10_0000;
        const SHF_TLS = 1024;
        const SHF_WRITE = 1;
        const SHF_X86_64_LARGE = 0x1000_0000;
        const XCORE_SHF_CP_SECTION = 0x2000_0000;
        const XCORE_SHF_DP_SECTION = 0x1000_0000;
    }
}

impl ElfSectionFlags {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.bits()
    }
}

impl From<u64> for ElfSectionFlags {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF dynamic-table flag values.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfDynamicFlags: u64 {
        const DF_1_CONFALT = 8192;
        const DF_1_DIRECT = 256;
        const DF_1_DISPRELDNE = 0x8000;
        const DF_1_DISPRELPND = 0x1_0000;
        const DF_1_EDITED = 0x20_0000;
        const DF_1_ENDFILTEE = 0x4000;
        const DF_1_GLOBAL = 2;
        const DF_1_GLOBAUDIT = 0x100_0000;
        const DF_1_GROUP = 4;
        const DF_1_IGNMULDEF = 0x4_0000;
        const DF_1_INITFIRST = 32;
        const DF_1_INTERPOSE = 1024;
        const DF_1_LOADFLTR = 16;
        const DF_1_NODEFLIB = 2048;
        const DF_1_NODELETE = 8;
        const DF_1_NODIRECT = 0x2_0000;
        const DF_1_NODUMP = 4096;
        const DF_1_NOHDR = 0x10_0000;
        const DF_1_NOKSYMS = 0x8_0000;
        const DF_1_NOOPEN = 64;
        const DF_1_NORELOC = 0x40_0000;
        const DF_1_NOW = 1;
        const DF_1_ORIGIN = 128;
        const DF_1_PIE = 0x800_0000;
        const DF_1_SINGLETON = 0x200_0000;
        const DF_1_SYMINTPOSE = 0x80_0000;
        const DF_1_TRANS = 512;
        const DF_BIND_NOW = 8;
        const DF_ORIGIN = 1;
        const DF_STATIC_TLS = 16;
        const DF_SYMBOLIC = 2;
        const DF_TEXTREL = 4;
    }
}

impl ElfDynamicFlags {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.bits()
    }
}

impl From<u64> for ElfDynamicFlags {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF section-group flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfGroupFlags: u32 {
        const GRP_COMDAT = 1;
        const GRP_MASKOS = 0xff0_0000;
        const GRP_MASKPROC = 0xf000_0000;
    }
}

impl ElfGroupFlags {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.bits()
    }
}

impl From<u32> for ElfGroupFlags {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF compressed relocation-group flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfRelocationGroupFlags: u32 {
        const RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;
    }
}

impl ElfRelocationGroupFlags {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.bits()
    }
}

impl From<u32> for ElfRelocationGroupFlags {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF file-header processor flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfHeaderFlags: u64 {
        const EF_AMDGPU_FEATURE_SRAMECC_ANY_V4 = 1024;
        const EF_AMDGPU_FEATURE_SRAMECC_OFF_V4 = 2048;
        const EF_AMDGPU_FEATURE_SRAMECC_ON_V4 = 3072;
        const EF_AMDGPU_FEATURE_SRAMECC_UNSUPPORTED_V4 = 0;
        const EF_AMDGPU_FEATURE_SRAMECC_V3 = 512;
        const EF_AMDGPU_FEATURE_SRAMECC_V4 = 3072;
        const EF_AMDGPU_FEATURE_TRAP_HANDLER_V2 = 2;
        const EF_AMDGPU_FEATURE_XNACK_ANY_V4 = 256;
        const EF_AMDGPU_FEATURE_XNACK_OFF_V4 = 512;
        const EF_AMDGPU_FEATURE_XNACK_ON_V4 = 768;
        const EF_AMDGPU_FEATURE_XNACK_UNSUPPORTED_V4 = 0;
        const EF_AMDGPU_FEATURE_XNACK_V2 = 1;
        const EF_AMDGPU_FEATURE_XNACK_V3 = 256;
        const EF_AMDGPU_FEATURE_XNACK_V4 = 768;
        const EF_AMDGPU_GENERIC_VERSION = 0xff00_0000;
        const EF_AMDGPU_GENERIC_VERSION_MAX = 255;
        const EF_AMDGPU_GENERIC_VERSION_MIN = 1;
        const EF_AMDGPU_GENERIC_VERSION_OFFSET = 24;
        const EF_AMDGPU_MACH = 255;
        const EF_AMDGPU_MACH_AMDGCN_FIRST = 32;
        const EF_AMDGPU_MACH_AMDGCN_GFX1010 = 51;
        const EF_AMDGPU_MACH_AMDGCN_GFX1011 = 52;
        const EF_AMDGPU_MACH_AMDGCN_GFX1012 = 53;
        const EF_AMDGPU_MACH_AMDGCN_GFX1013 = 66;
        const EF_AMDGPU_MACH_AMDGCN_GFX1030 = 54;
        const EF_AMDGPU_MACH_AMDGCN_GFX1031 = 55;
        const EF_AMDGPU_MACH_AMDGCN_GFX1032 = 56;
        const EF_AMDGPU_MACH_AMDGCN_GFX1033 = 57;
        const EF_AMDGPU_MACH_AMDGCN_GFX1034 = 62;
        const EF_AMDGPU_MACH_AMDGCN_GFX1035 = 61;
        const EF_AMDGPU_MACH_AMDGCN_GFX1036 = 69;
        const EF_AMDGPU_MACH_AMDGCN_GFX10_1_GENERIC = 82;
        const EF_AMDGPU_MACH_AMDGCN_GFX10_3_GENERIC = 83;
        const EF_AMDGPU_MACH_AMDGCN_GFX1100 = 65;
        const EF_AMDGPU_MACH_AMDGCN_GFX1101 = 70;
        const EF_AMDGPU_MACH_AMDGCN_GFX1102 = 71;
        const EF_AMDGPU_MACH_AMDGCN_GFX1103 = 68;
        const EF_AMDGPU_MACH_AMDGCN_GFX1150 = 67;
        const EF_AMDGPU_MACH_AMDGCN_GFX1151 = 74;
        const EF_AMDGPU_MACH_AMDGCN_GFX1152 = 85;
        const EF_AMDGPU_MACH_AMDGCN_GFX1153 = 88;
        const EF_AMDGPU_MACH_AMDGCN_GFX11_GENERIC = 84;
        const EF_AMDGPU_MACH_AMDGCN_GFX1200 = 72;
        const EF_AMDGPU_MACH_AMDGCN_GFX1201 = 78;
        const EF_AMDGPU_MACH_AMDGCN_GFX12_GENERIC = 89;
        const EF_AMDGPU_MACH_AMDGCN_GFX600 = 32;
        const EF_AMDGPU_MACH_AMDGCN_GFX601 = 33;
        const EF_AMDGPU_MACH_AMDGCN_GFX602 = 58;
        const EF_AMDGPU_MACH_AMDGCN_GFX700 = 34;
        const EF_AMDGPU_MACH_AMDGCN_GFX701 = 35;
        const EF_AMDGPU_MACH_AMDGCN_GFX702 = 36;
        const EF_AMDGPU_MACH_AMDGCN_GFX703 = 37;
        const EF_AMDGPU_MACH_AMDGCN_GFX704 = 38;
        const EF_AMDGPU_MACH_AMDGCN_GFX705 = 59;
        const EF_AMDGPU_MACH_AMDGCN_GFX801 = 40;
        const EF_AMDGPU_MACH_AMDGCN_GFX802 = 41;
        const EF_AMDGPU_MACH_AMDGCN_GFX803 = 42;
        const EF_AMDGPU_MACH_AMDGCN_GFX805 = 60;
        const EF_AMDGPU_MACH_AMDGCN_GFX810 = 43;
        const EF_AMDGPU_MACH_AMDGCN_GFX900 = 44;
        const EF_AMDGPU_MACH_AMDGCN_GFX902 = 45;
        const EF_AMDGPU_MACH_AMDGCN_GFX904 = 46;
        const EF_AMDGPU_MACH_AMDGCN_GFX906 = 47;
        const EF_AMDGPU_MACH_AMDGCN_GFX908 = 48;
        const EF_AMDGPU_MACH_AMDGCN_GFX909 = 49;
        const EF_AMDGPU_MACH_AMDGCN_GFX90A = 63;
        const EF_AMDGPU_MACH_AMDGCN_GFX90C = 50;
        const EF_AMDGPU_MACH_AMDGCN_GFX940 = 64;
        const EF_AMDGPU_MACH_AMDGCN_GFX941 = 75;
        const EF_AMDGPU_MACH_AMDGCN_GFX942 = 76;
        const EF_AMDGPU_MACH_AMDGCN_GFX950 = 79;
        const EF_AMDGPU_MACH_AMDGCN_GFX9_4_GENERIC = 95;
        const EF_AMDGPU_MACH_AMDGCN_GFX9_GENERIC = 81;
        const EF_AMDGPU_MACH_AMDGCN_LAST = 95;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X27 = 39;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X49 = 73;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X4D = 77;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X50 = 80;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X56 = 86;
        const EF_AMDGPU_MACH_AMDGCN_RESERVED_0X57 = 87;
        const EF_AMDGPU_MACH_NONE = 0;
        const EF_AMDGPU_MACH_R600_BARTS = 13;
        const EF_AMDGPU_MACH_R600_CAICOS = 14;
        const EF_AMDGPU_MACH_R600_CAYMAN = 15;
        const EF_AMDGPU_MACH_R600_CEDAR = 8;
        const EF_AMDGPU_MACH_R600_CYPRESS = 9;
        const EF_AMDGPU_MACH_R600_FIRST = 1;
        const EF_AMDGPU_MACH_R600_JUNIPER = 10;
        const EF_AMDGPU_MACH_R600_LAST = 16;
        const EF_AMDGPU_MACH_R600_R600 = 1;
        const EF_AMDGPU_MACH_R600_R630 = 2;
        const EF_AMDGPU_MACH_R600_REDWOOD = 11;
        const EF_AMDGPU_MACH_R600_RESERVED_FIRST = 17;
        const EF_AMDGPU_MACH_R600_RESERVED_LAST = 31;
        const EF_AMDGPU_MACH_R600_RS880 = 3;
        const EF_AMDGPU_MACH_R600_RV670 = 4;
        const EF_AMDGPU_MACH_R600_RV710 = 5;
        const EF_AMDGPU_MACH_R600_RV730 = 6;
        const EF_AMDGPU_MACH_R600_RV770 = 7;
        const EF_AMDGPU_MACH_R600_SUMO = 12;
        const EF_AMDGPU_MACH_R600_TURKS = 16;
        const EF_ARC_CPU_ARCV2EM = 5;
        const EF_ARC_CPU_ARCV2HS = 6;
        const EF_ARC_MACH_MSK = 255;
        const EF_ARC_OSABI_MSK = 3840;
        const EF_ARC_PIC = 256;
        const EF_ARM_ABI_FLOAT_HARD = 1024;
        const EF_ARM_ABI_FLOAT_SOFT = 512;
        const EF_ARM_BE8 = 0x80_0000;
        const EF_ARM_EABIMASK = 0xff00_0000;
        const EF_ARM_EABI_UNKNOWN = 0;
        const EF_ARM_EABI_VER1 = 0x100_0000;
        const EF_ARM_EABI_VER2 = 0x200_0000;
        const EF_ARM_EABI_VER3 = 0x300_0000;
        const EF_ARM_EABI_VER4 = 0x400_0000;
        const EF_ARM_EABI_VER5 = 0x500_0000;
        const EF_ARM_SOFT_FLOAT = 512;
        const EF_ARM_VFP_FLOAT = 1024;
        const EF_AVR_ARCH_AVR1 = 1;
        const EF_AVR_ARCH_AVR2 = 2;
        const EF_AVR_ARCH_AVR25 = 25;
        const EF_AVR_ARCH_AVR3 = 3;
        const EF_AVR_ARCH_AVR31 = 31;
        const EF_AVR_ARCH_AVR35 = 35;
        const EF_AVR_ARCH_AVR4 = 4;
        const EF_AVR_ARCH_AVR5 = 5;
        const EF_AVR_ARCH_AVR51 = 51;
        const EF_AVR_ARCH_AVR6 = 6;
        const EF_AVR_ARCH_AVRTINY = 100;
        const EF_AVR_ARCH_MASK = 127;
        const EF_AVR_ARCH_XMEGA1 = 101;
        const EF_AVR_ARCH_XMEGA2 = 102;
        const EF_AVR_ARCH_XMEGA3 = 103;
        const EF_AVR_ARCH_XMEGA4 = 104;
        const EF_AVR_ARCH_XMEGA5 = 105;
        const EF_AVR_ARCH_XMEGA6 = 106;
        const EF_AVR_ARCH_XMEGA7 = 107;
        const EF_AVR_LINKRELAX_PREPARED = 128;
        const EF_CSKY_800 = 31;
        const EF_CSKY_801 = 10;
        const EF_CSKY_802 = 16;
        const EF_CSKY_803 = 9;
        const EF_CSKY_805 = 17;
        const EF_CSKY_807 = 6;
        const EF_CSKY_810 = 8;
        const EF_CSKY_860 = 11;
        const EF_CSKY_ABIV2 = 0x2000_0000;
        const EF_CSKY_DSP = 0x4000;
        const EF_CSKY_EFV1 = 0x100_0000;
        const EF_CSKY_EFV2 = 0x200_0000;
        const EF_CSKY_EFV3 = 0x300_0000;
        const EF_CSKY_FLOAT = 8192;
        const EF_CUDA_64BIT_ADDRESS = 1024;
        const EF_CUDA_ACCELERATORS = 2048;
        const EF_CUDA_SM = 255;
        const EF_CUDA_SM20 = 20;
        const EF_CUDA_SM21 = 21;
        const EF_CUDA_SM30 = 30;
        const EF_CUDA_SM32 = 32;
        const EF_CUDA_SM35 = 35;
        const EF_CUDA_SM37 = 37;
        const EF_CUDA_SM50 = 50;
        const EF_CUDA_SM52 = 52;
        const EF_CUDA_SM53 = 53;
        const EF_CUDA_SM60 = 60;
        const EF_CUDA_SM61 = 61;
        const EF_CUDA_SM62 = 62;
        const EF_CUDA_SM70 = 70;
        const EF_CUDA_SM72 = 72;
        const EF_CUDA_SM75 = 75;
        const EF_CUDA_SM80 = 80;
        const EF_CUDA_SM86 = 86;
        const EF_CUDA_SM87 = 87;
        const EF_CUDA_SM89 = 89;
        const EF_CUDA_SM90 = 90;
        const EF_CUDA_SW_FLAG_V2 = 4096;
        const EF_CUDA_TEXMODE_INDEPENDANT = 512;
        const EF_CUDA_TEXMODE_UNIFIED = 256;
        const EF_CUDA_VIRTUAL_SM = 0xff_0000;
        const EF_HEXAGON_ISA = 1023;
        const EF_HEXAGON_ISA_MACH = 0;
        const EF_HEXAGON_ISA_V2 = 16;
        const EF_HEXAGON_ISA_V3 = 32;
        const EF_HEXAGON_ISA_V4 = 48;
        const EF_HEXAGON_ISA_V5 = 64;
        const EF_HEXAGON_ISA_V55 = 80;
        const EF_HEXAGON_ISA_V60 = 96;
        const EF_HEXAGON_ISA_V61 = 97;
        const EF_HEXAGON_ISA_V62 = 98;
        const EF_HEXAGON_ISA_V65 = 101;
        const EF_HEXAGON_ISA_V66 = 102;
        const EF_HEXAGON_ISA_V67 = 103;
        const EF_HEXAGON_ISA_V68 = 104;
        const EF_HEXAGON_ISA_V69 = 105;
        const EF_HEXAGON_ISA_V71 = 113;
        const EF_HEXAGON_ISA_V73 = 115;
        const EF_HEXAGON_ISA_V75 = 117;
        const EF_HEXAGON_ISA_V77 = 119;
        const EF_HEXAGON_ISA_V79 = 121;
        const EF_HEXAGON_ISA_V81 = 129;
        const EF_HEXAGON_ISA_V83 = 131;
        const EF_HEXAGON_ISA_V85 = 133;
        const EF_HEXAGON_MACH = 1023;
        const EF_HEXAGON_MACH_V2 = 1;
        const EF_HEXAGON_MACH_V3 = 2;
        const EF_HEXAGON_MACH_V4 = 3;
        const EF_HEXAGON_MACH_V5 = 4;
        const EF_HEXAGON_MACH_V55 = 5;
        const EF_HEXAGON_MACH_V60 = 96;
        const EF_HEXAGON_MACH_V61 = 97;
        const EF_HEXAGON_MACH_V62 = 98;
        const EF_HEXAGON_MACH_V65 = 101;
        const EF_HEXAGON_MACH_V66 = 102;
        const EF_HEXAGON_MACH_V67 = 103;
        const EF_HEXAGON_MACH_V67T = 0x8067;
        const EF_HEXAGON_MACH_V68 = 104;
        const EF_HEXAGON_MACH_V69 = 105;
        const EF_HEXAGON_MACH_V71 = 113;
        const EF_HEXAGON_MACH_V71T = 0x8071;
        const EF_HEXAGON_MACH_V73 = 115;
        const EF_HEXAGON_MACH_V75 = 117;
        const EF_HEXAGON_MACH_V77 = 119;
        const EF_HEXAGON_MACH_V79 = 121;
        const EF_HEXAGON_MACH_V81 = 129;
        const EF_HEXAGON_MACH_V83 = 131;
        const EF_HEXAGON_MACH_V85 = 133;
        const EF_LOONGARCH_ABI_DOUBLE_FLOAT = 3;
        const EF_LOONGARCH_ABI_MODIFIER_MASK = 7;
        const EF_LOONGARCH_ABI_SINGLE_FLOAT = 2;
        const EF_LOONGARCH_ABI_SOFT_FLOAT = 1;
        const EF_LOONGARCH_OBJABI_MASK = 192;
        const EF_LOONGARCH_OBJABI_V0 = 0;
        const EF_LOONGARCH_OBJABI_V1 = 64;
        const EF_MIPS_32BITMODE = 256;
        const EF_MIPS_ABI = 0xf000;
        const EF_MIPS_ABI2 = 32;
        const EF_MIPS_ABI_EABI32 = 0x3000;
        const EF_MIPS_ABI_EABI64 = 0x4000;
        const EF_MIPS_ABI_O32 = 4096;
        const EF_MIPS_ABI_O64 = 8192;
        const EF_MIPS_ARCH = 0xf000_0000;
        const EF_MIPS_ARCH_1 = 0;
        const EF_MIPS_ARCH_2 = 0x1000_0000;
        const EF_MIPS_ARCH_3 = 0x2000_0000;
        const EF_MIPS_ARCH_32 = 0x5000_0000;
        const EF_MIPS_ARCH_32R2 = 0x7000_0000;
        const EF_MIPS_ARCH_32R6 = 0x9000_0000;
        const EF_MIPS_ARCH_4 = 0x3000_0000;
        const EF_MIPS_ARCH_5 = 0x4000_0000;
        const EF_MIPS_ARCH_64 = 0x6000_0000;
        const EF_MIPS_ARCH_64R2 = 0x8000_0000;
        const EF_MIPS_ARCH_64R6 = 0xa000_0000;
        const EF_MIPS_ARCH_ASE = 0xf00_0000;
        const EF_MIPS_ARCH_ASE_M16 = 0x400_0000;
        const EF_MIPS_ARCH_ASE_MDMX = 0x800_0000;
        const EF_MIPS_CPIC = 4;
        const EF_MIPS_FP64 = 512;
        const EF_MIPS_MACH = 0xff_0000;
        const EF_MIPS_MACH_3900 = 0x81_0000;
        const EF_MIPS_MACH_4010 = 0x82_0000;
        const EF_MIPS_MACH_4100 = 0x83_0000;
        const EF_MIPS_MACH_4111 = 0x88_0000;
        const EF_MIPS_MACH_4120 = 0x87_0000;
        const EF_MIPS_MACH_4650 = 0x85_0000;
        const EF_MIPS_MACH_5400 = 0x91_0000;
        const EF_MIPS_MACH_5500 = 0x98_0000;
        const EF_MIPS_MACH_5900 = 0x92_0000;
        const EF_MIPS_MACH_9000 = 0x99_0000;
        const EF_MIPS_MACH_LS2E = 0xa0_0000;
        const EF_MIPS_MACH_LS2F = 0xa1_0000;
        const EF_MIPS_MACH_LS3A = 0xa2_0000;
        const EF_MIPS_MACH_NONE = 0;
        const EF_MIPS_MACH_OCTEON = 0x8b_0000;
        const EF_MIPS_MACH_OCTEON2 = 0x8d_0000;
        const EF_MIPS_MACH_OCTEON3 = 0x8e_0000;
        const EF_MIPS_MACH_SB1 = 0x8a_0000;
        const EF_MIPS_MACH_XLR = 0x8c_0000;
        const EF_MIPS_MICROMIPS = 0x200_0000;
        const EF_MIPS_NAN2008 = 1024;
        const EF_MIPS_NOREORDER = 1;
        const EF_MIPS_PIC = 2;
        const EF_MSP430_MACH_MSP430X = 45;
        const EF_PPC64_ABI = 3;
        const EF_RISCV_FLOAT_ABI = 6;
        const EF_RISCV_FLOAT_ABI_DOUBLE = 4;
        const EF_RISCV_FLOAT_ABI_QUAD = 6;
        const EF_RISCV_FLOAT_ABI_SINGLE = 2;
        const EF_RISCV_FLOAT_ABI_SOFT = 0;
        const EF_RISCV_RVC = 1;
        const EF_RISCV_RVE = 8;
        const EF_RISCV_TSO = 16;
        const EF_SPARCV9_MM = 3;
        const EF_SPARCV9_PSO = 1;
        const EF_SPARCV9_RMO = 2;
        const EF_SPARCV9_TSO = 0;
        const EF_SPARC_32PLUS = 256;
        const EF_SPARC_EXT_MASK = 0xff_ff00;
        const EF_SPARC_HAL_R1 = 1024;
        const EF_SPARC_SUN_US1 = 512;
        const EF_SPARC_SUN_US3 = 2048;
        const EF_XTENSA_MACH = 15;
        const EF_XTENSA_MACH_NONE = 0;
        const EF_XTENSA_XT_INSN = 256;
        const EF_XTENSA_XT_LIT = 512;
        const E_ARC_MACH_ARC600 = 2;
        const E_ARC_MACH_ARC601 = 4;
        const E_ARC_MACH_ARC700 = 3;
        const E_ARC_OSABI_ORIG = 0;
        const E_ARC_OSABI_V2 = 512;
        const E_ARC_OSABI_V3 = 768;
        const E_ARC_OSABI_V4 = 1024;
    }
}

impl ElfHeaderFlags {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.bits()
    }
}

impl From<u64> for ElfHeaderFlags {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// MIPS runtime flags.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfMipsRuntimeFlags: u64 {
        const RHF_CORD = 4096;
        const RHF_DEFAULT_DELAY_LOAD = 512;
        const RHF_DELTA_C_PLUS_PLUS = 64;
        const RHF_GUARANTEE_INIT = 32;
        const RHF_GUARANTEE_START_INIT = 128;
        const RHF_NONE = 0;
        const RHF_NOTPOT = 2;
        const RHF_NO_MOVE = 8;
        const RHF_NO_UNRES_UNDEF = 8192;
        const RHF_PIXIE = 256;
        const RHF_QUICKSTART = 1;
        const RHF_REQUICKSTART = 1024;
        const RHF_REQUICKSTARTED = 2048;
        const RHF_RLD_ORDER_SAFE = 0x4000;
        const RHF_SGI_ONLY = 16;
        const RHS_NO_LIBRARY_REPLACEMENT = 4;
    }
}

impl ElfMipsRuntimeFlags {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.bits()
    }
}

impl From<u64> for ElfMipsRuntimeFlags {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

bitflags! {
    /// ELF symbol-other flag values.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ElfSymbolOtherFlags: u64 {
        const STO_AARCH64_VARIANT_PCS = 128;
        const STO_MIPS_MICROMIPS = 128;
        const STO_MIPS_MIPS16 = 240;
        const STO_MIPS_OPTIONAL = 4;
        const STO_MIPS_PIC = 32;
        const STO_MIPS_PLT = 8;
        const STO_PPC64_LOCAL_BIT = 5;
        const STO_PPC64_LOCAL_MASK = 224;
        const STO_RISCV_VARIANT_CC = 128;
    }
}

impl ElfSymbolOtherFlags {
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self::from_bits_retain(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.bits()
    }
}

impl From<u64> for ElfSymbolOtherFlags {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

/// ELF identification bytes with decoded class and byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfIdent {
    pub class: PtrWidth,
    pub endian: Endianness,
    pub version: u8,
    pub os_abi: ElfOsAbi,
    pub abi_version: u8,
    pub padding: [u8; 7],
}

/// The decoded ELF file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    pub file_type: ElfType,
    pub machine: ElfMachine,
    pub version: u32,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count_raw: u16,
    pub section_header_entry_size: u16,
    pub section_header_count_raw: u16,
    pub section_name_table_index_raw: u16,
    pub program_header_count: u32,
    pub section_header_count: u32,
    pub section_name_table_index: Option<u32>,
}

/// One decoded ELF program header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfProgramHeader {
    pub index: u32,
    pub segment_type: ElfSegmentType,
    pub flags: ElfSegmentFlags,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

/// One decoded ELF section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSectionHeader {
    pub index: u32,
    pub name_offset: u32,
    pub name: Option<Vec<u8>>,
    pub section_type: ElfSectionType,
    pub flags: ElfSectionFlags,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub address_align: u64,
    pub entry_size: u64,
}

/// A section header paired with its file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    pub header_index: u32,
    pub data: Vec<u8>,
}

/// One decoded ELF symbol table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    pub table_section: u32,
    pub index: u32,
    pub name_offset: u32,
    pub name: Option<Vec<u8>>,
    pub bind: ElfSymbolBind,
    pub symbol_type: ElfSymbolType,
    pub other: u8,
    pub visibility: ElfSymbolVisibility,
    pub section_index: u32,
    pub value: u64,
    pub size: u64,
}

/// One decoded ELF relocation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfRelocation {
    pub table_section: u32,
    pub index: u32,
    pub offset: u64,
    pub symbol: u64,
    pub relocation_type: ElfRelocationType,
    pub info: u64,
    pub addend: Option<i64>,
}

/// Source table for a decoded dynamic entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfDynamicSource {
    Section(u32),
    ProgramHeader(u32),
}

/// One decoded ELF dynamic table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfDynamicEntry {
    pub source: ElfDynamicSource,
    pub index: u32,
    pub tag: ElfDynamicTag,
    pub value: u64,
}

/// Source table for a decoded ELF note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfNoteSource {
    Section(u32),
    ProgramHeader(u32),
}

/// One decoded ELF note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfNote {
    pub source: ElfNoteSource,
    pub index: u32,
    pub note_type: ElfNoteType,
    pub name: Vec<u8>,
    pub descriptor: Vec<u8>,
}

/// A lossless ELF-native representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile<'a> {
    pub ident: ElfIdent,
    pub header: ElfHeader,
    pub program_headers: Vec<ElfProgramHeader>,
    pub section_headers: Vec<ElfSectionHeader>,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub relocations: Vec<ElfRelocation>,
    pub dynamic_entries: Vec<ElfDynamicEntry>,
    pub notes: Vec<ElfNote>,
    bytes: Cow<'a, [u8]>,
}

impl<'a> ElfFile<'a> {
    /// Parses an ELF file into its native structure while preserving the original bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a structurally valid ELF file.
    #[expect(
        clippy::too_many_lines,
        reason = "ELF header parsing keeps the on-disk field order explicit"
    )]
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let ident = parse_ident(data)?;
        let mut r = ByteReader::new(body_after_ident(data)?, ident.endian);
        let file_type = ElfType::from_raw(r.read_u16()?);
        let machine = ElfMachine::from_raw(r.read_u16()?);
        let version = r.read_u32()?;
        if version != u32::from(ElfVersion::Current.raw()) {
            return Err(Error::Unsupported("ELF header version"));
        }
        let entry = read_addr(&mut r, ident.class)?;
        let program_header_offset = read_addr(&mut r, ident.class)?;
        let section_header_offset = read_addr(&mut r, ident.class)?;
        let flags = r.read_u32()?;
        let header_size = r.read_u16()?;
        let program_header_entry_size = r.read_u16()?;
        let program_header_count_raw = r.read_u16()?;
        let section_header_entry_size = r.read_u16()?;
        let section_header_count_raw = r.read_u16()?;
        let section_name_table_index_raw = r.read_u16()?;

        validate_entry_sizes(
            ident.class,
            header_size,
            program_header_count_raw,
            program_header_entry_size,
            section_header_count_raw,
            section_header_entry_size,
        )?;

        let first_section = read_first_section_header(
            data,
            ident.endian,
            ident.class,
            section_header_offset,
            section_header_entry_size,
        )?;
        let section_header_count = section_count(
            section_header_count_raw,
            section_header_offset,
            first_section.as_ref(),
        )?;
        let program_header_count = program_count(program_header_count_raw, first_section.as_ref())?;
        let section_name_table_index =
            section_name_index(section_name_table_index_raw, first_section.as_ref());

        let section_headers_result = read_section_headers(
            data,
            ident.endian,
            ident.class,
            section_header_offset,
            section_header_entry_size,
            section_header_count,
        );
        let mut section_headers = section_headers_result?;
        apply_section_names(data, &mut section_headers, section_name_table_index)?;
        let program_headers_result = read_program_headers(
            data,
            ident.endian,
            ident.class,
            program_header_offset,
            program_header_entry_size,
            program_header_count,
        );
        let program_headers = program_headers_result?;
        let sections = read_sections(data, &section_headers)?;
        let symbols = read_native_symbols(data, ident.endian, ident.class, &section_headers)?;
        let relocations =
            read_native_relocations(data, ident.endian, ident.class, &section_headers)?;
        let mut dynamic_entries =
            read_section_dynamic_entries(data, ident.endian, ident.class, &section_headers)?;
        let program_dynamic_entries_result =
            read_program_dynamic_entries(data, ident.endian, ident.class, &program_headers);
        let program_dynamic_entries = program_dynamic_entries_result?;
        dynamic_entries.extend(program_dynamic_entries);
        let mut notes = read_section_notes(data, ident.endian, &section_headers)?;
        notes.extend(read_program_notes(data, ident.endian, &program_headers)?);

        Ok(Self {
            ident,
            header: ElfHeader {
                file_type,
                machine,
                version,
                entry,
                program_header_offset,
                section_header_offset,
                flags,
                header_size,
                program_header_entry_size,
                program_header_count_raw,
                section_header_entry_size,
                section_header_count_raw,
                section_name_table_index_raw,
                program_header_count,
                section_header_count,
                section_name_table_index,
            },
            program_headers,
            section_headers,
            sections,
            symbols,
            relocations,
            dynamic_entries,
            notes,
            bytes: Cow::Borrowed(data),
        })
    }

    /// Returns the original ELF byte stream.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Consumes the file and returns the preserved byte stream.
    #[must_use]
    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        self.bytes
    }

    /// Serializes the file back to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored byte buffer is no longer a valid ELF image.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let reparsed = reparse_stored_bytes(self.bytes.as_ref())?;
        if reparsed.ident != self.ident || reparsed.header != self.header {
            return Err(Error::Malformed(
                "ELF native header changed without relayout",
            ));
        }
        Ok(self.bytes.as_ref().to_vec())
    }

    /// Projects this native ELF file into the format-neutral object model.
    ///
    /// # Errors
    ///
    /// Returns an error if the ELF contains names or references that cannot be represented in OIR.
    ///
    pub fn to_oir(&self) -> Result<ObjectModule> {
        let target = TargetSpec::new(
            machine_arch(self.header.machine.raw(), self.ident.class),
            self.ident.endian,
            self.ident.class,
        );
        let mut module = ObjectModule::new(BinaryFormat::Elf, target);
        if self.header.entry != 0 {
            module.set_entry(self.header.entry);
        }

        let mut section_ids = Vec::new();
        for header in self
            .section_headers
            .iter()
            .filter(|header| should_project_section(header.section_type))
        {
            let name = utf8_name(header.name.as_deref())?;
            let data = section_data(self, header.index)?;
            let name = module.intern(name)?;
            let section = Section {
                name,
                kind: classify_projected_section(module.resolve(name)?, header),
                address: header.address,
                align: header.address_align,
                flags: project_section_flags(header.flags),
                size: header.size,
                data,
            };
            let id = module.add_section(section)?;
            section_ids.push((header.index, id));
        }

        add_projected_segments(&mut module, self, &section_ids)?;
        let symbol_ids = add_projected_symbols(&mut module, self, &section_ids)?;
        add_projected_relocations(&mut module, self, &section_ids, &symbol_ids)?;
        Ok(module)
    }
}

impl ElfFile<'static> {
    /// Parses an owned ELF byte buffer into its native structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a structurally valid ELF file.
    pub fn parse_owned(bytes: Vec<u8>) -> Result<Self> {
        let parsed = ElfFile::parse(bytes.as_slice())?;
        let ElfFile {
            ident,
            header,
            program_headers,
            section_headers,
            sections,
            symbols,
            relocations,
            dynamic_entries,
            notes,
            bytes: _,
        } = parsed;
        Ok(Self {
            ident,
            header,
            program_headers,
            section_headers,
            sections,
            symbols,
            relocations,
            dynamic_entries,
            notes,
            bytes: Cow::Owned(bytes),
        })
    }

    /// Builds a native ELF file from an OIR module using the crate's canonical ELF emitter.
    ///
    /// # Errors
    ///
    /// Returns an error if the module cannot be represented as ELF.
    pub fn from_oir(module: &ObjectModule) -> Result<Self> {
        Self::parse_owned(crate::write::write(module)?)
    }
}

fn body_after_ident(data: &[u8]) -> Result<&[u8]> {
    data.get(EI_NIDENT..).ok_or(Error::UnexpectedEof {
        offset: EI_NIDENT,
        needed: 0,
        len: data.len(),
    })
}

fn reparse_stored_bytes(bytes: &[u8]) -> Result<ElfFile<'_>> {
    ElfFile::parse(bytes)
}

fn parse_ident(data: &[u8]) -> Result<ElfIdent> {
    let Some(
        &[
            m0,
            m1,
            m2,
            m3,
            class_raw,
            endian_raw,
            version,
            os_abi_raw,
            abi_version,
            p0,
            p1,
            p2,
            p3,
            p4,
            p5,
            p6,
        ],
    ) = data.get(..EI_NIDENT)
    else {
        return Err(Error::UnexpectedEof {
            offset: 0,
            needed: EI_NIDENT,
            len: data.len(),
        });
    };
    if [m0, m1, m2, m3] != MAGIC {
        return Err(Error::BadMagic);
    }
    let class = match ElfClass::from_raw(class_raw) {
        ElfClass::Class32 => PtrWidth::W32,
        ElfClass::Class64 => PtrWidth::W64,
        _ => return Err(Error::Unsupported("ELF class")),
    };
    let endian = match ElfDataEncoding::from_raw(endian_raw) {
        ElfDataEncoding::Little => Endianness::Little,
        ElfDataEncoding::Big => Endianness::Big,
        _ => return Err(Error::Unsupported("ELF data encoding")),
    };
    if version != ElfVersion::Current.raw() {
        return Err(Error::Unsupported("ELF version"));
    }
    Ok(ElfIdent {
        class,
        endian,
        version,
        os_abi: ElfOsAbi::from_raw(os_abi_raw),
        abi_version,
        padding: [p0, p1, p2, p3, p4, p5, p6],
    })
}

fn validate_entry_sizes(
    width: PtrWidth,
    header_size: u16,
    phnum: u16,
    phentsize: u16,
    shnum: u16,
    shentsize: u16,
) -> Result<()> {
    let expected_header = match width {
        PtrWidth::W32 => elf32::EHDR_SIZE,
        PtrWidth::W64 => elf64::EHDR_SIZE,
    };
    if u64::from(header_size) < expected_header {
        return Err(Error::Malformed("ELF header size"));
    }
    let program_entry_size = match width {
        PtrWidth::W32 => elf32::PHDR_SIZE,
        PtrWidth::W64 => elf64::PHDR_SIZE,
    };
    if phnum != 0 && u64::from(phentsize) < program_entry_size {
        return Err(Error::Malformed("ELF program header size"));
    }
    let section_entry_size = match width {
        PtrWidth::W32 => elf32::SHDR_SIZE,
        PtrWidth::W64 => elf64::SHDR_SIZE,
    };
    if shnum != 0 && u64::from(shentsize) < section_entry_size {
        return Err(Error::Malformed("ELF section header size"));
    }
    Ok(())
}

fn read_first_section_header(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    shoff: u64,
    shentsize: u16,
) -> Result<Option<ElfSectionHeader>> {
    if shoff == 0 || shentsize == 0 {
        return Ok(None);
    }
    Ok(Some(read_section_header(
        data,
        endian,
        width,
        shoff,
        u64::from(shentsize),
        0,
    )?))
}

fn section_count(raw: u16, shoff: u64, first: Option<&ElfSectionHeader>) -> Result<u32> {
    if raw != 0 {
        return Ok(u32::from(raw));
    }
    if shoff == 0 {
        return Ok(0);
    }
    let header = first.ok_or(Error::Malformed("extended section count"))?;
    u32::try_from(header.size).map_err(|_| Error::ValueOutOfRange("section count"))
}

fn program_count(raw: u16, first: Option<&ElfSectionHeader>) -> Result<u32> {
    if raw != PN_XNUM {
        return Ok(u32::from(raw));
    }
    first
        .map(|header| header.info)
        .ok_or(Error::Malformed("extended program header count"))
}

fn section_name_index(raw: u16, first: Option<&ElfSectionHeader>) -> Option<u32> {
    if raw == u16::MAX {
        return first.map(|header| header.link);
    }
    if raw == 0 { None } else { Some(u32::from(raw)) }
}

fn read_section_headers(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    shoff: u64,
    shentsize: u16,
    count: u32,
) -> Result<Vec<ElfSectionHeader>> {
    let mut headers = Vec::with_capacity(usize_from_u32(count)?);
    let entsize = u64::from(shentsize);
    for index in 0..count {
        let header_result = read_section_header(data, endian, width, shoff, entsize, index);
        let header = header_result?;
        headers.push(header);
    }
    Ok(headers)
}

fn read_section_header(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    shoff: u64,
    entsize: u64,
    index: u32,
) -> Result<ElfSectionHeader> {
    let offset = shoff
        .checked_add(u64::from(index) * entsize)
        .ok_or(Error::ValueOutOfRange("section header offset"))?;
    let min_size = match width {
        PtrWidth::W32 => elf32::SHDR_SIZE,
        PtrWidth::W64 => elf64::SHDR_SIZE,
    };
    let mut r = ByteReader::new(read_range(data, offset, min_size)?, endian);
    let name_offset = read_u32_field(&mut r)?;
    let section_type = ElfSectionType::from_raw(read_u32_field(&mut r)?);
    let flags;
    let address;
    let section_offset;
    let size;
    match width {
        PtrWidth::W32 => {
            flags = u64::from(read_u32_field(&mut r)?);
            address = u64::from(read_u32_field(&mut r)?);
            section_offset = u64::from(read_u32_field(&mut r)?);
            size = u64::from(read_u32_field(&mut r)?);
        }
        PtrWidth::W64 => {
            flags = read_u64_field(&mut r)?;
            address = read_u64_field(&mut r)?;
            section_offset = read_u64_field(&mut r)?;
            size = read_u64_field(&mut r)?;
        }
    }
    let link = read_u32_field(&mut r)?;
    let info = read_u32_field(&mut r)?;
    let address_align = read_word_field(&mut r, width)?;
    let entry_size = read_word_field(&mut r, width)?;
    Ok(ElfSectionHeader {
        index,
        name_offset,
        name: None,
        section_type,
        flags: ElfSectionFlags::from_raw(flags),
        address,
        offset: section_offset,
        size,
        link,
        info,
        address_align,
        entry_size,
    })
}

fn apply_section_names(
    data: &[u8],
    headers: &mut [ElfSectionHeader],
    shstrndx: Option<u32>,
) -> Result<()> {
    let Some(index) = shstrndx else {
        return Ok(());
    };
    let table = headers
        .iter()
        .find(|header| header.index == index)
        .ok_or(Error::Malformed("section name table index"))?;
    let bytes = read_range(data, table.offset, table.size)?;
    for header in headers {
        header.name = string_bytes(bytes, header.name_offset);
    }
    Ok(())
}

fn read_program_headers(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    phoff: u64,
    phentsize: u16,
    count: u32,
) -> Result<Vec<ElfProgramHeader>> {
    let mut headers = Vec::with_capacity(usize_from_u32(count)?);
    let min_size = match width {
        PtrWidth::W32 => elf32::PHDR_SIZE,
        PtrWidth::W64 => elf64::PHDR_SIZE,
    };
    for index in 0..count {
        let offset = phoff
            .checked_add(u64::from(index) * u64::from(phentsize))
            .ok_or(Error::ValueOutOfRange("program header offset"))?;
        let mut r = ByteReader::new(read_range(data, offset, min_size)?, endian);
        let segment_type;
        let flags;
        let file_offset;
        let virtual_address;
        let physical_address;
        let file_size;
        let memory_size;
        let align;
        match width {
            PtrWidth::W32 => {
                segment_type = read_u32_field(&mut r)?;
                file_offset = u64::from(read_u32_field(&mut r)?);
                virtual_address = u64::from(read_u32_field(&mut r)?);
                physical_address = u64::from(read_u32_field(&mut r)?);
                file_size = u64::from(read_u32_field(&mut r)?);
                memory_size = u64::from(read_u32_field(&mut r)?);
                flags = read_u32_field(&mut r)?;
                align = u64::from(read_u32_field(&mut r)?);
            }
            PtrWidth::W64 => {
                segment_type = read_u32_field(&mut r)?;
                flags = read_u32_field(&mut r)?;
                file_offset = read_u64_field(&mut r)?;
                virtual_address = read_u64_field(&mut r)?;
                physical_address = read_u64_field(&mut r)?;
                file_size = read_u64_field(&mut r)?;
                memory_size = read_u64_field(&mut r)?;
                align = read_u64_field(&mut r)?;
            }
        }
        headers.push(ElfProgramHeader {
            index,
            segment_type: ElfSegmentType::from_raw(segment_type),
            flags: ElfSegmentFlags::from_raw(flags),
            offset: file_offset,
            virtual_address,
            physical_address,
            file_size,
            memory_size,
            align,
        });
    }
    Ok(headers)
}

fn read_sections(data: &[u8], headers: &[ElfSectionHeader]) -> Result<Vec<ElfSection>> {
    let mut sections = Vec::with_capacity(headers.len());
    for header in headers {
        let data = if header.section_type == ElfSectionType::Nobits || header.size == 0 {
            Vec::new()
        } else {
            read_range(data, header.offset, header.size)?.to_vec()
        };
        sections.push(ElfSection {
            header_index: header.index,
            data,
        });
    }
    Ok(sections)
}

fn read_native_symbols(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    headers: &[ElfSectionHeader],
) -> Result<Vec<ElfSymbol>> {
    let mut symbols = Vec::new();
    for header in headers.iter().filter(|header| {
        header.section_type == ElfSectionType::Symtab
            || header.section_type == ElfSectionType::Dynsym
    }) {
        let strtab = linked_string_table(data, headers, header.link);
        let entsize = entry_size_or_default(header.entry_size, native_sym_size(width));
        require_entry_size(entsize, native_sym_size(width), "symbol entry size")?;
        let bytes = read_range(data, header.offset, header.size)?;
        let count = entry_count(header.size, entsize, "symbol table size")?;
        for index in 0..count {
            let entry = read_range(bytes, u64::from(index) * entsize, entsize)?;
            let symbol = read_native_symbol(entry, endian, width, header.index, index, strtab)?;
            symbols.push(symbol);
        }
    }
    Ok(symbols)
}

fn read_native_symbol(
    entry: &[u8],
    endian: Endianness,
    width: PtrWidth,
    table_section: u32,
    index: u32,
    strtab: Option<&[u8]>,
) -> Result<ElfSymbol> {
    let mut r = ByteReader::new(entry, endian);
    let name_offset;
    let info;
    let other;
    let section_index;
    let value;
    let size;
    match width {
        PtrWidth::W32 => {
            name_offset = read_u32_field(&mut r)?;
            value = u64::from(read_u32_field(&mut r)?);
            size = u64::from(read_u32_field(&mut r)?);
            info = read_u8_field(&mut r)?;
            other = read_u8_field(&mut r)?;
            section_index = u32::from(read_u16_field(&mut r)?);
        }
        PtrWidth::W64 => {
            name_offset = read_u32_field(&mut r)?;
            info = read_u8_field(&mut r)?;
            other = read_u8_field(&mut r)?;
            section_index = u32::from(read_u16_field(&mut r)?);
            value = read_u64_field(&mut r)?;
            size = read_u64_field(&mut r)?;
        }
    }
    Ok(ElfSymbol {
        table_section,
        index,
        name_offset,
        name: strtab.and_then(|table| string_bytes(table, name_offset)),
        bind: ElfSymbolBind::from_raw(info >> 4),
        symbol_type: ElfSymbolType::from_raw(info & 0x0f),
        other,
        visibility: ElfSymbolVisibility::from_raw(other & 0x03),
        section_index,
        value,
        size,
    })
}

fn read_native_relocations(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    headers: &[ElfSectionHeader],
) -> Result<Vec<ElfRelocation>> {
    let mut relocations = Vec::new();
    for header in headers.iter().filter(|header| {
        header.section_type == ElfSectionType::Rel || header.section_type == ElfSectionType::Rela
    }) {
        let default_size = native_relocation_size(header.section_type, width);
        let entsize = entry_size_or_default(header.entry_size, default_size);
        require_entry_size(entsize, default_size, "relocation entry size")?;
        let bytes = read_range(data, header.offset, header.size)?;
        let count = entry_count(header.size, entsize, "relocation table size")?;
        for index in 0..count {
            let entry = read_range(bytes, u64::from(index) * entsize, entsize)?;
            let relocation_result = read_native_relocation(
                entry,
                endian,
                width,
                header.section_type,
                header.index,
                index,
            );
            relocations.push(relocation_result?);
        }
    }
    Ok(relocations)
}

fn read_native_relocation(
    entry: &[u8],
    endian: Endianness,
    width: PtrWidth,
    section_type: ElfSectionType,
    table_section: u32,
    index: u32,
) -> Result<ElfRelocation> {
    let mut r = ByteReader::new(entry, endian);
    let offset;
    let info;
    let addend;
    match width {
        PtrWidth::W32 => {
            offset = u64::from(read_u32_field(&mut r)?);
            info = u64::from(read_u32_field(&mut r)?);
            addend = if section_type == ElfSectionType::Rela {
                Some(i64::from(i32::from_ne_bytes(
                    read_u32_field(&mut r)?.to_ne_bytes(),
                )))
            } else {
                None
            };
        }
        PtrWidth::W64 => {
            offset = read_u64_field(&mut r)?;
            info = read_u64_field(&mut r)?;
            addend = if section_type == ElfSectionType::Rela {
                Some(i64::from_ne_bytes(read_u64_field(&mut r)?.to_ne_bytes()))
            } else {
                None
            };
        }
    }
    let (symbol, typ) = split_relocation_info(width, info);
    Ok(ElfRelocation {
        table_section,
        index,
        offset,
        symbol,
        relocation_type: ElfRelocationType::from_raw(typ),
        info,
        addend,
    })
}

fn read_section_dynamic_entries(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    headers: &[ElfSectionHeader],
) -> Result<Vec<ElfDynamicEntry>> {
    let mut entries = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.section_type == ElfSectionType::Dynamic)
    {
        let parsed_result = read_dynamic_entries(
            read_range(data, header.offset, header.size)?,
            endian,
            width,
            ElfDynamicSource::Section(header.index),
        );
        let parsed = parsed_result?;
        entries.extend(parsed);
    }
    Ok(entries)
}

fn read_program_dynamic_entries(
    data: &[u8],
    endian: Endianness,
    width: PtrWidth,
    headers: &[ElfProgramHeader],
) -> Result<Vec<ElfDynamicEntry>> {
    let mut entries = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.segment_type == ElfSegmentType::Dynamic)
    {
        let parsed_result = read_dynamic_entries(
            read_range(data, header.offset, header.file_size)?,
            endian,
            width,
            ElfDynamicSource::ProgramHeader(header.index),
        );
        let parsed = parsed_result?;
        entries.extend(parsed);
    }
    Ok(entries)
}

fn read_dynamic_entries(
    bytes: &[u8],
    endian: Endianness,
    width: PtrWidth,
    source: ElfDynamicSource,
) -> Result<Vec<ElfDynamicEntry>> {
    let entsize = match width {
        PtrWidth::W32 => 8,
        PtrWidth::W64 => 16,
    };
    let count_result = entry_count(u64_len(bytes)?, entsize, "dynamic table size");
    let count = count_result?;
    let mut entries = Vec::with_capacity(usize_from_u32(count)?);
    for index in 0..count {
        let entry = read_range(bytes, u64::from(index) * entsize, entsize)?;
        let mut r = ByteReader::new(entry, endian);
        let tag = match width {
            PtrWidth::W32 => i64::from(i32::from_ne_bytes(read_u32_field(&mut r)?.to_ne_bytes())),
            PtrWidth::W64 => i64::from_ne_bytes(read_u64_field(&mut r)?.to_ne_bytes()),
        };
        let value = read_word_field(&mut r, width)?;
        entries.push(ElfDynamicEntry {
            source,
            index,
            tag: ElfDynamicTag::from_raw(tag),
            value,
        });
    }
    Ok(entries)
}

fn read_section_notes(
    data: &[u8],
    endian: Endianness,
    headers: &[ElfSectionHeader],
) -> Result<Vec<ElfNote>> {
    let mut notes = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.section_type == ElfSectionType::Note)
    {
        let parsed_result = read_notes(
            read_range(data, header.offset, header.size)?,
            endian,
            ElfNoteSource::Section(header.index),
        );
        let parsed = parsed_result?;
        notes.extend(parsed);
    }
    Ok(notes)
}

fn read_program_notes(
    data: &[u8],
    endian: Endianness,
    headers: &[ElfProgramHeader],
) -> Result<Vec<ElfNote>> {
    let mut notes = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.segment_type == ElfSegmentType::Note)
    {
        let parsed_result = read_notes(
            read_range(data, header.offset, header.file_size)?,
            endian,
            ElfNoteSource::ProgramHeader(header.index),
        );
        let parsed = parsed_result?;
        notes.extend(parsed);
    }
    Ok(notes)
}

fn read_notes(bytes: &[u8], endian: Endianness, source: ElfNoteSource) -> Result<Vec<ElfNote>> {
    let mut offset = 0_u64;
    let mut index = 0_u32;
    let mut notes = Vec::new();
    let byte_len = u64_len(bytes)?;
    while offset < byte_len {
        let mut r = ByteReader::new(read_range(bytes, offset, 12)?, endian);
        let namesz = u64::from(read_u32_field(&mut r)?);
        let descsz = u64::from(read_u32_field(&mut r)?);
        let note_type = read_u32_field(&mut r)?;
        offset = offset
            .checked_add(12)
            .ok_or(Error::ValueOutOfRange("note header offset"))?;
        let name = read_range(bytes, offset, namesz)?.to_vec();
        offset = align_up(
            offset
                .checked_add(namesz)
                .ok_or(Error::ValueOutOfRange("note name offset"))?,
            4,
        );
        let descriptor = read_range(bytes, offset, descsz)?.to_vec();
        offset = align_up(
            offset
                .checked_add(descsz)
                .ok_or(Error::ValueOutOfRange("note descriptor offset"))?,
            4,
        );
        notes.push(ElfNote {
            source,
            index,
            note_type: ElfNoteType::from_raw(note_type),
            name,
            descriptor,
        });
        index = index
            .checked_add(1)
            .ok_or(Error::ValueOutOfRange("note count"))?;
    }
    Ok(notes)
}

fn linked_string_table<'a>(
    data: &'a [u8],
    headers: &[ElfSectionHeader],
    index: u32,
) -> Option<&'a [u8]> {
    let header = headers.iter().find(|header| header.index == index)?;
    if header.section_type != ElfSectionType::Strtab {
        return None;
    }
    read_range(data, header.offset, header.size).ok()
}

fn string_bytes(table: &[u8], offset: u32) -> Option<Vec<u8>> {
    let start = usize::try_from(offset).ok()?;
    let rest = table.get(start..)?;
    let len = rest.iter().position(|byte| *byte == 0)?;
    Some(rest.get(..len)?.to_vec())
}

fn read_range(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let start = usize_from_u64(offset, "range offset")?;
    let count = usize_from_u64(size, "range size")?;
    let end = start
        .checked_add(count)
        .ok_or(Error::ValueOutOfRange("range end"))?;
    data.get(start..end).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: count,
        len: data.len(),
    })
}

fn u64_len(bytes: &[u8]) -> Result<u64> {
    u64::try_from(bytes.len()).map_err(|_| Error::ValueOutOfRange("slice length"))
}

fn read_addr(r: &mut ByteReader<'_>, width: PtrWidth) -> Result<u64> {
    match width {
        PtrWidth::W32 => Ok(u64::from(r.read_u32()?)),
        PtrWidth::W64 => r.read_u64(),
    }
}

fn read_u8_field(r: &mut ByteReader<'_>) -> Result<u8> {
    r.read_u8()
}

fn read_u16_field(r: &mut ByteReader<'_>) -> Result<u16> {
    r.read_u16()
}

fn read_u32_field(r: &mut ByteReader<'_>) -> Result<u32> {
    r.read_u32()
}

fn read_u64_field(r: &mut ByteReader<'_>) -> Result<u64> {
    r.read_u64()
}

fn read_word_field(r: &mut ByteReader<'_>, width: PtrWidth) -> Result<u64> {
    match width {
        PtrWidth::W32 => Ok(u64::from(read_u32_field(r)?)),
        PtrWidth::W64 => read_u64_field(r),
    }
}

const fn native_sym_size(width: PtrWidth) -> u64 {
    match width {
        PtrWidth::W32 => elf32::SYM_SIZE,
        PtrWidth::W64 => elf64::SYM_SIZE,
    }
}

const fn native_relocation_size(section_type: ElfSectionType, width: PtrWidth) -> u64 {
    match (section_type, width) {
        (ElfSectionType::Rel, PtrWidth::W32) => elf32::REL_SIZE,
        (ElfSectionType::Rel, PtrWidth::W64) => elf64::REL_SIZE,
        (ElfSectionType::Rela, PtrWidth::W32) => elf32::RELA_SIZE,
        (ElfSectionType::Rela, PtrWidth::W64) => elf64::RELA_SIZE,
        _ => 0,
    }
}

const fn entry_size_or_default(raw: u64, default: u64) -> u64 {
    if raw == 0 { default } else { raw }
}

fn require_entry_size(actual: u64, expected: u64, what: &'static str) -> Result<()> {
    if actual < expected {
        return Err(Error::Malformed(what));
    }
    Ok(())
}

fn entry_count(size: u64, entsize: u64, what: &'static str) -> Result<u32> {
    if entsize == 0 || !size.is_multiple_of(entsize) {
        return Err(Error::Malformed(what));
    }
    match u32::try_from(size / entsize) {
        Ok(count) => Ok(count),
        Err(_) => Err(Error::ValueOutOfRange(what)),
    }
}

fn split_relocation_info(width: PtrWidth, info: u64) -> (u64, u32) {
    match width {
        PtrWidth::W32 => (info >> 8, (info & 0xff) as u32),
        PtrWidth::W64 => (info >> 32, (info & 0xffff_ffff) as u32),
    }
}

const fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn usize_from_u64(value: u64, what: &'static str) -> Result<usize> {
    usize_from_u64_with_max(value, what, usize::MAX as u64)
}

fn usize_from_u64_with_max(value: u64, what: &'static str, max: u64) -> Result<usize> {
    if value > max {
        return Err(Error::ValueOutOfRange(what));
    }
    usize::try_from(value).or(Err(Error::ValueOutOfRange(what)))
}

fn usize_from_u32(value: u32) -> Result<usize> {
    usize_from_u64(u64::from(value), "u32 count")
}

fn machine_arch(machine: u16, width: PtrWidth) -> Architecture {
    match ElfMachine::from_raw(machine) {
        ElfMachine::X86 => Architecture::X86,
        ElfMachine::X86_64 => Architecture::X86_64,
        ElfMachine::Arm => Architecture::Arm,
        ElfMachine::Aarch64 => Architecture::Aarch64,
        ElfMachine::Riscv => Architecture::Riscv64,
        ElfMachine::PowerPc => Architecture::PowerPc,
        ElfMachine::PowerPc64 => Architecture::PowerPc64,
        ElfMachine::S390 => Architecture::S390x,
        ElfMachine::Mips => match width {
            PtrWidth::W32 => Architecture::Mips,
            PtrWidth::W64 => Architecture::Mips64,
        },
        ElfMachine::LoongArch => Architecture::LoongArch64,
        ElfMachine::SparcV9 => Architecture::Sparc64,
        other => Architecture::Other(u32::from(other.raw())),
    }
}

fn should_project_section(section_type: ElfSectionType) -> bool {
    section_type != ElfSectionType::Null
        && section_type != ElfSectionType::Strtab
        && section_type != ElfSectionType::Symtab
        && section_type != ElfSectionType::Dynsym
        && section_type != ElfSectionType::Rela
        && section_type != ElfSectionType::Rel
}

fn utf8_name(name: Option<&[u8]>) -> Result<&str> {
    let bytes = name.ok_or(Error::Malformed("missing ELF name"))?;
    core::str::from_utf8(bytes).map_err(|_| Error::Malformed("ELF name is not UTF-8"))
}

fn section_data(file: &ElfFile, header_index: u32) -> Result<Vec<u8>> {
    file.sections
        .iter()
        .find(|section| section.header_index == header_index)
        .map(|section| section.data.clone())
        .ok_or(Error::Malformed("section data"))
}

fn classify_projected_section(name: &str, header: &ElfSectionHeader) -> SectionKind {
    if header.section_type == ElfSectionType::Nobits {
        return SectionKind::Bss;
    }
    if header.flags.contains(ElfSectionFlags::SHF_EXECINSTR) {
        return SectionKind::Text;
    }
    if header.flags.contains(ElfSectionFlags::SHF_ALLOC)
        && header.flags.contains(ElfSectionFlags::SHF_WRITE)
    {
        return SectionKind::Data;
    }
    if header.flags.contains(ElfSectionFlags::SHF_ALLOC) {
        return SectionKind::ReadOnlyData;
    }
    if name.starts_with(".debug") {
        return SectionKind::Debug;
    }
    SectionKind::Other
}

fn project_section_flags(flags: ElfSectionFlags) -> SectionFlags {
    SectionFlags {
        read: flags.contains(ElfSectionFlags::SHF_ALLOC),
        write: flags.contains(ElfSectionFlags::SHF_WRITE),
        execute: flags.contains(ElfSectionFlags::SHF_EXECINSTR),
    }
}

fn add_projected_segments(
    module: &mut ObjectModule,
    file: &ElfFile,
    section_ids: &[(u32, SectionId)],
) -> Result<()> {
    for phdr in file
        .program_headers
        .iter()
        .filter(|phdr| phdr.segment_type == ElfSegmentType::Load)
    {
        if phdr.file_size > phdr.memory_size {
            return Err(Error::Malformed("segment file size exceeds memory size"));
        }
        let end = phdr
            .virtual_address
            .checked_add(phdr.memory_size)
            .ok_or(Error::ValueOutOfRange("segment end"))?;
        let mut sections = Vec::new();
        for (shndx, id) in section_ids {
            let Some(header) = file
                .section_headers
                .iter()
                .find(|header| header.index == *shndx)
            else {
                continue;
            };
            let section_end = header
                .address
                .checked_add(header.size)
                .ok_or(Error::ValueOutOfRange("section end"))?;
            if header.address >= phdr.virtual_address
                && section_end <= end
                && header.flags.contains(ElfSectionFlags::SHF_ALLOC)
            {
                sections.push(*id);
            }
        }
        let name = module.intern("PT_LOAD")?;
        module.add_segment(Segment {
            name,
            address: phdr.virtual_address,
            vm_size: phdr.memory_size,
            flags: SectionFlags {
                read: phdr.flags.contains(ElfSegmentFlags::PF_R),
                write: phdr.flags.contains(ElfSegmentFlags::PF_W),
                execute: phdr.flags.contains(ElfSegmentFlags::PF_X),
            },
            sections,
        });
    }
    Ok(())
}

fn add_projected_symbols(
    module: &mut ObjectModule,
    file: &ElfFile,
    section_ids: &[(u32, SectionId)],
) -> Result<Vec<(u32, u32, SymbolId)>> {
    let mut ids = Vec::new();
    for symbol in file.symbols.iter().filter(|symbol| symbol.index != 0) {
        let name = utf8_name(symbol.name.as_deref()).unwrap_or("");
        let undefined = symbol.section_index == ElfSectionIndex::Undef.raw();
        let section = if undefined {
            None
        } else {
            section_ids
                .iter()
                .find_map(|(idx, id)| (*idx == symbol.section_index).then_some(*id))
        };
        let entry = SymbolEntry {
            name: module.intern(name)?,
            value: symbol.value,
            size: symbol.size,
            section,
            kind: project_symbol_kind(symbol.symbol_type.raw()),
            binding: project_symbol_binding(symbol.bind.raw()),
            flags: SymbolFlags {
                undefined,
                imported: false,
                exported: false,
            },
        };
        let id = module.add_symbol(entry)?;
        ids.push((symbol.table_section, symbol.index, id));
    }
    Ok(ids)
}

const fn project_symbol_kind(raw: u8) -> SymbolKind {
    match raw {
        1 => SymbolKind::Object,
        2 => SymbolKind::Function,
        3 => SymbolKind::Section,
        _ => SymbolKind::None,
    }
}

const fn project_symbol_binding(raw: u8) -> SymbolBinding {
    match raw {
        1 => SymbolBinding::Global,
        2 => SymbolBinding::Weak,
        _ => SymbolBinding::Local,
    }
}

fn add_projected_relocations(
    module: &mut ObjectModule,
    file: &ElfFile,
    section_ids: &[(u32, SectionId)],
    symbol_ids: &[(u32, u32, SymbolId)],
) -> Result<()> {
    for reloc in &file.relocations {
        let Some(table) = find_section_header(&file.section_headers, reloc.table_section) else {
            return Err(Error::Malformed("relocation table section"));
        };
        let Some(section) = find_projected_section(section_ids, table.info) else {
            return Err(Error::Malformed("relocation target section"));
        };
        let Ok(symbol_index) = u32::try_from(reloc.symbol) else {
            return Err(Error::ValueOutOfRange("relocation symbol"));
        };
        let Some(symbol) = find_projected_symbol(symbol_ids, table.link, symbol_index) else {
            return Err(Error::Malformed("relocation symbol"));
        };
        let relocation = Relocation {
            section,
            offset: reloc.offset,
            symbol,
            kind: project_relocation_kind(module.target().arch, reloc.relocation_type.raw()),
            addend: reloc.addend.unwrap_or(0),
        };
        module.add_relocation(relocation)?;
    }
    Ok(())
}

#[expect(
    clippy::manual_find,
    reason = "iterator find generates a separate closure in llvm-cov function coverage"
)]
fn find_section_header(headers: &[ElfSectionHeader], index: u32) -> Option<&ElfSectionHeader> {
    for header in headers {
        if header.index == index {
            return Some(header);
        }
    }
    None
}

fn find_projected_section(section_ids: &[(u32, SectionId)], index: u32) -> Option<SectionId> {
    for (idx, id) in section_ids {
        if *idx == index {
            return Some(*id);
        }
    }
    None
}

fn find_projected_symbol(
    symbol_ids: &[(u32, u32, SymbolId)],
    table_index: u32,
    symbol_index: u32,
) -> Option<SymbolId> {
    for (table_section, index, id) in symbol_ids {
        if *table_section == table_index && *index == symbol_index {
            return Some(*id);
        }
    }
    None
}

#[expect(
    clippy::match_same_arms,
    reason = "ELF relocation numbers intentionally collapse onto neutral relocation kinds"
)]
const fn project_relocation_kind(arch: Architecture, typ: u32) -> RelocKind {
    match (arch, typ) {
        (Architecture::X86_64, 1) => RelocKind::Absolute64,
        (Architecture::X86_64, 2) => RelocKind::Relative32,
        (Architecture::X86_64, 4) => RelocKind::PltRelative,
        (Architecture::X86_64, 9) => RelocKind::GotRelative,
        (Architecture::X86, 1) => RelocKind::Absolute32,
        (Architecture::X86, 2) => RelocKind::Relative32,
        (Architecture::Aarch64, 257) => RelocKind::Absolute64,
        (Architecture::Aarch64, 258) => RelocKind::Absolute32,
        (Architecture::Aarch64, 261) => RelocKind::Relative32,
        (Architecture::Arm, 2) => RelocKind::Absolute32,
        (Architecture::Arm, 3) => RelocKind::Relative32,
        (Architecture::Riscv64, 2) => RelocKind::Absolute64,
        (Architecture::Riscv64, 39) => RelocKind::Relative32,
        (Architecture::PowerPc64, 38) => RelocKind::Absolute64,
        (Architecture::PowerPc | Architecture::PowerPc64, 1) => RelocKind::Absolute32,
        (Architecture::PowerPc | Architecture::PowerPc64, 26) => RelocKind::Relative32,
        (Architecture::Mips | Architecture::Mips64, 2) => RelocKind::Absolute32,
        (Architecture::Mips64, 18) => RelocKind::Absolute64,
        (Architecture::S390x, 22) => RelocKind::Absolute64,
        (Architecture::S390x, 5) => RelocKind::Relative32,
        (Architecture::LoongArch64, 2) => RelocKind::Absolute64,
        (Architecture::Sparc64, 32) => RelocKind::Absolute64,
        (_, 1) => RelocKind::Absolute32,
        (_, 2) => RelocKind::Relative32,
        _ => RelocKind::Other(typ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{samples, write};
    use alloc::vec;
    use std::cmp::Ordering;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hello_bytes() -> Vec<u8> {
        write(&samples::hello_world_x86_64_linux().unwrap()).unwrap()
    }

    #[test]
    fn parses_and_projects_self_emitted_elf() {
        let bytes = hello_bytes();
        let file = ElfFile::parse(&bytes).unwrap();
        assert_eq!(file.ident.class, PtrWidth::W64);
        assert_eq!(file.ident.endian, Endianness::Little);
        assert_eq!(file.header.machine, ElfMachine::X86_64);
        assert_eq!(file.to_bytes().unwrap(), bytes);
        let module = file.to_oir().unwrap();
        assert_eq!(module.format(), BinaryFormat::Elf);
        assert_eq!(module.entry(), Some(0x40_1000));
    }

    #[test]
    fn parsed_bytes_can_borrow_or_own() {
        let bytes = hello_bytes();
        let file = ElfFile::parse(&bytes).unwrap();
        assert!(core::ptr::eq(file.as_bytes().as_ptr(), bytes.as_ptr()));
        assert_eq!(file.clone().into_bytes().as_ref(), bytes.as_slice());

        let owned = ElfFile::parse_owned(bytes.clone()).unwrap();
        assert_eq!(owned.as_bytes(), bytes.as_slice());
        assert_eq!(owned.clone().into_bytes().as_ref(), bytes.as_slice());
        assert_eq!(owned.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn from_oir_uses_native_parser() {
        let module = samples::hello_world_aarch64_linux().unwrap();
        let file = ElfFile::from_oir(&module).unwrap();
        assert_eq!(file.header.machine, ElfMachine::Aarch64);
        assert!(!file.program_headers.is_empty());
        assert!(!file.section_headers.is_empty());
    }

    #[test]
    fn rejects_bad_ident_and_small_entries() {
        assert!(usize_from_u64_with_max(2, "usize", 1).is_err());

        assert!(ElfFile::parse(&[]).is_err());
        assert!(ElfFile::parse_owned(Vec::new()).is_err());
        let mut bytes = hello_bytes();
        *bytes.get_mut(0).unwrap() = 0;
        assert!(ElfFile::parse(&bytes).is_err());

        let mut bytes = hello_bytes();
        *bytes.get_mut(4).unwrap() = 3;
        assert!(ElfFile::parse(&bytes).is_err());

        let mut bytes = hello_bytes();
        *bytes.get_mut(5).unwrap() = 3;
        assert!(ElfFile::parse(&bytes).is_err());

        let mut bytes = hello_bytes();
        *bytes.get_mut(6).unwrap() = 0;
        assert!(ElfFile::parse(&bytes).is_err());

        let mut bytes = hello_bytes();
        patch(&mut bytes, 52, &1_u16.to_le_bytes());
        assert!(ElfFile::parse(&bytes).is_err());
    }

    #[test]
    fn raw_wrappers_expose_values() {
        macro_rules! assert_enum {
            ($ty:ty, default $default:expr, values [$($value:expr),+ $(,)?]) => {{
                assert_eq!(<$ty>::default().raw(), $default);
                $(
                    let wrapped = <$ty>::from($value);
                    assert_eq!(wrapped.raw(), $value);
                    assert_eq!(<$ty>::from(wrapped.raw()).raw(), $value);
                    assert_eq!(wrapped, <$ty>::from($value));
                    assert_eq!(wrapped.partial_cmp(&<$ty>::from($value)), Some(Ordering::Equal));
                    assert_eq!(wrapped.cmp(&<$ty>::from($value)), Ordering::Equal);
                    assert_eq!(hash_value(wrapped), hash_value(<$ty>::from($value)));
                )+
            }};
        }

        assert_enum!(ElfType, default 0, values [0_u16, 1, 2, 3, 4, 0xfeff]);
        assert_enum!(
            ElfMachine,
            default 0,
            values [0_u16, 3, 8, 20, 21, 40, 62, 183, 243, 258, 390, 999]
        );
        assert_enum!(
            ElfOsAbi,
            default 0,
            values [0_u8, 1, 2, 3, 6, 7, 8, 9, 12, 64, 255]
        );
        assert_enum!(
            ElfSegmentType,
            default 0,
            values [0_u32, 1, 2, 4, 0x7000_0000]
        );
        assert_enum!(ElfSegmentFlags, default 0, values [0_u32, 7]);
        assert_enum!(
            ElfSectionType,
            default 0,
            values [0_u32, 1, 2, 3, 4, 6, 7, 8, 9, 11, 0x7000_0000]
        );
        assert_enum!(ElfSectionFlags, default 0, values [0_u64, 6]);
        assert_enum!(ElfSymbolBind, default 0, values [0_u8, 1, 2, 13]);
        assert_enum!(
            ElfSymbolType,
            default 0,
            values [0_u8, 1, 2, 3, 4, 5, 6, 15]
        );
        assert_enum!(
            ElfSymbolVisibility,
            default 0,
            values [0_u8, 1, 2, 3, 7]
        );
        assert_enum!(ElfRelocationType, default 0, values [0_u32, 42]);
        assert_enum!(
            ElfDynamicTag,
            default 0,
            values [
                0_i64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, -1
            ]
        );
        assert_enum!(ElfNoteType, default 0, values [0_u32, 1]);
        assert!(ElfType::from(1) < ElfType::from(2));
    }

    fn hash_value<T: Hash>(value: T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "generated ELF enum surface coverage is intentionally exhaustive"
    )]
    fn generated_elf_constant_replacements_are_covered() {
        assert_eq!(<ElfType>::default().raw(), 0);
        assert_eq!(ElfType::None.raw(), 0);
        assert_eq!(ElfType::Relocatable.raw(), 1);
        assert_eq!(ElfType::Executable.raw(), 2);
        assert_eq!(ElfType::Dynamic.raw(), 3);
        assert_eq!(ElfType::Core.raw(), 4);
        assert_eq!(ElfType::Dyn.raw(), 3);
        assert_eq!(ElfType::Exec.raw(), 2);
        assert_eq!(ElfType::Hios.raw(), 0xfeff);
        assert_eq!(ElfType::Hiproc.raw(), 0xffff);
        assert_eq!(ElfType::Loos.raw(), 0xfe00);
        assert_eq!(ElfType::Loproc.raw(), 0xff00);
        assert_eq!(ElfType::Rel.raw(), 1);
        assert_eq!(ElfType::from_raw(0).raw(), 0);
        assert_eq!(ElfType::from_raw(1).raw(), 1);
        assert_eq!(ElfType::from_raw(2).raw(), 2);
        assert_eq!(ElfType::from_raw(3).raw(), 3);
        assert_eq!(ElfType::from_raw(4).raw(), 4);
        assert_eq!(ElfType::from_raw(0xfeff).raw(), 0xfeff);
        assert_eq!(ElfType::from_raw(0xffff).raw(), 0xffff);
        assert_eq!(ElfType::from_raw(0xfe00).raw(), 0xfe00);
        assert_eq!(ElfType::from_raw(0xff00).raw(), 0xff00);
        assert_eq!(ElfType::from_raw(0xfffe).raw(), 0xfffe);
        assert_eq!(<ElfMachine>::default().raw(), 0);
        assert_eq!(ElfMachine::None.raw(), 0);
        assert_eq!(ElfMachine::X86.raw(), 3);
        assert_eq!(ElfMachine::X86_64.raw(), 62);
        assert_eq!(ElfMachine::Arm.raw(), 40);
        assert_eq!(ElfMachine::Aarch64.raw(), 183);
        assert_eq!(ElfMachine::Riscv.raw(), 243);
        assert_eq!(ElfMachine::PowerPc.raw(), 20);
        assert_eq!(ElfMachine::PowerPc64.raw(), 21);
        assert_eq!(ElfMachine::Mips.raw(), 8);
        assert_eq!(ElfMachine::S390.raw(), 22);
        assert_eq!(ElfMachine::LoongArch.raw(), 258);
        assert_eq!(ElfMachine::SparcV9.raw(), 43);
        assert_eq!(ElfMachine::X386.raw(), 3);
        assert_eq!(ElfMachine::X56800Ex.raw(), 200);
        assert_eq!(ElfMachine::X68Hc05.raw(), 72);
        assert_eq!(ElfMachine::X68Hc08.raw(), 71);
        assert_eq!(ElfMachine::X68Hc11.raw(), 70);
        assert_eq!(ElfMachine::X68Hc12.raw(), 53);
        assert_eq!(ElfMachine::X68Hc16.raw(), 69);
        assert_eq!(ElfMachine::X68K.raw(), 4);
        assert_eq!(ElfMachine::X78Kor.raw(), 199);
        assert_eq!(ElfMachine::X8051.raw(), 165);
        assert_eq!(ElfMachine::X860.raw(), 7);
        assert_eq!(ElfMachine::X88K.raw(), 5);
        assert_eq!(ElfMachine::X960.raw(), 19);
        assert_eq!(ElfMachine::Alpha.raw(), 41);
        assert_eq!(ElfMachine::AlteraNios2.raw(), 113);
        assert_eq!(ElfMachine::Amdgpu.raw(), 224);
        assert_eq!(ElfMachine::Arc.raw(), 45);
        assert_eq!(ElfMachine::Arca.raw(), 109);
        assert_eq!(ElfMachine::ArcCompact.raw(), 93);
        assert_eq!(ElfMachine::ArcCompact2.raw(), 195);
        assert_eq!(ElfMachine::Avr.raw(), 83);
        assert_eq!(ElfMachine::Avr32.raw(), 185);
        assert_eq!(ElfMachine::Ba1.raw(), 201);
        assert_eq!(ElfMachine::Ba2.raw(), 202);
        assert_eq!(ElfMachine::Blackfin.raw(), 106);
        assert_eq!(ElfMachine::Bpf.raw(), 247);
        assert_eq!(ElfMachine::C166.raw(), 116);
        assert_eq!(ElfMachine::Cdp.raw(), 215);
        assert_eq!(ElfMachine::Ce.raw(), 119);
        assert_eq!(ElfMachine::Cloudshield.raw(), 192);
        assert_eq!(ElfMachine::Coge.raw(), 216);
        assert_eq!(ElfMachine::Coldfire.raw(), 52);
        assert_eq!(ElfMachine::Cool.raw(), 217);
        assert_eq!(ElfMachine::Corea1St.raw(), 193);
        assert_eq!(ElfMachine::Corea2Nd.raw(), 194);
        assert_eq!(ElfMachine::Cr.raw(), 103);
        assert_eq!(ElfMachine::Cr16.raw(), 177);
        assert_eq!(ElfMachine::Craynv2.raw(), 172);
        assert_eq!(ElfMachine::Cris.raw(), 76);
        assert_eq!(ElfMachine::Crx.raw(), 114);
        assert_eq!(ElfMachine::Csky.raw(), 252);
        assert_eq!(ElfMachine::CsrKalimba.raw(), 219);
        assert_eq!(ElfMachine::Cuda.raw(), 190);
        assert_eq!(ElfMachine::CypressM8C.raw(), 161);
        assert_eq!(ElfMachine::D10V.raw(), 85);
        assert_eq!(ElfMachine::D30V.raw(), 86);
        assert_eq!(ElfMachine::Dsp24.raw(), 136);
        assert_eq!(ElfMachine::Dspic30F.raw(), 118);
        assert_eq!(ElfMachine::Dxp.raw(), 112);
        assert_eq!(ElfMachine::Ecog1.raw(), 168);
        assert_eq!(ElfMachine::Ecog16.raw(), 176);
        assert_eq!(ElfMachine::Ecog1X.raw(), 168);
        assert_eq!(ElfMachine::Ecog2.raw(), 134);
        assert_eq!(ElfMachine::Etpu.raw(), 178);
        assert_eq!(ElfMachine::Excess.raw(), 111);
        assert_eq!(ElfMachine::F2Mc16.raw(), 104);
        assert_eq!(ElfMachine::Firepath.raw(), 78);
        assert_eq!(ElfMachine::Fr20.raw(), 37);
        assert_eq!(ElfMachine::Fr30.raw(), 84);
        assert_eq!(ElfMachine::Fx66.raw(), 66);
        assert_eq!(ElfMachine::H8S.raw(), 48);
        assert_eq!(ElfMachine::H8300.raw(), 46);
        assert_eq!(ElfMachine::H8300H.raw(), 47);
        assert_eq!(ElfMachine::H8500.raw(), 49);
        assert_eq!(ElfMachine::Hexagon.raw(), 164);
        assert_eq!(ElfMachine::Huany.raw(), 81);
        assert_eq!(ElfMachine::Iamcu.raw(), 6);
        assert_eq!(ElfMachine::Ia64.raw(), 50);
        assert_eq!(ElfMachine::Intel205.raw(), 205);
        assert_eq!(ElfMachine::Intel206.raw(), 206);
        assert_eq!(ElfMachine::Intel207.raw(), 207);
        assert_eq!(ElfMachine::Intel208.raw(), 208);
        assert_eq!(ElfMachine::Intel209.raw(), 209);
        assert_eq!(ElfMachine::Ip2K.raw(), 101);
        assert_eq!(ElfMachine::Javelin.raw(), 77);
        assert_eq!(ElfMachine::K10M.raw(), 181);
        assert_eq!(ElfMachine::Km32.raw(), 210);
        assert_eq!(ElfMachine::Kmx16.raw(), 212);
        assert_eq!(ElfMachine::Kmx32.raw(), 211);
        assert_eq!(ElfMachine::Kmx8.raw(), 213);
        assert_eq!(ElfMachine::Kvarc.raw(), 214);
        assert_eq!(ElfMachine::L10M.raw(), 180);
        assert_eq!(ElfMachine::Lanai.raw(), 244);
        assert_eq!(ElfMachine::Latticemico32.raw(), 138);
        assert_eq!(ElfMachine::Loongarch.raw(), 258);
        assert_eq!(ElfMachine::M16C.raw(), 117);
        assert_eq!(ElfMachine::M32.raw(), 1);
        assert_eq!(ElfMachine::M32C.raw(), 120);
        assert_eq!(ElfMachine::M32R.raw(), 88);
        assert_eq!(ElfMachine::Manik.raw(), 171);
        assert_eq!(ElfMachine::Max.raw(), 102);
        assert_eq!(ElfMachine::Maxq30.raw(), 169);
        assert_eq!(ElfMachine::MchpPic.raw(), 204);
        assert_eq!(ElfMachine::McstElbrus.raw(), 175);
        assert_eq!(ElfMachine::Me16.raw(), 59);
        assert_eq!(ElfMachine::Metag.raw(), 174);
        assert_eq!(ElfMachine::Microblaze.raw(), 189);
        assert_eq!(ElfMachine::MipsRs3Le.raw(), 10);
        assert_eq!(ElfMachine::MipsX.raw(), 51);
        assert_eq!(ElfMachine::Mma.raw(), 54);
        assert_eq!(ElfMachine::MmdspPlus.raw(), 160);
        assert_eq!(ElfMachine::Mmix.raw(), 80);
        assert_eq!(ElfMachine::Mn10200.raw(), 90);
        assert_eq!(ElfMachine::Mn10300.raw(), 89);
        assert_eq!(ElfMachine::Msp430.raw(), 105);
        assert_eq!(ElfMachine::Ncpu.raw(), 56);
        assert_eq!(ElfMachine::Ndr1.raw(), 57);
        assert_eq!(ElfMachine::Nds32.raw(), 167);
        assert_eq!(ElfMachine::Norc.raw(), 218);
        assert_eq!(ElfMachine::Ns32K.raw(), 97);
        assert_eq!(ElfMachine::Open8.raw(), 196);
        assert_eq!(ElfMachine::Openrisc.raw(), 92);
        assert_eq!(ElfMachine::Parisc.raw(), 15);
        assert_eq!(ElfMachine::Pcp.raw(), 55);
        assert_eq!(ElfMachine::Pdp10.raw(), 64);
        assert_eq!(ElfMachine::Pdp11.raw(), 65);
        assert_eq!(ElfMachine::Pdsp.raw(), 63);
        assert_eq!(ElfMachine::Pj.raw(), 91);
        assert_eq!(ElfMachine::Ppc.raw(), 20);
        assert_eq!(ElfMachine::Ppc64.raw(), 21);
        assert_eq!(ElfMachine::Prism.raw(), 82);
        assert_eq!(ElfMachine::R32C.raw(), 162);
        assert_eq!(ElfMachine::Rce.raw(), 39);
        assert_eq!(ElfMachine::Rh32.raw(), 38);
        assert_eq!(ElfMachine::Rl78.raw(), 197);
        assert_eq!(ElfMachine::Rs08.raw(), 132);
        assert_eq!(ElfMachine::Rx.raw(), 173);
        assert_eq!(ElfMachine::S370.raw(), 9);
        assert_eq!(ElfMachine::Score7.raw(), 135);
        assert_eq!(ElfMachine::Sep.raw(), 108);
        assert_eq!(ElfMachine::SeC17.raw(), 139);
        assert_eq!(ElfMachine::SeC33.raw(), 107);
        assert_eq!(ElfMachine::Sh.raw(), 42);
        assert_eq!(ElfMachine::Sharc.raw(), 133);
        assert_eq!(ElfMachine::Sle9X.raw(), 179);
        assert_eq!(ElfMachine::Snp1K.raw(), 99);
        assert_eq!(ElfMachine::Sparc.raw(), 2);
        assert_eq!(ElfMachine::Sparc32Plus.raw(), 18);
        assert_eq!(ElfMachine::Sparcv9.raw(), 43);
        assert_eq!(ElfMachine::Spu.raw(), 23);
        assert_eq!(ElfMachine::St100.raw(), 60);
        assert_eq!(ElfMachine::St19.raw(), 74);
        assert_eq!(ElfMachine::St200.raw(), 100);
        assert_eq!(ElfMachine::St7.raw(), 68);
        assert_eq!(ElfMachine::St9Plus.raw(), 67);
        assert_eq!(ElfMachine::Starcore.raw(), 58);
        assert_eq!(ElfMachine::Stm8.raw(), 186);
        assert_eq!(ElfMachine::Stxp7X.raw(), 166);
        assert_eq!(ElfMachine::Svx.raw(), 73);
        assert_eq!(ElfMachine::Tile64.raw(), 187);
        assert_eq!(ElfMachine::Tilegx.raw(), 191);
        assert_eq!(ElfMachine::Tilepro.raw(), 188);
        assert_eq!(ElfMachine::Tinyj.raw(), 61);
        assert_eq!(ElfMachine::TiC2000.raw(), 141);
        assert_eq!(ElfMachine::TiC5500.raw(), 142);
        assert_eq!(ElfMachine::TiC6000.raw(), 140);
        assert_eq!(ElfMachine::TmmGpp.raw(), 96);
        assert_eq!(ElfMachine::Tpc.raw(), 98);
        assert_eq!(ElfMachine::Tricore.raw(), 44);
        assert_eq!(ElfMachine::Trimedia.raw(), 163);
        assert_eq!(ElfMachine::Tsk3000.raw(), 131);
        assert_eq!(ElfMachine::Unicore.raw(), 110);
        assert_eq!(ElfMachine::V800.raw(), 36);
        assert_eq!(ElfMachine::V850.raw(), 87);
        assert_eq!(ElfMachine::Vax.raw(), 75);
        assert_eq!(ElfMachine::Ve.raw(), 251);
        assert_eq!(ElfMachine::Videocore.raw(), 95);
        assert_eq!(ElfMachine::Videocore3.raw(), 137);
        assert_eq!(ElfMachine::Videocore5.raw(), 198);
        assert_eq!(ElfMachine::Vpp500.raw(), 17);
        assert_eq!(ElfMachine::X8664.raw(), 62);
        assert_eq!(ElfMachine::Xcore.raw(), 203);
        assert_eq!(ElfMachine::Xgate.raw(), 115);
        assert_eq!(ElfMachine::Ximo16.raw(), 170);
        assert_eq!(ElfMachine::Xtensa.raw(), 94);
        assert_eq!(ElfMachine::Zsp.raw(), 79);
        assert_eq!(ElfMachine::from_raw(0).raw(), 0);
        assert_eq!(ElfMachine::from_raw(3).raw(), 3);
        assert_eq!(ElfMachine::from_raw(62).raw(), 62);
        assert_eq!(ElfMachine::from_raw(40).raw(), 40);
        assert_eq!(ElfMachine::from_raw(183).raw(), 183);
        assert_eq!(ElfMachine::from_raw(243).raw(), 243);
        assert_eq!(ElfMachine::from_raw(20).raw(), 20);
        assert_eq!(ElfMachine::from_raw(21).raw(), 21);
        assert_eq!(ElfMachine::from_raw(8).raw(), 8);
        assert_eq!(ElfMachine::from_raw(22).raw(), 22);
        assert_eq!(ElfMachine::from_raw(258).raw(), 258);
        assert_eq!(ElfMachine::from_raw(43).raw(), 43);
        assert_eq!(ElfMachine::from_raw(200).raw(), 200);
        assert_eq!(ElfMachine::from_raw(72).raw(), 72);
        assert_eq!(ElfMachine::from_raw(71).raw(), 71);
        assert_eq!(ElfMachine::from_raw(70).raw(), 70);
        assert_eq!(ElfMachine::from_raw(53).raw(), 53);
        assert_eq!(ElfMachine::from_raw(69).raw(), 69);
        assert_eq!(ElfMachine::from_raw(4).raw(), 4);
        assert_eq!(ElfMachine::from_raw(199).raw(), 199);
        assert_eq!(ElfMachine::from_raw(165).raw(), 165);
        assert_eq!(ElfMachine::from_raw(7).raw(), 7);
        assert_eq!(ElfMachine::from_raw(5).raw(), 5);
        assert_eq!(ElfMachine::from_raw(19).raw(), 19);
        assert_eq!(ElfMachine::from_raw(41).raw(), 41);
        assert_eq!(ElfMachine::from_raw(113).raw(), 113);
        assert_eq!(ElfMachine::from_raw(224).raw(), 224);
        assert_eq!(ElfMachine::from_raw(45).raw(), 45);
        assert_eq!(ElfMachine::from_raw(109).raw(), 109);
        assert_eq!(ElfMachine::from_raw(93).raw(), 93);
        assert_eq!(ElfMachine::from_raw(195).raw(), 195);
        assert_eq!(ElfMachine::from_raw(83).raw(), 83);
        assert_eq!(ElfMachine::from_raw(185).raw(), 185);
        assert_eq!(ElfMachine::from_raw(201).raw(), 201);
        assert_eq!(ElfMachine::from_raw(202).raw(), 202);
        assert_eq!(ElfMachine::from_raw(106).raw(), 106);
        assert_eq!(ElfMachine::from_raw(247).raw(), 247);
        assert_eq!(ElfMachine::from_raw(116).raw(), 116);
        assert_eq!(ElfMachine::from_raw(215).raw(), 215);
        assert_eq!(ElfMachine::from_raw(119).raw(), 119);
        assert_eq!(ElfMachine::from_raw(192).raw(), 192);
        assert_eq!(ElfMachine::from_raw(216).raw(), 216);
        assert_eq!(ElfMachine::from_raw(52).raw(), 52);
        assert_eq!(ElfMachine::from_raw(217).raw(), 217);
        assert_eq!(ElfMachine::from_raw(193).raw(), 193);
        assert_eq!(ElfMachine::from_raw(194).raw(), 194);
        assert_eq!(ElfMachine::from_raw(103).raw(), 103);
        assert_eq!(ElfMachine::from_raw(177).raw(), 177);
        assert_eq!(ElfMachine::from_raw(172).raw(), 172);
        assert_eq!(ElfMachine::from_raw(76).raw(), 76);
        assert_eq!(ElfMachine::from_raw(114).raw(), 114);
        assert_eq!(ElfMachine::from_raw(252).raw(), 252);
        assert_eq!(ElfMachine::from_raw(219).raw(), 219);
        assert_eq!(ElfMachine::from_raw(190).raw(), 190);
        assert_eq!(ElfMachine::from_raw(161).raw(), 161);
        assert_eq!(ElfMachine::from_raw(85).raw(), 85);
        assert_eq!(ElfMachine::from_raw(86).raw(), 86);
        assert_eq!(ElfMachine::from_raw(136).raw(), 136);
        assert_eq!(ElfMachine::from_raw(118).raw(), 118);
        assert_eq!(ElfMachine::from_raw(112).raw(), 112);
        assert_eq!(ElfMachine::from_raw(168).raw(), 168);
        assert_eq!(ElfMachine::from_raw(176).raw(), 176);
        assert_eq!(ElfMachine::from_raw(134).raw(), 134);
        assert_eq!(ElfMachine::from_raw(178).raw(), 178);
        assert_eq!(ElfMachine::from_raw(111).raw(), 111);
        assert_eq!(ElfMachine::from_raw(104).raw(), 104);
        assert_eq!(ElfMachine::from_raw(78).raw(), 78);
        assert_eq!(ElfMachine::from_raw(37).raw(), 37);
        assert_eq!(ElfMachine::from_raw(84).raw(), 84);
        assert_eq!(ElfMachine::from_raw(66).raw(), 66);
        assert_eq!(ElfMachine::from_raw(48).raw(), 48);
        assert_eq!(ElfMachine::from_raw(46).raw(), 46);
        assert_eq!(ElfMachine::from_raw(47).raw(), 47);
        assert_eq!(ElfMachine::from_raw(49).raw(), 49);
        assert_eq!(ElfMachine::from_raw(164).raw(), 164);
        assert_eq!(ElfMachine::from_raw(81).raw(), 81);
        assert_eq!(ElfMachine::from_raw(6).raw(), 6);
        assert_eq!(ElfMachine::from_raw(50).raw(), 50);
        assert_eq!(ElfMachine::from_raw(205).raw(), 205);
        assert_eq!(ElfMachine::from_raw(206).raw(), 206);
        assert_eq!(ElfMachine::from_raw(207).raw(), 207);
        assert_eq!(ElfMachine::from_raw(208).raw(), 208);
        assert_eq!(ElfMachine::from_raw(209).raw(), 209);
        assert_eq!(ElfMachine::from_raw(101).raw(), 101);
        assert_eq!(ElfMachine::from_raw(77).raw(), 77);
        assert_eq!(ElfMachine::from_raw(181).raw(), 181);
        assert_eq!(ElfMachine::from_raw(210).raw(), 210);
        assert_eq!(ElfMachine::from_raw(212).raw(), 212);
        assert_eq!(ElfMachine::from_raw(211).raw(), 211);
        assert_eq!(ElfMachine::from_raw(213).raw(), 213);
        assert_eq!(ElfMachine::from_raw(214).raw(), 214);
        assert_eq!(ElfMachine::from_raw(180).raw(), 180);
        assert_eq!(ElfMachine::from_raw(244).raw(), 244);
        assert_eq!(ElfMachine::from_raw(138).raw(), 138);
        assert_eq!(ElfMachine::from_raw(117).raw(), 117);
        assert_eq!(ElfMachine::from_raw(1).raw(), 1);
        assert_eq!(ElfMachine::from_raw(120).raw(), 120);
        assert_eq!(ElfMachine::from_raw(88).raw(), 88);
        assert_eq!(ElfMachine::from_raw(171).raw(), 171);
        assert_eq!(ElfMachine::from_raw(102).raw(), 102);
        assert_eq!(ElfMachine::from_raw(169).raw(), 169);
        assert_eq!(ElfMachine::from_raw(204).raw(), 204);
        assert_eq!(ElfMachine::from_raw(175).raw(), 175);
        assert_eq!(ElfMachine::from_raw(59).raw(), 59);
        assert_eq!(ElfMachine::from_raw(174).raw(), 174);
        assert_eq!(ElfMachine::from_raw(189).raw(), 189);
        assert_eq!(ElfMachine::from_raw(10).raw(), 10);
        assert_eq!(ElfMachine::from_raw(51).raw(), 51);
        assert_eq!(ElfMachine::from_raw(54).raw(), 54);
        assert_eq!(ElfMachine::from_raw(160).raw(), 160);
        assert_eq!(ElfMachine::from_raw(80).raw(), 80);
        assert_eq!(ElfMachine::from_raw(90).raw(), 90);
        assert_eq!(ElfMachine::from_raw(89).raw(), 89);
        assert_eq!(ElfMachine::from_raw(105).raw(), 105);
        assert_eq!(ElfMachine::from_raw(56).raw(), 56);
        assert_eq!(ElfMachine::from_raw(57).raw(), 57);
        assert_eq!(ElfMachine::from_raw(167).raw(), 167);
        assert_eq!(ElfMachine::from_raw(218).raw(), 218);
        assert_eq!(ElfMachine::from_raw(97).raw(), 97);
        assert_eq!(ElfMachine::from_raw(196).raw(), 196);
        assert_eq!(ElfMachine::from_raw(92).raw(), 92);
        assert_eq!(ElfMachine::from_raw(15).raw(), 15);
        assert_eq!(ElfMachine::from_raw(55).raw(), 55);
        assert_eq!(ElfMachine::from_raw(64).raw(), 64);
        assert_eq!(ElfMachine::from_raw(65).raw(), 65);
        assert_eq!(ElfMachine::from_raw(63).raw(), 63);
        assert_eq!(ElfMachine::from_raw(91).raw(), 91);
        assert_eq!(ElfMachine::from_raw(82).raw(), 82);
        assert_eq!(ElfMachine::from_raw(162).raw(), 162);
        assert_eq!(ElfMachine::from_raw(39).raw(), 39);
        assert_eq!(ElfMachine::from_raw(38).raw(), 38);
        assert_eq!(ElfMachine::from_raw(197).raw(), 197);
        assert_eq!(ElfMachine::from_raw(132).raw(), 132);
        assert_eq!(ElfMachine::from_raw(173).raw(), 173);
        assert_eq!(ElfMachine::from_raw(9).raw(), 9);
        assert_eq!(ElfMachine::from_raw(135).raw(), 135);
        assert_eq!(ElfMachine::from_raw(108).raw(), 108);
        assert_eq!(ElfMachine::from_raw(139).raw(), 139);
        assert_eq!(ElfMachine::from_raw(107).raw(), 107);
        assert_eq!(ElfMachine::from_raw(42).raw(), 42);
        assert_eq!(ElfMachine::from_raw(133).raw(), 133);
        assert_eq!(ElfMachine::from_raw(179).raw(), 179);
        assert_eq!(ElfMachine::from_raw(99).raw(), 99);
        assert_eq!(ElfMachine::from_raw(2).raw(), 2);
        assert_eq!(ElfMachine::from_raw(18).raw(), 18);
        assert_eq!(ElfMachine::from_raw(23).raw(), 23);
        assert_eq!(ElfMachine::from_raw(60).raw(), 60);
        assert_eq!(ElfMachine::from_raw(74).raw(), 74);
        assert_eq!(ElfMachine::from_raw(100).raw(), 100);
        assert_eq!(ElfMachine::from_raw(68).raw(), 68);
        assert_eq!(ElfMachine::from_raw(67).raw(), 67);
        assert_eq!(ElfMachine::from_raw(58).raw(), 58);
        assert_eq!(ElfMachine::from_raw(186).raw(), 186);
        assert_eq!(ElfMachine::from_raw(166).raw(), 166);
        assert_eq!(ElfMachine::from_raw(73).raw(), 73);
        assert_eq!(ElfMachine::from_raw(187).raw(), 187);
        assert_eq!(ElfMachine::from_raw(191).raw(), 191);
        assert_eq!(ElfMachine::from_raw(188).raw(), 188);
        assert_eq!(ElfMachine::from_raw(61).raw(), 61);
        assert_eq!(ElfMachine::from_raw(141).raw(), 141);
        assert_eq!(ElfMachine::from_raw(142).raw(), 142);
        assert_eq!(ElfMachine::from_raw(140).raw(), 140);
        assert_eq!(ElfMachine::from_raw(96).raw(), 96);
        assert_eq!(ElfMachine::from_raw(98).raw(), 98);
        assert_eq!(ElfMachine::from_raw(44).raw(), 44);
        assert_eq!(ElfMachine::from_raw(163).raw(), 163);
        assert_eq!(ElfMachine::from_raw(131).raw(), 131);
        assert_eq!(ElfMachine::from_raw(110).raw(), 110);
        assert_eq!(ElfMachine::from_raw(36).raw(), 36);
        assert_eq!(ElfMachine::from_raw(87).raw(), 87);
        assert_eq!(ElfMachine::from_raw(75).raw(), 75);
        assert_eq!(ElfMachine::from_raw(251).raw(), 251);
        assert_eq!(ElfMachine::from_raw(95).raw(), 95);
        assert_eq!(ElfMachine::from_raw(137).raw(), 137);
        assert_eq!(ElfMachine::from_raw(198).raw(), 198);
        assert_eq!(ElfMachine::from_raw(17).raw(), 17);
        assert_eq!(ElfMachine::from_raw(203).raw(), 203);
        assert_eq!(ElfMachine::from_raw(115).raw(), 115);
        assert_eq!(ElfMachine::from_raw(170).raw(), 170);
        assert_eq!(ElfMachine::from_raw(94).raw(), 94);
        assert_eq!(ElfMachine::from_raw(79).raw(), 79);
        assert_eq!(ElfMachine::from_raw(0xfffe).raw(), 0xfffe);
        assert_eq!(<ElfOsAbi>::default().raw(), 0);
        assert_eq!(ElfOsAbi::SystemV.raw(), 0);
        assert_eq!(ElfOsAbi::HpUx.raw(), 1);
        assert_eq!(ElfOsAbi::NetBsd.raw(), 2);
        assert_eq!(ElfOsAbi::Gnu.raw(), 3);
        assert_eq!(ElfOsAbi::Solaris.raw(), 6);
        assert_eq!(ElfOsAbi::Aix.raw(), 7);
        assert_eq!(ElfOsAbi::Irix.raw(), 8);
        assert_eq!(ElfOsAbi::FreeBsd.raw(), 9);
        assert_eq!(ElfOsAbi::OpenBsd.raw(), 12);
        assert_eq!(ElfOsAbi::Standalone.raw(), 255);
        assert_eq!(ElfOsAbi::AmdgpuHsa.raw(), 64);
        assert_eq!(ElfOsAbi::AmdgpuMesa3D.raw(), 66);
        assert_eq!(ElfOsAbi::AmdgpuPal.raw(), 65);
        assert_eq!(ElfOsAbi::Arm.raw(), 97);
        assert_eq!(ElfOsAbi::ArmFdpic.raw(), 65);
        assert_eq!(ElfOsAbi::Aros.raw(), 15);
        assert_eq!(ElfOsAbi::C6000Elfabi.raw(), 64);
        assert_eq!(ElfOsAbi::C6000Linux.raw(), 65);
        assert_eq!(ElfOsAbi::Cloudabi.raw(), 17);
        assert_eq!(ElfOsAbi::Cuda.raw(), 51);
        assert_eq!(ElfOsAbi::Fenixos.raw(), 16);
        assert_eq!(ElfOsAbi::FirstArch.raw(), 64);
        assert_eq!(ElfOsAbi::Freebsd.raw(), 9);
        assert_eq!(ElfOsAbi::Hpux.raw(), 1);
        assert_eq!(ElfOsAbi::Hurd.raw(), 4);
        assert_eq!(ElfOsAbi::LastArch.raw(), 255);
        assert_eq!(ElfOsAbi::Linux.raw(), 3);
        assert_eq!(ElfOsAbi::Modesto.raw(), 11);
        assert_eq!(ElfOsAbi::Netbsd.raw(), 2);
        assert_eq!(ElfOsAbi::None.raw(), 0);
        assert_eq!(ElfOsAbi::Nsk.raw(), 14);
        assert_eq!(ElfOsAbi::Openbsd.raw(), 12);
        assert_eq!(ElfOsAbi::Openvms.raw(), 13);
        assert_eq!(ElfOsAbi::Tru64.raw(), 10);
        assert_eq!(ElfOsAbi::from_raw(0).raw(), 0);
        assert_eq!(ElfOsAbi::from_raw(1).raw(), 1);
        assert_eq!(ElfOsAbi::from_raw(2).raw(), 2);
        assert_eq!(ElfOsAbi::from_raw(3).raw(), 3);
        assert_eq!(ElfOsAbi::from_raw(6).raw(), 6);
        assert_eq!(ElfOsAbi::from_raw(7).raw(), 7);
        assert_eq!(ElfOsAbi::from_raw(8).raw(), 8);
        assert_eq!(ElfOsAbi::from_raw(9).raw(), 9);
        assert_eq!(ElfOsAbi::from_raw(12).raw(), 12);
        assert_eq!(ElfOsAbi::from_raw(255).raw(), 255);
        assert_eq!(ElfOsAbi::from_raw(64).raw(), 64);
        assert_eq!(ElfOsAbi::from_raw(66).raw(), 66);
        assert_eq!(ElfOsAbi::from_raw(65).raw(), 65);
        assert_eq!(ElfOsAbi::from_raw(97).raw(), 97);
        assert_eq!(ElfOsAbi::from_raw(15).raw(), 15);
        assert_eq!(ElfOsAbi::from_raw(17).raw(), 17);
        assert_eq!(ElfOsAbi::from_raw(51).raw(), 51);
        assert_eq!(ElfOsAbi::from_raw(16).raw(), 16);
        assert_eq!(ElfOsAbi::from_raw(4).raw(), 4);
        assert_eq!(ElfOsAbi::from_raw(11).raw(), 11);
        assert_eq!(ElfOsAbi::from_raw(14).raw(), 14);
        assert_eq!(ElfOsAbi::from_raw(13).raw(), 13);
        assert_eq!(ElfOsAbi::from_raw(10).raw(), 10);
        assert_eq!(ElfOsAbi::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfClass>::default().raw(), 0);
        assert_eq!(ElfClass::None.raw(), 0);
        assert_eq!(ElfClass::Class32.raw(), 1);
        assert_eq!(ElfClass::Class64.raw(), 2);
        assert_eq!(ElfClass::X32.raw(), 1);
        assert_eq!(ElfClass::X64.raw(), 2);
        assert_eq!(ElfClass::from_raw(0).raw(), 0);
        assert_eq!(ElfClass::from_raw(1).raw(), 1);
        assert_eq!(ElfClass::from_raw(2).raw(), 2);
        assert_eq!(ElfClass::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfDataEncoding>::default().raw(), 0);
        assert_eq!(ElfDataEncoding::None.raw(), 0);
        assert_eq!(ElfDataEncoding::Little.raw(), 1);
        assert_eq!(ElfDataEncoding::Big.raw(), 2);
        assert_eq!(ElfDataEncoding::X2Lsb.raw(), 1);
        assert_eq!(ElfDataEncoding::X2Msb.raw(), 2);
        assert_eq!(ElfDataEncoding::from_raw(0).raw(), 0);
        assert_eq!(ElfDataEncoding::from_raw(1).raw(), 1);
        assert_eq!(ElfDataEncoding::from_raw(2).raw(), 2);
        assert_eq!(ElfDataEncoding::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfVersion>::default().raw(), 0);
        assert_eq!(ElfVersion::None.raw(), 0);
        assert_eq!(ElfVersion::Current.raw(), 1);
        assert_eq!(ElfVersion::from_raw(0).raw(), 0);
        assert_eq!(ElfVersion::from_raw(1).raw(), 1);
        assert_eq!(ElfVersion::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(ElfVersion::from(1).raw(), 1);
        assert_eq!(<ElfAbiVersion>::default().raw(), 0);
        assert_eq!(ElfAbiVersion::AmdgpuHsaV2.raw(), 0);
        assert_eq!(ElfAbiVersion::AmdgpuHsaV3.raw(), 1);
        assert_eq!(ElfAbiVersion::AmdgpuHsaV4.raw(), 2);
        assert_eq!(ElfAbiVersion::AmdgpuHsaV5.raw(), 3);
        assert_eq!(ElfAbiVersion::AmdgpuHsaV6.raw(), 4);
        assert_eq!(ElfAbiVersion::from_raw(0).raw(), 0);
        assert_eq!(ElfAbiVersion::from_raw(1).raw(), 1);
        assert_eq!(ElfAbiVersion::from_raw(2).raw(), 2);
        assert_eq!(ElfAbiVersion::from_raw(3).raw(), 3);
        assert_eq!(ElfAbiVersion::from_raw(4).raw(), 4);
        assert_eq!(ElfAbiVersion::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfIdentField>::default().raw(), 0);
        assert_eq!(ElfIdentField::Abiversion.raw(), 8);
        assert_eq!(ElfIdentField::Class.raw(), 4);
        assert_eq!(ElfIdentField::Data.raw(), 5);
        assert_eq!(ElfIdentField::Mag0.raw(), 0);
        assert_eq!(ElfIdentField::Mag1.raw(), 1);
        assert_eq!(ElfIdentField::Mag2.raw(), 2);
        assert_eq!(ElfIdentField::Mag3.raw(), 3);
        assert_eq!(ElfIdentField::Nident.raw(), 16);
        assert_eq!(ElfIdentField::Osabi.raw(), 7);
        assert_eq!(ElfIdentField::Pad.raw(), 9);
        assert_eq!(ElfIdentField::Version.raw(), 6);
        assert_eq!(ElfIdentField::from_raw(8).raw(), 8);
        assert_eq!(ElfIdentField::from_raw(4).raw(), 4);
        assert_eq!(ElfIdentField::from_raw(5).raw(), 5);
        assert_eq!(ElfIdentField::from_raw(0).raw(), 0);
        assert_eq!(ElfIdentField::from_raw(1).raw(), 1);
        assert_eq!(ElfIdentField::from_raw(2).raw(), 2);
        assert_eq!(ElfIdentField::from_raw(3).raw(), 3);
        assert_eq!(ElfIdentField::from_raw(16).raw(), 16);
        assert_eq!(ElfIdentField::from_raw(7).raw(), 7);
        assert_eq!(ElfIdentField::from_raw(9).raw(), 9);
        assert_eq!(ElfIdentField::from_raw(6).raw(), 6);
        assert_eq!(ElfIdentField::from_raw(usize::MAX).raw(), usize::MAX);
        assert_eq!(<ElfSegmentType>::default().raw(), 0);
        assert_eq!(ElfSegmentType::Null.raw(), 0);
        assert_eq!(ElfSegmentType::Load.raw(), 1);
        assert_eq!(ElfSegmentType::Dynamic.raw(), 2);
        assert_eq!(ElfSegmentType::Note.raw(), 4);
        assert_eq!(ElfSegmentType::Aarch64MemtagMte.raw(), 0x7000_0002);
        assert_eq!(ElfSegmentType::ArmArchext.raw(), 0x7000_0000);
        assert_eq!(ElfSegmentType::ArmExidx.raw(), 0x7000_0001);
        assert_eq!(ElfSegmentType::ArmUnwind.raw(), 0x7000_0001);
        assert_eq!(ElfSegmentType::GnuEhFrame.raw(), 0x6474_e550);
        assert_eq!(ElfSegmentType::GnuProperty.raw(), 0x6474_e553);
        assert_eq!(ElfSegmentType::GnuRelro.raw(), 0x6474_e552);
        assert_eq!(ElfSegmentType::GnuStack.raw(), 0x6474_e551);
        assert_eq!(ElfSegmentType::Hios.raw(), 0x6fff_ffff);
        assert_eq!(ElfSegmentType::Hiproc.raw(), 0x7fff_ffff);
        assert_eq!(ElfSegmentType::Interp.raw(), 3);
        assert_eq!(ElfSegmentType::Loos.raw(), 0x6000_0000);
        assert_eq!(ElfSegmentType::Loproc.raw(), 0x7000_0000);
        assert_eq!(ElfSegmentType::MipsAbiflags.raw(), 0x7000_0003);
        assert_eq!(ElfSegmentType::MipsOptions.raw(), 0x7000_0002);
        assert_eq!(ElfSegmentType::MipsReginfo.raw(), 0x7000_0000);
        assert_eq!(ElfSegmentType::MipsRtproc.raw(), 0x7000_0001);
        assert_eq!(ElfSegmentType::OpenbsdBootdata.raw(), 0x65a4_1be6);
        assert_eq!(ElfSegmentType::OpenbsdMutable.raw(), 0x65a3_dbe5);
        assert_eq!(ElfSegmentType::OpenbsdNobtcfi.raw(), 0x65a3_dbe8);
        assert_eq!(ElfSegmentType::OpenbsdRandomize.raw(), 0x65a3_dbe6);
        assert_eq!(ElfSegmentType::OpenbsdSyscalls.raw(), 0x65a3_dbe9);
        assert_eq!(ElfSegmentType::OpenbsdWxneeded.raw(), 0x65a3_dbe7);
        assert_eq!(ElfSegmentType::Phdr.raw(), 6);
        assert_eq!(ElfSegmentType::RiscvAttributes.raw(), 0x7000_0003);
        assert_eq!(ElfSegmentType::Shlib.raw(), 5);
        assert_eq!(ElfSegmentType::SunwEhFrame.raw(), 0x6474_e550);
        assert_eq!(ElfSegmentType::SunwUnwind.raw(), 0x6464_e550);
        assert_eq!(ElfSegmentType::Tls.raw(), 7);
        assert_eq!(ElfSegmentType::from_raw(0).raw(), 0);
        assert_eq!(ElfSegmentType::from_raw(1).raw(), 1);
        assert_eq!(ElfSegmentType::from_raw(2).raw(), 2);
        assert_eq!(ElfSegmentType::from_raw(4).raw(), 4);
        assert_eq!(ElfSegmentType::from_raw(0x7000_0002).raw(), 0x7000_0002);
        assert_eq!(ElfSegmentType::from_raw(0x7000_0000).raw(), 0x7000_0000);
        assert_eq!(ElfSegmentType::from_raw(0x7000_0001).raw(), 0x7000_0001);
        assert_eq!(ElfSegmentType::from_raw(0x6474_e550).raw(), 0x6474_e550);
        assert_eq!(ElfSegmentType::from_raw(0x6474_e553).raw(), 0x6474_e553);
        assert_eq!(ElfSegmentType::from_raw(0x6474_e552).raw(), 0x6474_e552);
        assert_eq!(ElfSegmentType::from_raw(0x6474_e551).raw(), 0x6474_e551);
        assert_eq!(ElfSegmentType::from_raw(0x6fff_ffff).raw(), 0x6fff_ffff);
        assert_eq!(ElfSegmentType::from_raw(0x7fff_ffff).raw(), 0x7fff_ffff);
        assert_eq!(ElfSegmentType::from_raw(3).raw(), 3);
        assert_eq!(ElfSegmentType::from_raw(0x6000_0000).raw(), 0x6000_0000);
        assert_eq!(ElfSegmentType::from_raw(0x7000_0003).raw(), 0x7000_0003);
        assert_eq!(ElfSegmentType::from_raw(0x65a4_1be6).raw(), 0x65a4_1be6);
        assert_eq!(ElfSegmentType::from_raw(0x65a3_dbe5).raw(), 0x65a3_dbe5);
        assert_eq!(ElfSegmentType::from_raw(0x65a3_dbe8).raw(), 0x65a3_dbe8);
        assert_eq!(ElfSegmentType::from_raw(0x65a3_dbe6).raw(), 0x65a3_dbe6);
        assert_eq!(ElfSegmentType::from_raw(0x65a3_dbe9).raw(), 0x65a3_dbe9);
        assert_eq!(ElfSegmentType::from_raw(0x65a3_dbe7).raw(), 0x65a3_dbe7);
        assert_eq!(ElfSegmentType::from_raw(6).raw(), 6);
        assert_eq!(ElfSegmentType::from_raw(5).raw(), 5);
        assert_eq!(ElfSegmentType::from_raw(0x6464_e550).raw(), 0x6464_e550);
        assert_eq!(ElfSegmentType::from_raw(7).raw(), 7);
        assert_eq!(ElfSegmentType::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfSectionType>::default().raw(), 0);
        assert_eq!(ElfSectionType::Null.raw(), 0);
        assert_eq!(ElfSectionType::Progbits.raw(), 1);
        assert_eq!(ElfSectionType::Symtab.raw(), 2);
        assert_eq!(ElfSectionType::Strtab.raw(), 3);
        assert_eq!(ElfSectionType::Rela.raw(), 4);
        assert_eq!(ElfSectionType::Dynamic.raw(), 6);
        assert_eq!(ElfSectionType::Note.raw(), 7);
        assert_eq!(ElfSectionType::Nobits.raw(), 8);
        assert_eq!(ElfSectionType::Rel.raw(), 9);
        assert_eq!(ElfSectionType::Dynsym.raw(), 11);
        assert_eq!(ElfSectionType::Aarch64Attributes.raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::Aarch64AuthRelr.raw(), 0x7000_0004);
        assert_eq!(
            ElfSectionType::Aarch64MemtagGlobalsDynamic.raw(),
            0x7000_0008
        );
        assert_eq!(
            ElfSectionType::Aarch64MemtagGlobalsStatic.raw(),
            0x7000_0007
        );
        assert_eq!(ElfSectionType::AndroidRel.raw(), 0x6000_0001);
        assert_eq!(ElfSectionType::AndroidRela.raw(), 0x6000_0002);
        assert_eq!(ElfSectionType::AndroidRelr.raw(), 0x6fff_ff00);
        assert_eq!(ElfSectionType::ArmAttributes.raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::ArmDebugoverlay.raw(), 0x7000_0004);
        assert_eq!(ElfSectionType::ArmExidx.raw(), 0x7000_0001);
        assert_eq!(ElfSectionType::ArmOverlaysection.raw(), 0x7000_0005);
        assert_eq!(ElfSectionType::ArmPreemptmap.raw(), 0x7000_0002);
        assert_eq!(ElfSectionType::Crel.raw(), 0x4000_0014);
        assert_eq!(ElfSectionType::CskyAttributes.raw(), 0x7000_0001);
        assert_eq!(ElfSectionType::FiniArray.raw(), 15);
        assert_eq!(ElfSectionType::GnuAttributes.raw(), 0x6fff_fff5);
        assert_eq!(ElfSectionType::GnuHash.raw(), 0x6fff_fff6);
        assert_eq!(ElfSectionType::Group.raw(), 17);
        assert_eq!(ElfSectionType::Hash.raw(), 5);
        assert_eq!(ElfSectionType::HexagonAttributes.raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::HexOrdered.raw(), 0x7000_0000);
        assert_eq!(ElfSectionType::Hios.raw(), 0x6fff_ffff);
        assert_eq!(ElfSectionType::Hiproc.raw(), 0x7fff_ffff);
        assert_eq!(ElfSectionType::Hiuser.raw(), 0xffff_ffff);
        assert_eq!(ElfSectionType::InitArray.raw(), 14);
        assert_eq!(ElfSectionType::LlvmAddrsig.raw(), 0x6fff_4c03);
        assert_eq!(ElfSectionType::LlvmBbAddrMap.raw(), 0x6fff_4c0a);
        assert_eq!(ElfSectionType::LlvmCallGraphProfile.raw(), 0x6fff_4c09);
        assert_eq!(ElfSectionType::LlvmJtSizes.raw(), 0x6fff_4c0d);
        assert_eq!(ElfSectionType::LlvmLinkerOptions.raw(), 0x6fff_4c01);
        assert_eq!(ElfSectionType::LlvmLto.raw(), 0x6fff_4c0c);
        assert_eq!(ElfSectionType::LlvmOdrtab.raw(), 0x6fff_4c00);
        assert_eq!(ElfSectionType::LlvmOffloading.raw(), 0x6fff_4c0b);
        assert_eq!(ElfSectionType::LlvmPartEhdr.raw(), 0x6fff_4c06);
        assert_eq!(ElfSectionType::LlvmPartPhdr.raw(), 0x6fff_4c07);
        assert_eq!(ElfSectionType::LlvmSympart.raw(), 0x6fff_4c05);
        assert_eq!(ElfSectionType::Loos.raw(), 0x6000_0000);
        assert_eq!(ElfSectionType::Loproc.raw(), 0x7000_0000);
        assert_eq!(ElfSectionType::Louser.raw(), 0x8000_0000);
        assert_eq!(ElfSectionType::MipsAbiflags.raw(), 0x7000_002a);
        assert_eq!(ElfSectionType::MipsDwarf.raw(), 0x7000_001e);
        assert_eq!(ElfSectionType::MipsOptions.raw(), 0x7000_000d);
        assert_eq!(ElfSectionType::MipsReginfo.raw(), 0x7000_0006);
        assert_eq!(ElfSectionType::Msp430Attributes.raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::PreinitArray.raw(), 16);
        assert_eq!(ElfSectionType::Relr.raw(), 19);
        assert_eq!(ElfSectionType::RiscvAttributes.raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::Shlib.raw(), 10);
        assert_eq!(ElfSectionType::SymtabShndx.raw(), 18);
        assert_eq!(ElfSectionType::X8664Unwind.raw(), 0x7000_0001);
        assert_eq!(ElfSectionType::from_raw(0).raw(), 0);
        assert_eq!(ElfSectionType::from_raw(1).raw(), 1);
        assert_eq!(ElfSectionType::from_raw(2).raw(), 2);
        assert_eq!(ElfSectionType::from_raw(3).raw(), 3);
        assert_eq!(ElfSectionType::from_raw(4).raw(), 4);
        assert_eq!(ElfSectionType::from_raw(6).raw(), 6);
        assert_eq!(ElfSectionType::from_raw(7).raw(), 7);
        assert_eq!(ElfSectionType::from_raw(8).raw(), 8);
        assert_eq!(ElfSectionType::from_raw(9).raw(), 9);
        assert_eq!(ElfSectionType::from_raw(11).raw(), 11);
        assert_eq!(ElfSectionType::from_raw(0x7000_0003).raw(), 0x7000_0003);
        assert_eq!(ElfSectionType::from_raw(0x7000_0004).raw(), 0x7000_0004);
        assert_eq!(ElfSectionType::from_raw(0x7000_0008).raw(), 0x7000_0008);
        assert_eq!(ElfSectionType::from_raw(0x7000_0007).raw(), 0x7000_0007);
        assert_eq!(ElfSectionType::from_raw(0x6000_0001).raw(), 0x6000_0001);
        assert_eq!(ElfSectionType::from_raw(0x6000_0002).raw(), 0x6000_0002);
        assert_eq!(ElfSectionType::from_raw(0x6fff_ff00).raw(), 0x6fff_ff00);
        assert_eq!(ElfSectionType::from_raw(0x7000_0001).raw(), 0x7000_0001);
        assert_eq!(ElfSectionType::from_raw(0x7000_0005).raw(), 0x7000_0005);
        assert_eq!(ElfSectionType::from_raw(0x7000_0002).raw(), 0x7000_0002);
        assert_eq!(ElfSectionType::from_raw(0x4000_0014).raw(), 0x4000_0014);
        assert_eq!(ElfSectionType::from_raw(15).raw(), 15);
        assert_eq!(ElfSectionType::from_raw(0x6fff_fff5).raw(), 0x6fff_fff5);
        assert_eq!(ElfSectionType::from_raw(0x6fff_fff6).raw(), 0x6fff_fff6);
        assert_eq!(ElfSectionType::from_raw(17).raw(), 17);
        assert_eq!(ElfSectionType::from_raw(5).raw(), 5);
        assert_eq!(ElfSectionType::from_raw(0x7000_0000).raw(), 0x7000_0000);
        assert_eq!(ElfSectionType::from_raw(0x6fff_ffff).raw(), 0x6fff_ffff);
        assert_eq!(ElfSectionType::from_raw(0x7fff_ffff).raw(), 0x7fff_ffff);
        assert_eq!(ElfSectionType::from_raw(0xffff_ffff).raw(), 0xffff_ffff);
        assert_eq!(ElfSectionType::from_raw(14).raw(), 14);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c03).raw(), 0x6fff_4c03);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c0a).raw(), 0x6fff_4c0a);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c09).raw(), 0x6fff_4c09);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c0d).raw(), 0x6fff_4c0d);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c01).raw(), 0x6fff_4c01);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c0c).raw(), 0x6fff_4c0c);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c00).raw(), 0x6fff_4c00);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c0b).raw(), 0x6fff_4c0b);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c06).raw(), 0x6fff_4c06);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c07).raw(), 0x6fff_4c07);
        assert_eq!(ElfSectionType::from_raw(0x6fff_4c05).raw(), 0x6fff_4c05);
        assert_eq!(ElfSectionType::from_raw(0x6000_0000).raw(), 0x6000_0000);
        assert_eq!(ElfSectionType::from_raw(0x8000_0000).raw(), 0x8000_0000);
        assert_eq!(ElfSectionType::from_raw(0x7000_002a).raw(), 0x7000_002a);
        assert_eq!(ElfSectionType::from_raw(0x7000_001e).raw(), 0x7000_001e);
        assert_eq!(ElfSectionType::from_raw(0x7000_000d).raw(), 0x7000_000d);
        assert_eq!(ElfSectionType::from_raw(0x7000_0006).raw(), 0x7000_0006);
        assert_eq!(ElfSectionType::from_raw(16).raw(), 16);
        assert_eq!(ElfSectionType::from_raw(19).raw(), 19);
        assert_eq!(ElfSectionType::from_raw(10).raw(), 10);
        assert_eq!(ElfSectionType::from_raw(18).raw(), 18);
        assert_eq!(ElfSectionType::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfSectionIndex>::default().raw(), 0);
        assert_eq!(ElfSectionIndex::Abs.raw(), 0xfff1);
        assert_eq!(ElfSectionIndex::AmdgpuLds.raw(), 0xff00);
        assert_eq!(ElfSectionIndex::Common.raw(), 0xfff2);
        assert_eq!(ElfSectionIndex::HexagonScommon.raw(), 0xff00);
        assert_eq!(ElfSectionIndex::HexagonScommon1.raw(), 0xff01);
        assert_eq!(ElfSectionIndex::HexagonScommon2.raw(), 0xff02);
        assert_eq!(ElfSectionIndex::HexagonScommon4.raw(), 0xff03);
        assert_eq!(ElfSectionIndex::HexagonScommon8.raw(), 0xff04);
        assert_eq!(ElfSectionIndex::Hios.raw(), 0xff3f);
        assert_eq!(ElfSectionIndex::Hiproc.raw(), 0xff1f);
        assert_eq!(ElfSectionIndex::Hireserve.raw(), 0xffff);
        assert_eq!(ElfSectionIndex::Loos.raw(), 0xff20);
        assert_eq!(ElfSectionIndex::Loproc.raw(), 0xff00);
        assert_eq!(ElfSectionIndex::Loreserve.raw(), 0xff00);
        assert_eq!(ElfSectionIndex::MipsAcommon.raw(), 0xff00);
        assert_eq!(ElfSectionIndex::MipsData.raw(), 0xff02);
        assert_eq!(ElfSectionIndex::MipsScommon.raw(), 0xff03);
        assert_eq!(ElfSectionIndex::MipsSundefined.raw(), 0xff04);
        assert_eq!(ElfSectionIndex::MipsText.raw(), 0xff01);
        assert_eq!(ElfSectionIndex::Undef.raw(), 0);
        assert_eq!(ElfSectionIndex::Xindex.raw(), 0xffff);
        assert_eq!(ElfSectionIndex::from_raw(0xfff1).raw(), 0xfff1);
        assert_eq!(ElfSectionIndex::from_raw(0xff00).raw(), 0xff00);
        assert_eq!(ElfSectionIndex::from_raw(0xfff2).raw(), 0xfff2);
        assert_eq!(ElfSectionIndex::from_raw(0xff01).raw(), 0xff01);
        assert_eq!(ElfSectionIndex::from_raw(0xff02).raw(), 0xff02);
        assert_eq!(ElfSectionIndex::from_raw(0xff03).raw(), 0xff03);
        assert_eq!(ElfSectionIndex::from_raw(0xff04).raw(), 0xff04);
        assert_eq!(ElfSectionIndex::from_raw(0xff3f).raw(), 0xff3f);
        assert_eq!(ElfSectionIndex::from_raw(0xff1f).raw(), 0xff1f);
        assert_eq!(ElfSectionIndex::from_raw(0xffff).raw(), 0xffff);
        assert_eq!(ElfSectionIndex::from_raw(0xff20).raw(), 0xff20);
        assert_eq!(ElfSectionIndex::from_raw(0).raw(), 0);
        assert_eq!(ElfSectionIndex::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfSymbolBind>::default().raw(), 0);
        assert_eq!(ElfSymbolBind::Local.raw(), 0);
        assert_eq!(ElfSymbolBind::Global.raw(), 1);
        assert_eq!(ElfSymbolBind::Weak.raw(), 2);
        assert_eq!(ElfSymbolBind::GnuUnique.raw(), 10);
        assert_eq!(ElfSymbolBind::Hios.raw(), 12);
        assert_eq!(ElfSymbolBind::Hiproc.raw(), 15);
        assert_eq!(ElfSymbolBind::Loos.raw(), 10);
        assert_eq!(ElfSymbolBind::Loproc.raw(), 13);
        assert_eq!(ElfSymbolBind::from_raw(0).raw(), 0);
        assert_eq!(ElfSymbolBind::from_raw(1).raw(), 1);
        assert_eq!(ElfSymbolBind::from_raw(2).raw(), 2);
        assert_eq!(ElfSymbolBind::from_raw(10).raw(), 10);
        assert_eq!(ElfSymbolBind::from_raw(12).raw(), 12);
        assert_eq!(ElfSymbolBind::from_raw(15).raw(), 15);
        assert_eq!(ElfSymbolBind::from_raw(13).raw(), 13);
        assert_eq!(ElfSymbolBind::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfSymbolType>::default().raw(), 0);
        assert_eq!(ElfSymbolType::NoType.raw(), 0);
        assert_eq!(ElfSymbolType::Object.raw(), 1);
        assert_eq!(ElfSymbolType::Function.raw(), 2);
        assert_eq!(ElfSymbolType::Section.raw(), 3);
        assert_eq!(ElfSymbolType::File.raw(), 4);
        assert_eq!(ElfSymbolType::Common.raw(), 5);
        assert_eq!(ElfSymbolType::Tls.raw(), 6);
        assert_eq!(ElfSymbolType::AmdgpuHsaKernel.raw(), 10);
        assert_eq!(ElfSymbolType::Func.raw(), 2);
        assert_eq!(ElfSymbolType::GnuIfunc.raw(), 10);
        assert_eq!(ElfSymbolType::Hios.raw(), 12);
        assert_eq!(ElfSymbolType::Hiproc.raw(), 15);
        assert_eq!(ElfSymbolType::Loos.raw(), 10);
        assert_eq!(ElfSymbolType::Loproc.raw(), 13);
        assert_eq!(ElfSymbolType::Notype.raw(), 0);
        assert_eq!(ElfSymbolType::from_raw(0).raw(), 0);
        assert_eq!(ElfSymbolType::from_raw(1).raw(), 1);
        assert_eq!(ElfSymbolType::from_raw(2).raw(), 2);
        assert_eq!(ElfSymbolType::from_raw(3).raw(), 3);
        assert_eq!(ElfSymbolType::from_raw(4).raw(), 4);
        assert_eq!(ElfSymbolType::from_raw(5).raw(), 5);
        assert_eq!(ElfSymbolType::from_raw(6).raw(), 6);
        assert_eq!(ElfSymbolType::from_raw(10).raw(), 10);
        assert_eq!(ElfSymbolType::from_raw(12).raw(), 12);
        assert_eq!(ElfSymbolType::from_raw(15).raw(), 15);
        assert_eq!(ElfSymbolType::from_raw(13).raw(), 13);
        assert_eq!(ElfSymbolType::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfSymbolVisibility>::default().raw(), 0);
        assert_eq!(ElfSymbolVisibility::Default.raw(), 0);
        assert_eq!(ElfSymbolVisibility::Internal.raw(), 1);
        assert_eq!(ElfSymbolVisibility::Hidden.raw(), 2);
        assert_eq!(ElfSymbolVisibility::Protected.raw(), 3);
        assert_eq!(ElfSymbolVisibility::from_raw(0).raw(), 0);
        assert_eq!(ElfSymbolVisibility::from_raw(1).raw(), 1);
        assert_eq!(ElfSymbolVisibility::from_raw(2).raw(), 2);
        assert_eq!(ElfSymbolVisibility::from_raw(3).raw(), 3);
        assert_eq!(ElfSymbolVisibility::from_raw(0xfe).raw(), 0xfe);
        assert_eq!(<ElfRelocationType>::default().raw(), 0);
        assert_eq!(ElfRelocationType::None.raw(), 0);
        assert_eq!(ElfRelocationType::R38616.raw(), 20);
        assert_eq!(ElfRelocationType::R38632.raw(), 1);
        assert_eq!(ElfRelocationType::R38632Plt.raw(), 11);
        assert_eq!(ElfRelocationType::R3868.raw(), 22);
        assert_eq!(ElfRelocationType::R386Copy.raw(), 5);
        assert_eq!(ElfRelocationType::R386GlobDat.raw(), 6);
        assert_eq!(ElfRelocationType::R386Got32.raw(), 3);
        assert_eq!(ElfRelocationType::R386Got32X.raw(), 43);
        assert_eq!(ElfRelocationType::R386Gotoff.raw(), 9);
        assert_eq!(ElfRelocationType::R386Gotpc.raw(), 10);
        assert_eq!(ElfRelocationType::R386Irelative.raw(), 42);
        assert_eq!(ElfRelocationType::R386JumpSlot.raw(), 7);
        assert_eq!(ElfRelocationType::R386None.raw(), 0);
        assert_eq!(ElfRelocationType::R386Pc16.raw(), 21);
        assert_eq!(ElfRelocationType::R386Pc32.raw(), 2);
        assert_eq!(ElfRelocationType::R386Pc8.raw(), 23);
        assert_eq!(ElfRelocationType::R386Plt32.raw(), 4);
        assert_eq!(ElfRelocationType::R386Relative.raw(), 8);
        assert_eq!(ElfRelocationType::R386TlsDesc.raw(), 41);
        assert_eq!(ElfRelocationType::R386TlsDescCall.raw(), 40);
        assert_eq!(ElfRelocationType::R386TlsDtpmod32.raw(), 35);
        assert_eq!(ElfRelocationType::R386TlsDtpoff32.raw(), 36);
        assert_eq!(ElfRelocationType::R386TlsGd.raw(), 18);
        assert_eq!(ElfRelocationType::R386TlsGd32.raw(), 24);
        assert_eq!(ElfRelocationType::R386TlsGdCall.raw(), 26);
        assert_eq!(ElfRelocationType::R386TlsGdPop.raw(), 27);
        assert_eq!(ElfRelocationType::R386TlsGdPush.raw(), 25);
        assert_eq!(ElfRelocationType::R386TlsGotdesc.raw(), 39);
        assert_eq!(ElfRelocationType::R386TlsGotie.raw(), 16);
        assert_eq!(ElfRelocationType::R386TlsIe.raw(), 15);
        assert_eq!(ElfRelocationType::R386TlsIe32.raw(), 33);
        assert_eq!(ElfRelocationType::R386TlsLdm.raw(), 19);
        assert_eq!(ElfRelocationType::R386TlsLdm32.raw(), 28);
        assert_eq!(ElfRelocationType::R386TlsLdmCall.raw(), 30);
        assert_eq!(ElfRelocationType::R386TlsLdmPop.raw(), 31);
        assert_eq!(ElfRelocationType::R386TlsLdmPush.raw(), 29);
        assert_eq!(ElfRelocationType::R386TlsLdo32.raw(), 32);
        assert_eq!(ElfRelocationType::R386TlsLe.raw(), 17);
        assert_eq!(ElfRelocationType::R386TlsLe32.raw(), 34);
        assert_eq!(ElfRelocationType::R386TlsTpoff.raw(), 14);
        assert_eq!(ElfRelocationType::R386TlsTpoff32.raw(), 37);
        assert_eq!(ElfRelocationType::R39012.raw(), 2);
        assert_eq!(ElfRelocationType::R39016.raw(), 3);
        assert_eq!(ElfRelocationType::R39020.raw(), 57);
        assert_eq!(ElfRelocationType::R39032.raw(), 4);
        assert_eq!(ElfRelocationType::R39064.raw(), 22);
        assert_eq!(ElfRelocationType::R3908.raw(), 1);
        assert_eq!(ElfRelocationType::R390Copy.raw(), 9);
        assert_eq!(ElfRelocationType::R390GlobDat.raw(), 10);
        assert_eq!(ElfRelocationType::R390Got12.raw(), 6);
        assert_eq!(ElfRelocationType::R390Got16.raw(), 15);
        assert_eq!(ElfRelocationType::R390Got20.raw(), 58);
        assert_eq!(ElfRelocationType::R390Got32.raw(), 7);
        assert_eq!(ElfRelocationType::R390Got64.raw(), 24);
        assert_eq!(ElfRelocationType::R390Gotent.raw(), 26);
        assert_eq!(ElfRelocationType::R390Gotoff.raw(), 13);
        assert_eq!(ElfRelocationType::R390Gotoff16.raw(), 27);
        assert_eq!(ElfRelocationType::R390Gotoff64.raw(), 28);
        assert_eq!(ElfRelocationType::R390Gotpc.raw(), 14);
        assert_eq!(ElfRelocationType::R390Gotpcdbl.raw(), 21);
        assert_eq!(ElfRelocationType::R390Gotplt12.raw(), 29);
        assert_eq!(ElfRelocationType::R390Gotplt16.raw(), 30);
        assert_eq!(ElfRelocationType::R390Gotplt20.raw(), 59);
        assert_eq!(ElfRelocationType::R390Gotplt32.raw(), 31);
        assert_eq!(ElfRelocationType::R390Gotplt64.raw(), 32);
        assert_eq!(ElfRelocationType::R390Gotpltent.raw(), 33);
        assert_eq!(ElfRelocationType::R390Irelative.raw(), 61);
        assert_eq!(ElfRelocationType::R390JmpSlot.raw(), 11);
        assert_eq!(ElfRelocationType::R390None.raw(), 0);
        assert_eq!(ElfRelocationType::R390Pc12Dbl.raw(), 62);
        assert_eq!(ElfRelocationType::R390Pc16.raw(), 16);
        assert_eq!(ElfRelocationType::R390Pc16Dbl.raw(), 17);
        assert_eq!(ElfRelocationType::R390Pc24Dbl.raw(), 64);
        assert_eq!(ElfRelocationType::R390Pc32.raw(), 5);
        assert_eq!(ElfRelocationType::R390Pc32Dbl.raw(), 19);
        assert_eq!(ElfRelocationType::R390Pc64.raw(), 23);
        assert_eq!(ElfRelocationType::R390Plt12Dbl.raw(), 63);
        assert_eq!(ElfRelocationType::R390Plt16Dbl.raw(), 18);
        assert_eq!(ElfRelocationType::R390Plt24Dbl.raw(), 65);
        assert_eq!(ElfRelocationType::R390Plt32.raw(), 8);
        assert_eq!(ElfRelocationType::R390Plt32Dbl.raw(), 20);
        assert_eq!(ElfRelocationType::R390Plt64.raw(), 25);
        assert_eq!(ElfRelocationType::R390Pltoff16.raw(), 34);
        assert_eq!(ElfRelocationType::R390Pltoff32.raw(), 35);
        assert_eq!(ElfRelocationType::R390Pltoff64.raw(), 36);
        assert_eq!(ElfRelocationType::R390Relative.raw(), 12);
        assert_eq!(ElfRelocationType::R390TlsDtpmod.raw(), 54);
        assert_eq!(ElfRelocationType::R390TlsDtpoff.raw(), 55);
        assert_eq!(ElfRelocationType::R390TlsGd32.raw(), 40);
        assert_eq!(ElfRelocationType::R390TlsGd64.raw(), 41);
        assert_eq!(ElfRelocationType::R390TlsGdcall.raw(), 38);
        assert_eq!(ElfRelocationType::R390TlsGotie12.raw(), 42);
        assert_eq!(ElfRelocationType::R390TlsGotie20.raw(), 60);
        assert_eq!(ElfRelocationType::R390TlsGotie32.raw(), 43);
        assert_eq!(ElfRelocationType::R390TlsGotie64.raw(), 44);
        assert_eq!(ElfRelocationType::R390TlsIe32.raw(), 47);
        assert_eq!(ElfRelocationType::R390TlsIe64.raw(), 48);
        assert_eq!(ElfRelocationType::R390TlsIeent.raw(), 49);
        assert_eq!(ElfRelocationType::R390TlsLdcall.raw(), 39);
        assert_eq!(ElfRelocationType::R390TlsLdm32.raw(), 45);
        assert_eq!(ElfRelocationType::R390TlsLdm64.raw(), 46);
        assert_eq!(ElfRelocationType::R390TlsLdo32.raw(), 52);
        assert_eq!(ElfRelocationType::R390TlsLdo64.raw(), 53);
        assert_eq!(ElfRelocationType::R390TlsLe32.raw(), 50);
        assert_eq!(ElfRelocationType::R390TlsLe64.raw(), 51);
        assert_eq!(ElfRelocationType::R390TlsLoad.raw(), 37);
        assert_eq!(ElfRelocationType::R390TlsTpoff.raw(), 56);
        assert_eq!(ElfRelocationType::R68K16.raw(), 2);
        assert_eq!(ElfRelocationType::R68K32.raw(), 1);
        assert_eq!(ElfRelocationType::R68K8.raw(), 3);
        assert_eq!(ElfRelocationType::R68KCopy.raw(), 19);
        assert_eq!(ElfRelocationType::R68KGlobDat.raw(), 20);
        assert_eq!(ElfRelocationType::R68KGnuVtentry.raw(), 24);
        assert_eq!(ElfRelocationType::R68KGnuVtinherit.raw(), 23);
        assert_eq!(ElfRelocationType::R68KGotoff16.raw(), 11);
        assert_eq!(ElfRelocationType::R68KGotoff32.raw(), 10);
        assert_eq!(ElfRelocationType::R68KGotoff8.raw(), 12);
        assert_eq!(ElfRelocationType::R68KGotpcrel16.raw(), 8);
        assert_eq!(ElfRelocationType::R68KGotpcrel32.raw(), 7);
        assert_eq!(ElfRelocationType::R68KGotpcrel8.raw(), 9);
        assert_eq!(ElfRelocationType::R68KJmpSlot.raw(), 21);
        assert_eq!(ElfRelocationType::R68KNone.raw(), 0);
        assert_eq!(ElfRelocationType::R68KPc16.raw(), 5);
        assert_eq!(ElfRelocationType::R68KPc32.raw(), 4);
        assert_eq!(ElfRelocationType::R68KPc8.raw(), 6);
        assert_eq!(ElfRelocationType::R68KPlt16.raw(), 14);
        assert_eq!(ElfRelocationType::R68KPlt32.raw(), 13);
        assert_eq!(ElfRelocationType::R68KPlt8.raw(), 15);
        assert_eq!(ElfRelocationType::R68KPltoff16.raw(), 17);
        assert_eq!(ElfRelocationType::R68KPltoff32.raw(), 16);
        assert_eq!(ElfRelocationType::R68KPltoff8.raw(), 18);
        assert_eq!(ElfRelocationType::R68KRelative.raw(), 22);
        assert_eq!(ElfRelocationType::R68KTlsDtpmod32.raw(), 40);
        assert_eq!(ElfRelocationType::R68KTlsDtprel32.raw(), 41);
        assert_eq!(ElfRelocationType::R68KTlsGd16.raw(), 26);
        assert_eq!(ElfRelocationType::R68KTlsGd32.raw(), 25);
        assert_eq!(ElfRelocationType::R68KTlsGd8.raw(), 27);
        assert_eq!(ElfRelocationType::R68KTlsIe16.raw(), 35);
        assert_eq!(ElfRelocationType::R68KTlsIe32.raw(), 34);
        assert_eq!(ElfRelocationType::R68KTlsIe8.raw(), 36);
        assert_eq!(ElfRelocationType::R68KTlsLdm16.raw(), 29);
        assert_eq!(ElfRelocationType::R68KTlsLdm32.raw(), 28);
        assert_eq!(ElfRelocationType::R68KTlsLdm8.raw(), 30);
        assert_eq!(ElfRelocationType::R68KTlsLdo16.raw(), 32);
        assert_eq!(ElfRelocationType::R68KTlsLdo32.raw(), 31);
        assert_eq!(ElfRelocationType::R68KTlsLdo8.raw(), 33);
        assert_eq!(ElfRelocationType::R68KTlsLe16.raw(), 38);
        assert_eq!(ElfRelocationType::R68KTlsLe32.raw(), 37);
        assert_eq!(ElfRelocationType::R68KTlsLe8.raw(), 39);
        assert_eq!(ElfRelocationType::R68KTlsTprel32.raw(), 42);
        assert_eq!(ElfRelocationType::RAarch64Abs16.raw(), 259);
        assert_eq!(ElfRelocationType::RAarch64Abs32.raw(), 258);
        assert_eq!(ElfRelocationType::RAarch64Abs64.raw(), 257);
        assert_eq!(ElfRelocationType::RAarch64AddAbsLo12Nc.raw(), 277);
        assert_eq!(ElfRelocationType::RAarch64AdrGotPage.raw(), 311);
        assert_eq!(ElfRelocationType::RAarch64AdrPrelLo21.raw(), 274);
        assert_eq!(ElfRelocationType::RAarch64AdrPrelPgHi21.raw(), 275);
        assert_eq!(ElfRelocationType::RAarch64AdrPrelPgHi21Nc.raw(), 276);
        assert_eq!(ElfRelocationType::RAarch64AuthAbs64.raw(), 580);
        assert_eq!(ElfRelocationType::RAarch64AuthAdrGotPage.raw(), 590);
        assert_eq!(ElfRelocationType::RAarch64AuthGlobDat.raw(), 1042);
        assert_eq!(ElfRelocationType::RAarch64AuthGotAddLo12Nc.raw(), 593);
        assert_eq!(ElfRelocationType::RAarch64AuthGotAdrPrelLo21.raw(), 594);
        assert_eq!(ElfRelocationType::RAarch64AuthGotLdPrel19.raw(), 588);
        assert_eq!(ElfRelocationType::RAarch64AuthIrelative.raw(), 1044);
        assert_eq!(ElfRelocationType::RAarch64AuthLd64GotoffLo15.raw(), 589);
        assert_eq!(ElfRelocationType::RAarch64AuthLd64GotpageLo15.raw(), 592);
        assert_eq!(ElfRelocationType::RAarch64AuthLd64GotLo12Nc.raw(), 591);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG0.raw(), 581);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG0Nc.raw(), 582);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG1.raw(), 583);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG1Nc.raw(), 584);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG2.raw(), 585);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG2Nc.raw(), 586);
        assert_eq!(ElfRelocationType::RAarch64AuthMovwGotoffG3.raw(), 587);
        assert_eq!(ElfRelocationType::RAarch64AuthRelative.raw(), 1041);
        assert_eq!(ElfRelocationType::RAarch64AuthTlsdesc.raw(), 1043);
        assert_eq!(ElfRelocationType::RAarch64AuthTlsdescAddLo12.raw(), 597);
        assert_eq!(ElfRelocationType::RAarch64AuthTlsdescAdrPage21.raw(), 595);
        assert_eq!(ElfRelocationType::RAarch64AuthTlsdescLd64Lo12.raw(), 596);
        assert_eq!(ElfRelocationType::RAarch64Call26.raw(), 283);
        assert_eq!(ElfRelocationType::RAarch64Condbr19.raw(), 280);
        assert_eq!(ElfRelocationType::RAarch64Copy.raw(), 1024);
        assert_eq!(ElfRelocationType::RAarch64GlobDat.raw(), 1025);
        assert_eq!(ElfRelocationType::RAarch64Gotpcrel32.raw(), 315);
        assert_eq!(ElfRelocationType::RAarch64Gotrel32.raw(), 308);
        assert_eq!(ElfRelocationType::RAarch64Gotrel64.raw(), 307);
        assert_eq!(ElfRelocationType::RAarch64GotLdPrel19.raw(), 309);
        assert_eq!(ElfRelocationType::RAarch64Irelative.raw(), 1032);
        assert_eq!(ElfRelocationType::RAarch64Jump26.raw(), 282);
        assert_eq!(ElfRelocationType::RAarch64JumpSlot.raw(), 1026);
        assert_eq!(ElfRelocationType::RAarch64Ld64GotoffLo15.raw(), 310);
        assert_eq!(ElfRelocationType::RAarch64Ld64GotpageLo15.raw(), 313);
        assert_eq!(ElfRelocationType::RAarch64Ld64GotLo12Nc.raw(), 312);
        assert_eq!(ElfRelocationType::RAarch64Ldst128AbsLo12Nc.raw(), 299);
        assert_eq!(ElfRelocationType::RAarch64Ldst16AbsLo12Nc.raw(), 284);
        assert_eq!(ElfRelocationType::RAarch64Ldst32AbsLo12Nc.raw(), 285);
        assert_eq!(ElfRelocationType::RAarch64Ldst64AbsLo12Nc.raw(), 286);
        assert_eq!(ElfRelocationType::RAarch64Ldst8AbsLo12Nc.raw(), 278);
        assert_eq!(ElfRelocationType::RAarch64LdPrelLo19.raw(), 273);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG0.raw(), 300);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG0Nc.raw(), 301);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG1.raw(), 302);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG1Nc.raw(), 303);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG2.raw(), 304);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG2Nc.raw(), 305);
        assert_eq!(ElfRelocationType::RAarch64MovwGotoffG3.raw(), 306);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG0.raw(), 287);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG0Nc.raw(), 288);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG1.raw(), 289);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG1Nc.raw(), 290);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG2.raw(), 291);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG2Nc.raw(), 292);
        assert_eq!(ElfRelocationType::RAarch64MovwPrelG3.raw(), 293);
        assert_eq!(ElfRelocationType::RAarch64MovwSabsG0.raw(), 270);
        assert_eq!(ElfRelocationType::RAarch64MovwSabsG1.raw(), 271);
        assert_eq!(ElfRelocationType::RAarch64MovwSabsG2.raw(), 272);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG0.raw(), 263);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG0Nc.raw(), 264);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG1.raw(), 265);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG1Nc.raw(), 266);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG2.raw(), 267);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG2Nc.raw(), 268);
        assert_eq!(ElfRelocationType::RAarch64MovwUabsG3.raw(), 269);
        assert_eq!(ElfRelocationType::RAarch64None.raw(), 0);
        assert_eq!(ElfRelocationType::RAarch64P32Abs16.raw(), 2);
        assert_eq!(ElfRelocationType::RAarch64P32Abs32.raw(), 1);
        assert_eq!(ElfRelocationType::RAarch64P32AddAbsLo12Nc.raw(), 12);
        assert_eq!(ElfRelocationType::RAarch64P32AdrGotPage.raw(), 26);
        assert_eq!(ElfRelocationType::RAarch64P32AdrPrelLo21.raw(), 10);
        assert_eq!(ElfRelocationType::RAarch64P32AdrPrelPgHi21.raw(), 11);
        assert_eq!(ElfRelocationType::RAarch64P32Call26.raw(), 21);
        assert_eq!(ElfRelocationType::RAarch64P32Condbr19.raw(), 19);
        assert_eq!(ElfRelocationType::RAarch64P32Copy.raw(), 180);
        assert_eq!(ElfRelocationType::RAarch64P32GlobDat.raw(), 181);
        assert_eq!(ElfRelocationType::RAarch64P32GotLdPrel19.raw(), 25);
        assert_eq!(ElfRelocationType::RAarch64P32Irelative.raw(), 188);
        assert_eq!(ElfRelocationType::RAarch64P32Jump26.raw(), 20);
        assert_eq!(ElfRelocationType::RAarch64P32JumpSlot.raw(), 182);
        assert_eq!(ElfRelocationType::RAarch64P32Ld32GotpageLo14.raw(), 28);
        assert_eq!(ElfRelocationType::RAarch64P32Ld32GotLo12Nc.raw(), 27);
        assert_eq!(ElfRelocationType::RAarch64P32Ldst128AbsLo12Nc.raw(), 17);
        assert_eq!(ElfRelocationType::RAarch64P32Ldst16AbsLo12Nc.raw(), 14);
        assert_eq!(ElfRelocationType::RAarch64P32Ldst32AbsLo12Nc.raw(), 15);
        assert_eq!(ElfRelocationType::RAarch64P32Ldst64AbsLo12Nc.raw(), 16);
        assert_eq!(ElfRelocationType::RAarch64P32Ldst8AbsLo12Nc.raw(), 13);
        assert_eq!(ElfRelocationType::RAarch64P32LdPrelLo19.raw(), 9);
        assert_eq!(ElfRelocationType::RAarch64P32MovwPrelG0.raw(), 22);
        assert_eq!(ElfRelocationType::RAarch64P32MovwPrelG0Nc.raw(), 23);
        assert_eq!(ElfRelocationType::RAarch64P32MovwPrelG1.raw(), 24);
        assert_eq!(ElfRelocationType::RAarch64P32MovwSabsG0.raw(), 8);
        assert_eq!(ElfRelocationType::RAarch64P32MovwUabsG0.raw(), 5);
        assert_eq!(ElfRelocationType::RAarch64P32MovwUabsG0Nc.raw(), 6);
        assert_eq!(ElfRelocationType::RAarch64P32MovwUabsG1.raw(), 7);
        assert_eq!(ElfRelocationType::RAarch64P32None.raw(), 0);
        assert_eq!(ElfRelocationType::RAarch64P32Plt32.raw(), 29);
        assert_eq!(ElfRelocationType::RAarch64P32Prel16.raw(), 4);
        assert_eq!(ElfRelocationType::RAarch64P32Prel32.raw(), 3);
        assert_eq!(ElfRelocationType::RAarch64P32Relative.raw(), 183);
        assert_eq!(ElfRelocationType::RAarch64P32Tlsdesc.raw(), 187);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescAddLo12.raw(), 126);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescAdrPage21.raw(), 124);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescAdrPrel21.raw(), 123);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescCall.raw(), 127);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescLd32Lo12.raw(), 125);
        assert_eq!(ElfRelocationType::RAarch64P32TlsdescLdPrel19.raw(), 122);
        assert_eq!(ElfRelocationType::RAarch64P32TlsgdAddLo12Nc.raw(), 82);
        assert_eq!(ElfRelocationType::RAarch64P32TlsgdAdrPage21.raw(), 81);
        assert_eq!(ElfRelocationType::RAarch64P32TlsgdAdrPrel21.raw(), 80);
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsieAdrGottprelPage21.raw(),
            103
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsieLd32GottprelLo12Nc.raw(),
            104
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsieLdGottprelPrel19.raw(),
            105
        );
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAddDtprelHi12.raw(), 90);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAddDtprelLo12.raw(), 91);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAddDtprelLo12Nc.raw(), 92);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAddLo12Nc.raw(), 85);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAdrPage21.raw(), 84);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldAdrPrel21.raw(), 83);
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst128DtprelLo12.raw(),
            101
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst128DtprelLo12Nc.raw(),
            102
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst16DtprelLo12.raw(),
            95
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst16DtprelLo12Nc.raw(),
            96
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst32DtprelLo12.raw(),
            97
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst32DtprelLo12Nc.raw(),
            98
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst64DtprelLo12.raw(),
            99
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst64DtprelLo12Nc.raw(),
            100
        );
        assert_eq!(ElfRelocationType::RAarch64P32TlsldLdst8DtprelLo12.raw(), 93);
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsldLdst8DtprelLo12Nc.raw(),
            94
        );
        assert_eq!(ElfRelocationType::RAarch64P32TlsldLdPrel19.raw(), 86);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldMovwDtprelG0.raw(), 88);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldMovwDtprelG0Nc.raw(), 89);
        assert_eq!(ElfRelocationType::RAarch64P32TlsldMovwDtprelG1.raw(), 87);
        assert_eq!(ElfRelocationType::RAarch64P32TlsleAddTprelHi12.raw(), 109);
        assert_eq!(ElfRelocationType::RAarch64P32TlsleAddTprelLo12.raw(), 110);
        assert_eq!(ElfRelocationType::RAarch64P32TlsleAddTprelLo12Nc.raw(), 111);
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst128TprelLo12.raw(),
            120
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst128TprelLo12Nc.raw(),
            121
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst16TprelLo12.raw(),
            114
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst16TprelLo12Nc.raw(),
            115
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst32TprelLo12.raw(),
            116
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst32TprelLo12Nc.raw(),
            117
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst64TprelLo12.raw(),
            118
        );
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst64TprelLo12Nc.raw(),
            119
        );
        assert_eq!(ElfRelocationType::RAarch64P32TlsleLdst8TprelLo12.raw(), 112);
        assert_eq!(
            ElfRelocationType::RAarch64P32TlsleLdst8TprelLo12Nc.raw(),
            113
        );
        assert_eq!(ElfRelocationType::RAarch64P32TlsleMovwTprelG0.raw(), 107);
        assert_eq!(ElfRelocationType::RAarch64P32TlsleMovwTprelG0Nc.raw(), 108);
        assert_eq!(ElfRelocationType::RAarch64P32TlsleMovwTprelG1.raw(), 106);
        assert_eq!(ElfRelocationType::RAarch64P32TlsDtpmod.raw(), 185);
        assert_eq!(ElfRelocationType::RAarch64P32TlsDtprel.raw(), 184);
        assert_eq!(ElfRelocationType::RAarch64P32TlsTprel.raw(), 186);
        assert_eq!(ElfRelocationType::RAarch64P32Tstbr14.raw(), 18);
        assert_eq!(ElfRelocationType::RAarch64Plt32.raw(), 314);
        assert_eq!(ElfRelocationType::RAarch64Prel16.raw(), 262);
        assert_eq!(ElfRelocationType::RAarch64Prel32.raw(), 261);
        assert_eq!(ElfRelocationType::RAarch64Prel64.raw(), 260);
        assert_eq!(ElfRelocationType::RAarch64Relative.raw(), 1027);
        assert_eq!(ElfRelocationType::RAarch64Tlsdesc.raw(), 1031);
        assert_eq!(ElfRelocationType::RAarch64TlsdescAdd.raw(), 568);
        assert_eq!(ElfRelocationType::RAarch64TlsdescAddLo12.raw(), 564);
        assert_eq!(ElfRelocationType::RAarch64TlsdescAdrPage21.raw(), 562);
        assert_eq!(ElfRelocationType::RAarch64TlsdescAdrPrel21.raw(), 561);
        assert_eq!(ElfRelocationType::RAarch64TlsdescCall.raw(), 569);
        assert_eq!(ElfRelocationType::RAarch64TlsdescLd64Lo12.raw(), 563);
        assert_eq!(ElfRelocationType::RAarch64TlsdescLdr.raw(), 567);
        assert_eq!(ElfRelocationType::RAarch64TlsdescLdPrel19.raw(), 560);
        assert_eq!(ElfRelocationType::RAarch64TlsdescOffG0Nc.raw(), 566);
        assert_eq!(ElfRelocationType::RAarch64TlsdescOffG1.raw(), 565);
        assert_eq!(ElfRelocationType::RAarch64TlsgdAddLo12Nc.raw(), 514);
        assert_eq!(ElfRelocationType::RAarch64TlsgdAdrPage21.raw(), 513);
        assert_eq!(ElfRelocationType::RAarch64TlsgdAdrPrel21.raw(), 512);
        assert_eq!(ElfRelocationType::RAarch64TlsgdMovwG0Nc.raw(), 516);
        assert_eq!(ElfRelocationType::RAarch64TlsgdMovwG1.raw(), 515);
        assert_eq!(ElfRelocationType::RAarch64TlsieAdrGottprelPage21.raw(), 541);
        assert_eq!(
            ElfRelocationType::RAarch64TlsieLd64GottprelLo12Nc.raw(),
            542
        );
        assert_eq!(ElfRelocationType::RAarch64TlsieLdGottprelPrel19.raw(), 543);
        assert_eq!(ElfRelocationType::RAarch64TlsieMovwGottprelG0Nc.raw(), 540);
        assert_eq!(ElfRelocationType::RAarch64TlsieMovwGottprelG1.raw(), 539);
        assert_eq!(ElfRelocationType::RAarch64TlsldAddDtprelHi12.raw(), 528);
        assert_eq!(ElfRelocationType::RAarch64TlsldAddDtprelLo12.raw(), 529);
        assert_eq!(ElfRelocationType::RAarch64TlsldAddDtprelLo12Nc.raw(), 530);
        assert_eq!(ElfRelocationType::RAarch64TlsldAddLo12Nc.raw(), 519);
        assert_eq!(ElfRelocationType::RAarch64TlsldAdrPage21.raw(), 518);
        assert_eq!(ElfRelocationType::RAarch64TlsldAdrPrel21.raw(), 517);
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst128DtprelLo12.raw(), 572);
        assert_eq!(
            ElfRelocationType::RAarch64TlsldLdst128DtprelLo12Nc.raw(),
            573
        );
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst16DtprelLo12.raw(), 533);
        assert_eq!(
            ElfRelocationType::RAarch64TlsldLdst16DtprelLo12Nc.raw(),
            534
        );
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst32DtprelLo12.raw(), 535);
        assert_eq!(
            ElfRelocationType::RAarch64TlsldLdst32DtprelLo12Nc.raw(),
            536
        );
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst64DtprelLo12.raw(), 537);
        assert_eq!(
            ElfRelocationType::RAarch64TlsldLdst64DtprelLo12Nc.raw(),
            538
        );
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst8DtprelLo12.raw(), 531);
        assert_eq!(ElfRelocationType::RAarch64TlsldLdst8DtprelLo12Nc.raw(), 532);
        assert_eq!(ElfRelocationType::RAarch64TlsldLdPrel19.raw(), 522);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwDtprelG0.raw(), 526);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwDtprelG0Nc.raw(), 527);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwDtprelG1.raw(), 524);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwDtprelG1Nc.raw(), 525);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwDtprelG2.raw(), 523);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwG0Nc.raw(), 521);
        assert_eq!(ElfRelocationType::RAarch64TlsldMovwG1.raw(), 520);
        assert_eq!(ElfRelocationType::RAarch64TlsleAddTprelHi12.raw(), 549);
        assert_eq!(ElfRelocationType::RAarch64TlsleAddTprelLo12.raw(), 550);
        assert_eq!(ElfRelocationType::RAarch64TlsleAddTprelLo12Nc.raw(), 551);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst128TprelLo12.raw(), 570);
        assert_eq!(
            ElfRelocationType::RAarch64TlsleLdst128TprelLo12Nc.raw(),
            571
        );
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst16TprelLo12.raw(), 554);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst16TprelLo12Nc.raw(), 555);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst32TprelLo12.raw(), 556);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst32TprelLo12Nc.raw(), 557);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst64TprelLo12.raw(), 558);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst64TprelLo12Nc.raw(), 559);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst8TprelLo12.raw(), 552);
        assert_eq!(ElfRelocationType::RAarch64TlsleLdst8TprelLo12Nc.raw(), 553);
        assert_eq!(ElfRelocationType::RAarch64TlsleMovwTprelG0.raw(), 547);
        assert_eq!(ElfRelocationType::RAarch64TlsleMovwTprelG0Nc.raw(), 548);
        assert_eq!(ElfRelocationType::RAarch64TlsleMovwTprelG1.raw(), 545);
        assert_eq!(ElfRelocationType::RAarch64TlsleMovwTprelG1Nc.raw(), 546);
        assert_eq!(ElfRelocationType::RAarch64TlsleMovwTprelG2.raw(), 544);
        assert_eq!(ElfRelocationType::RAarch64TlsDtpmod64.raw(), 1028);
        assert_eq!(ElfRelocationType::RAarch64TlsDtprel64.raw(), 1029);
        assert_eq!(ElfRelocationType::RAarch64TlsTprel64.raw(), 1030);
        assert_eq!(ElfRelocationType::RAarch64Tstbr14.raw(), 279);
        assert_eq!(ElfRelocationType::RAcSectoffS9.raw(), 38);
        assert_eq!(ElfRelocationType::RAcSectoffS91.raw(), 39);
        assert_eq!(ElfRelocationType::RAcSectoffS92.raw(), 40);
        assert_eq!(ElfRelocationType::RAcSectoffU8.raw(), 35);
        assert_eq!(ElfRelocationType::RAcSectoffU81.raw(), 36);
        assert_eq!(ElfRelocationType::RAcSectoffU82.raw(), 37);
        assert_eq!(ElfRelocationType::RAmdgpuAbs32.raw(), 6);
        assert_eq!(ElfRelocationType::RAmdgpuAbs32Hi.raw(), 2);
        assert_eq!(ElfRelocationType::RAmdgpuAbs32Lo.raw(), 1);
        assert_eq!(ElfRelocationType::RAmdgpuAbs64.raw(), 3);
        assert_eq!(ElfRelocationType::RAmdgpuGotpcrel.raw(), 7);
        assert_eq!(ElfRelocationType::RAmdgpuGotpcrel32Hi.raw(), 9);
        assert_eq!(ElfRelocationType::RAmdgpuGotpcrel32Lo.raw(), 8);
        assert_eq!(ElfRelocationType::RAmdgpuNone.raw(), 0);
        assert_eq!(ElfRelocationType::RAmdgpuRel16.raw(), 14);
        assert_eq!(ElfRelocationType::RAmdgpuRel32.raw(), 4);
        assert_eq!(ElfRelocationType::RAmdgpuRel32Hi.raw(), 11);
        assert_eq!(ElfRelocationType::RAmdgpuRel32Lo.raw(), 10);
        assert_eq!(ElfRelocationType::RAmdgpuRel64.raw(), 5);
        assert_eq!(ElfRelocationType::RAmdgpuRelative64.raw(), 13);
        assert_eq!(ElfRelocationType::RArc16.raw(), 2);
        assert_eq!(ElfRelocationType::RArc24.raw(), 3);
        assert_eq!(ElfRelocationType::RArc32.raw(), 4);
        assert_eq!(ElfRelocationType::RArc32Me.raw(), 27);
        assert_eq!(ElfRelocationType::RArc32MeS.raw(), 105);
        assert_eq!(ElfRelocationType::RArc32Pcrel.raw(), 49);
        assert_eq!(ElfRelocationType::RArc8.raw(), 1);
        assert_eq!(ElfRelocationType::RArcCopy.raw(), 53);
        assert_eq!(ElfRelocationType::RArcGlobDat.raw(), 54);
        assert_eq!(ElfRelocationType::RArcGot32.raw(), 59);
        assert_eq!(ElfRelocationType::RArcGotoff.raw(), 57);
        assert_eq!(ElfRelocationType::RArcGotpc.raw(), 58);
        assert_eq!(ElfRelocationType::RArcGotpc32.raw(), 51);
        assert_eq!(ElfRelocationType::RArcJliSectoff.raw(), 63);
        assert_eq!(ElfRelocationType::RArcJmpSlot.raw(), 55);
        assert_eq!(ElfRelocationType::RArcN16.raw(), 9);
        assert_eq!(ElfRelocationType::RArcN24.raw(), 10);
        assert_eq!(ElfRelocationType::RArcN32.raw(), 11);
        assert_eq!(ElfRelocationType::RArcN32Me.raw(), 28);
        assert_eq!(ElfRelocationType::RArcN8.raw(), 8);
        assert_eq!(ElfRelocationType::RArcNone.raw(), 0);
        assert_eq!(ElfRelocationType::RArcNpsCmem16.raw(), 78);
        assert_eq!(ElfRelocationType::RArcPc32.raw(), 50);
        assert_eq!(ElfRelocationType::RArcPlt32.raw(), 52);
        assert_eq!(ElfRelocationType::RArcRelative.raw(), 56);
        assert_eq!(ElfRelocationType::RArcS13Pcrel.raw(), 25);
        assert_eq!(ElfRelocationType::RArcS21HPcrel.raw(), 14);
        assert_eq!(ElfRelocationType::RArcS21HPcrelPlt.raw(), 77);
        assert_eq!(ElfRelocationType::RArcS21WPcrel.raw(), 15);
        assert_eq!(ElfRelocationType::RArcS21WPcrelPlt.raw(), 60);
        assert_eq!(ElfRelocationType::RArcS25HPcrel.raw(), 16);
        assert_eq!(ElfRelocationType::RArcS25HPcrelPlt.raw(), 61);
        assert_eq!(ElfRelocationType::RArcS25WPcrel.raw(), 17);
        assert_eq!(ElfRelocationType::RArcS25WPcrelPlt.raw(), 76);
        assert_eq!(ElfRelocationType::RArcSda.raw(), 12);
        assert_eq!(ElfRelocationType::RArcSda16Ld.raw(), 22);
        assert_eq!(ElfRelocationType::RArcSda16Ld1.raw(), 23);
        assert_eq!(ElfRelocationType::RArcSda16Ld2.raw(), 24);
        assert_eq!(ElfRelocationType::RArcSda16St2.raw(), 48);
        assert_eq!(ElfRelocationType::RArcSda32.raw(), 18);
        assert_eq!(ElfRelocationType::RArcSda32Me.raw(), 30);
        assert_eq!(ElfRelocationType::RArcSda12.raw(), 45);
        assert_eq!(ElfRelocationType::RArcSdaLdst.raw(), 19);
        assert_eq!(ElfRelocationType::RArcSdaLdst1.raw(), 20);
        assert_eq!(ElfRelocationType::RArcSdaLdst2.raw(), 21);
        assert_eq!(ElfRelocationType::RArcSectoff.raw(), 13);
        assert_eq!(ElfRelocationType::RArcSectoff1.raw(), 43);
        assert_eq!(ElfRelocationType::RArcSectoff2.raw(), 44);
        assert_eq!(ElfRelocationType::RArcSectoffMe.raw(), 29);
        assert_eq!(ElfRelocationType::RArcSectoffMe1.raw(), 41);
        assert_eq!(ElfRelocationType::RArcSectoffMe2.raw(), 42);
        assert_eq!(ElfRelocationType::RArcTlsDtpmod.raw(), 66);
        assert_eq!(ElfRelocationType::RArcTlsDtpoff.raw(), 67);
        assert_eq!(ElfRelocationType::RArcTlsDtpoffS9.raw(), 73);
        assert_eq!(ElfRelocationType::RArcTlsGdCall.raw(), 71);
        assert_eq!(ElfRelocationType::RArcTlsGdGot.raw(), 69);
        assert_eq!(ElfRelocationType::RArcTlsGdLd.raw(), 70);
        assert_eq!(ElfRelocationType::RArcTlsIeGot.raw(), 72);
        assert_eq!(ElfRelocationType::RArcTlsLe32.raw(), 75);
        assert_eq!(ElfRelocationType::RArcTlsLeS9.raw(), 74);
        assert_eq!(ElfRelocationType::RArcTlsTpoff.raw(), 68);
        assert_eq!(ElfRelocationType::RArcW.raw(), 26);
        assert_eq!(ElfRelocationType::RArcWMe.raw(), 31);
        assert_eq!(ElfRelocationType::RArmAbs12.raw(), 6);
        assert_eq!(ElfRelocationType::RArmAbs16.raw(), 5);
        assert_eq!(ElfRelocationType::RArmAbs32.raw(), 2);
        assert_eq!(ElfRelocationType::RArmAbs32Noi.raw(), 55);
        assert_eq!(ElfRelocationType::RArmAbs8.raw(), 8);
        assert_eq!(ElfRelocationType::RArmAluPcrel158.raw(), 33);
        assert_eq!(ElfRelocationType::RArmAluPcrel2315.raw(), 34);
        assert_eq!(ElfRelocationType::RArmAluPcrel70.raw(), 32);
        assert_eq!(ElfRelocationType::RArmAluPcG0.raw(), 58);
        assert_eq!(ElfRelocationType::RArmAluPcG0Nc.raw(), 57);
        assert_eq!(ElfRelocationType::RArmAluPcG1.raw(), 60);
        assert_eq!(ElfRelocationType::RArmAluPcG1Nc.raw(), 59);
        assert_eq!(ElfRelocationType::RArmAluPcG2.raw(), 61);
        assert_eq!(ElfRelocationType::RArmAluSbrel1912Nc.raw(), 36);
        assert_eq!(ElfRelocationType::RArmAluSbrel2720Ck.raw(), 37);
        assert_eq!(ElfRelocationType::RArmAluSbG0.raw(), 71);
        assert_eq!(ElfRelocationType::RArmAluSbG0Nc.raw(), 70);
        assert_eq!(ElfRelocationType::RArmAluSbG1.raw(), 73);
        assert_eq!(ElfRelocationType::RArmAluSbG1Nc.raw(), 72);
        assert_eq!(ElfRelocationType::RArmAluSbG2.raw(), 74);
        assert_eq!(ElfRelocationType::RArmBaseAbs.raw(), 31);
        assert_eq!(ElfRelocationType::RArmBasePrel.raw(), 25);
        assert_eq!(ElfRelocationType::RArmBrelAdj.raw(), 12);
        assert_eq!(ElfRelocationType::RArmCall.raw(), 28);
        assert_eq!(ElfRelocationType::RArmCopy.raw(), 20);
        assert_eq!(ElfRelocationType::RArmFuncdesc.raw(), 163);
        assert_eq!(ElfRelocationType::RArmFuncdescValue.raw(), 164);
        assert_eq!(ElfRelocationType::RArmGlobDat.raw(), 21);
        assert_eq!(ElfRelocationType::RArmGnuVtentry.raw(), 100);
        assert_eq!(ElfRelocationType::RArmGnuVtinherit.raw(), 101);
        assert_eq!(ElfRelocationType::RArmGotfuncdesc.raw(), 161);
        assert_eq!(ElfRelocationType::RArmGotoff12.raw(), 98);
        assert_eq!(ElfRelocationType::RArmGotoff32.raw(), 24);
        assert_eq!(ElfRelocationType::RArmGotofffuncdesc.raw(), 162);
        assert_eq!(ElfRelocationType::RArmGotrelax.raw(), 99);
        assert_eq!(ElfRelocationType::RArmGotAbs.raw(), 95);
        assert_eq!(ElfRelocationType::RArmGotBrel.raw(), 26);
        assert_eq!(ElfRelocationType::RArmGotBrel12.raw(), 97);
        assert_eq!(ElfRelocationType::RArmGotPrel.raw(), 96);
        assert_eq!(ElfRelocationType::RArmIrelative.raw(), 160);
        assert_eq!(ElfRelocationType::RArmJump24.raw(), 29);
        assert_eq!(ElfRelocationType::RArmJumpSlot.raw(), 22);
        assert_eq!(ElfRelocationType::RArmLdcPcG0.raw(), 67);
        assert_eq!(ElfRelocationType::RArmLdcPcG1.raw(), 68);
        assert_eq!(ElfRelocationType::RArmLdcPcG2.raw(), 69);
        assert_eq!(ElfRelocationType::RArmLdcSbG0.raw(), 81);
        assert_eq!(ElfRelocationType::RArmLdcSbG1.raw(), 82);
        assert_eq!(ElfRelocationType::RArmLdcSbG2.raw(), 83);
        assert_eq!(ElfRelocationType::RArmLdrsPcG0.raw(), 64);
        assert_eq!(ElfRelocationType::RArmLdrsPcG1.raw(), 65);
        assert_eq!(ElfRelocationType::RArmLdrsPcG2.raw(), 66);
        assert_eq!(ElfRelocationType::RArmLdrsSbG0.raw(), 78);
        assert_eq!(ElfRelocationType::RArmLdrsSbG1.raw(), 79);
        assert_eq!(ElfRelocationType::RArmLdrsSbG2.raw(), 80);
        assert_eq!(ElfRelocationType::RArmLdrPcG0.raw(), 4);
        assert_eq!(ElfRelocationType::RArmLdrPcG1.raw(), 62);
        assert_eq!(ElfRelocationType::RArmLdrPcG2.raw(), 63);
        assert_eq!(ElfRelocationType::RArmLdrSbrel110Nc.raw(), 35);
        assert_eq!(ElfRelocationType::RArmLdrSbG0.raw(), 75);
        assert_eq!(ElfRelocationType::RArmLdrSbG1.raw(), 76);
        assert_eq!(ElfRelocationType::RArmLdrSbG2.raw(), 77);
        assert_eq!(ElfRelocationType::RArmMeToo.raw(), 128);
        assert_eq!(ElfRelocationType::RArmMovtAbs.raw(), 44);
        assert_eq!(ElfRelocationType::RArmMovtBrel.raw(), 85);
        assert_eq!(ElfRelocationType::RArmMovtPrel.raw(), 46);
        assert_eq!(ElfRelocationType::RArmMovwAbsNc.raw(), 43);
        assert_eq!(ElfRelocationType::RArmMovwBrel.raw(), 86);
        assert_eq!(ElfRelocationType::RArmMovwBrelNc.raw(), 84);
        assert_eq!(ElfRelocationType::RArmMovwPrelNc.raw(), 45);
        assert_eq!(ElfRelocationType::RArmNone.raw(), 0);
        assert_eq!(ElfRelocationType::RArmPc24.raw(), 1);
        assert_eq!(ElfRelocationType::RArmPlt32.raw(), 27);
        assert_eq!(ElfRelocationType::RArmPlt32Abs.raw(), 94);
        assert_eq!(ElfRelocationType::RArmPrel31.raw(), 42);
        assert_eq!(ElfRelocationType::RArmPrivate0.raw(), 112);
        assert_eq!(ElfRelocationType::RArmPrivate1.raw(), 113);
        assert_eq!(ElfRelocationType::RArmPrivate10.raw(), 122);
        assert_eq!(ElfRelocationType::RArmPrivate11.raw(), 123);
        assert_eq!(ElfRelocationType::RArmPrivate12.raw(), 124);
        assert_eq!(ElfRelocationType::RArmPrivate13.raw(), 125);
        assert_eq!(ElfRelocationType::RArmPrivate14.raw(), 126);
        assert_eq!(ElfRelocationType::RArmPrivate15.raw(), 127);
        assert_eq!(ElfRelocationType::RArmPrivate2.raw(), 114);
        assert_eq!(ElfRelocationType::RArmPrivate3.raw(), 115);
        assert_eq!(ElfRelocationType::RArmPrivate4.raw(), 116);
        assert_eq!(ElfRelocationType::RArmPrivate5.raw(), 117);
        assert_eq!(ElfRelocationType::RArmPrivate6.raw(), 118);
        assert_eq!(ElfRelocationType::RArmPrivate7.raw(), 119);
        assert_eq!(ElfRelocationType::RArmPrivate8.raw(), 120);
        assert_eq!(ElfRelocationType::RArmPrivate9.raw(), 121);
        assert_eq!(ElfRelocationType::RArmRel32.raw(), 3);
        assert_eq!(ElfRelocationType::RArmRel32Noi.raw(), 56);
        assert_eq!(ElfRelocationType::RArmRelative.raw(), 23);
        assert_eq!(ElfRelocationType::RArmSbrel31.raw(), 39);
        assert_eq!(ElfRelocationType::RArmSbrel32.raw(), 9);
        assert_eq!(ElfRelocationType::RArmTarget1.raw(), 38);
        assert_eq!(ElfRelocationType::RArmTarget2.raw(), 41);
        assert_eq!(ElfRelocationType::RArmThmAbs5.raw(), 7);
        assert_eq!(ElfRelocationType::RArmThmAluAbsG0Nc.raw(), 132);
        assert_eq!(ElfRelocationType::RArmThmAluAbsG1Nc.raw(), 133);
        assert_eq!(ElfRelocationType::RArmThmAluAbsG2Nc.raw(), 134);
        assert_eq!(ElfRelocationType::RArmThmAluAbsG3.raw(), 135);
        assert_eq!(ElfRelocationType::RArmThmAluPrel110.raw(), 53);
        assert_eq!(ElfRelocationType::RArmThmBf12.raw(), 137);
        assert_eq!(ElfRelocationType::RArmThmBf16.raw(), 136);
        assert_eq!(ElfRelocationType::RArmThmBf18.raw(), 138);
        assert_eq!(ElfRelocationType::RArmThmCall.raw(), 10);
        assert_eq!(ElfRelocationType::RArmThmJump11.raw(), 102);
        assert_eq!(ElfRelocationType::RArmThmJump19.raw(), 51);
        assert_eq!(ElfRelocationType::RArmThmJump24.raw(), 30);
        assert_eq!(ElfRelocationType::RArmThmJump6.raw(), 52);
        assert_eq!(ElfRelocationType::RArmThmJump8.raw(), 103);
        assert_eq!(ElfRelocationType::RArmThmMovtAbs.raw(), 48);
        assert_eq!(ElfRelocationType::RArmThmMovtBrel.raw(), 88);
        assert_eq!(ElfRelocationType::RArmThmMovtPrel.raw(), 50);
        assert_eq!(ElfRelocationType::RArmThmMovwAbsNc.raw(), 47);
        assert_eq!(ElfRelocationType::RArmThmMovwBrel.raw(), 89);
        assert_eq!(ElfRelocationType::RArmThmMovwBrelNc.raw(), 87);
        assert_eq!(ElfRelocationType::RArmThmMovwPrelNc.raw(), 49);
        assert_eq!(ElfRelocationType::RArmThmPc12.raw(), 54);
        assert_eq!(ElfRelocationType::RArmThmPc8.raw(), 11);
        assert_eq!(ElfRelocationType::RArmThmSwi8.raw(), 14);
        assert_eq!(ElfRelocationType::RArmThmTlsCall.raw(), 93);
        assert_eq!(ElfRelocationType::RArmThmTlsDescseq16.raw(), 129);
        assert_eq!(ElfRelocationType::RArmThmTlsDescseq32.raw(), 130);
        assert_eq!(ElfRelocationType::RArmThmXpc22.raw(), 16);
        assert_eq!(ElfRelocationType::RArmTlsCall.raw(), 91);
        assert_eq!(ElfRelocationType::RArmTlsDesc.raw(), 13);
        assert_eq!(ElfRelocationType::RArmTlsDescseq.raw(), 92);
        assert_eq!(ElfRelocationType::RArmTlsDtpmod32.raw(), 17);
        assert_eq!(ElfRelocationType::RArmTlsDtpoff32.raw(), 18);
        assert_eq!(ElfRelocationType::RArmTlsGd32.raw(), 104);
        assert_eq!(ElfRelocationType::RArmTlsGd32Fdpic.raw(), 165);
        assert_eq!(ElfRelocationType::RArmTlsGotdesc.raw(), 90);
        assert_eq!(ElfRelocationType::RArmTlsIe12Gp.raw(), 111);
        assert_eq!(ElfRelocationType::RArmTlsIe32.raw(), 107);
        assert_eq!(ElfRelocationType::RArmTlsIe32Fdpic.raw(), 167);
        assert_eq!(ElfRelocationType::RArmTlsLdm32.raw(), 105);
        assert_eq!(ElfRelocationType::RArmTlsLdm32Fdpic.raw(), 166);
        assert_eq!(ElfRelocationType::RArmTlsLdo12.raw(), 109);
        assert_eq!(ElfRelocationType::RArmTlsLdo32.raw(), 106);
        assert_eq!(ElfRelocationType::RArmTlsLe12.raw(), 110);
        assert_eq!(ElfRelocationType::RArmTlsLe32.raw(), 108);
        assert_eq!(ElfRelocationType::RArmTlsTpoff32.raw(), 19);
        assert_eq!(ElfRelocationType::RArmV4Bx.raw(), 40);
        assert_eq!(ElfRelocationType::RArmXpc25.raw(), 15);
        assert_eq!(ElfRelocationType::RAvr13Pcrel.raw(), 3);
        assert_eq!(ElfRelocationType::RAvr16.raw(), 4);
        assert_eq!(ElfRelocationType::RAvr16Pm.raw(), 5);
        assert_eq!(ElfRelocationType::RAvr32.raw(), 1);
        assert_eq!(ElfRelocationType::RAvr6.raw(), 20);
        assert_eq!(ElfRelocationType::RAvr6Adiw.raw(), 21);
        assert_eq!(ElfRelocationType::RAvr7Pcrel.raw(), 2);
        assert_eq!(ElfRelocationType::RAvr8.raw(), 26);
        assert_eq!(ElfRelocationType::RAvr8Hi8.raw(), 28);
        assert_eq!(ElfRelocationType::RAvr8Hlo8.raw(), 29);
        assert_eq!(ElfRelocationType::RAvr8Lo8.raw(), 27);
        assert_eq!(ElfRelocationType::RAvrCall.raw(), 18);
        assert_eq!(ElfRelocationType::RAvrDiff16.raw(), 31);
        assert_eq!(ElfRelocationType::RAvrDiff32.raw(), 32);
        assert_eq!(ElfRelocationType::RAvrDiff8.raw(), 30);
        assert_eq!(ElfRelocationType::RAvrHh8Ldi.raw(), 8);
        assert_eq!(ElfRelocationType::RAvrHh8LdiNeg.raw(), 11);
        assert_eq!(ElfRelocationType::RAvrHh8LdiPm.raw(), 14);
        assert_eq!(ElfRelocationType::RAvrHh8LdiPmNeg.raw(), 17);
        assert_eq!(ElfRelocationType::RAvrHi8Ldi.raw(), 7);
        assert_eq!(ElfRelocationType::RAvrHi8LdiGs.raw(), 25);
        assert_eq!(ElfRelocationType::RAvrHi8LdiNeg.raw(), 10);
        assert_eq!(ElfRelocationType::RAvrHi8LdiPm.raw(), 13);
        assert_eq!(ElfRelocationType::RAvrHi8LdiPmNeg.raw(), 16);
        assert_eq!(ElfRelocationType::RAvrLdi.raw(), 19);
        assert_eq!(ElfRelocationType::RAvrLdsSts16.raw(), 33);
        assert_eq!(ElfRelocationType::RAvrLo8Ldi.raw(), 6);
        assert_eq!(ElfRelocationType::RAvrLo8LdiGs.raw(), 24);
        assert_eq!(ElfRelocationType::RAvrLo8LdiNeg.raw(), 9);
        assert_eq!(ElfRelocationType::RAvrLo8LdiPm.raw(), 12);
        assert_eq!(ElfRelocationType::RAvrLo8LdiPmNeg.raw(), 15);
        assert_eq!(ElfRelocationType::RAvrMs8Ldi.raw(), 22);
        assert_eq!(ElfRelocationType::RAvrMs8LdiNeg.raw(), 23);
        assert_eq!(ElfRelocationType::RAvrNone.raw(), 0);
        assert_eq!(ElfRelocationType::RAvrPort5.raw(), 35);
        assert_eq!(ElfRelocationType::RAvrPort6.raw(), 34);
        assert_eq!(ElfRelocationType::RBpf6432.raw(), 10);
        assert_eq!(ElfRelocationType::RBpf6464.raw(), 1);
        assert_eq!(ElfRelocationType::RBpf64Abs32.raw(), 3);
        assert_eq!(ElfRelocationType::RBpf64Abs64.raw(), 2);
        assert_eq!(ElfRelocationType::RBpf64Nodyld32.raw(), 4);
        assert_eq!(ElfRelocationType::RBpfNone.raw(), 0);
        assert_eq!(ElfRelocationType::RCkcoreAddr32.raw(), 1);
        assert_eq!(ElfRelocationType::RCkcoreAddrgot.raw(), 17);
        assert_eq!(ElfRelocationType::RCkcoreAddrgotHi16.raw(), 36);
        assert_eq!(ElfRelocationType::RCkcoreAddrgotLo16.raw(), 37);
        assert_eq!(ElfRelocationType::RCkcoreAddrplt.raw(), 18);
        assert_eq!(ElfRelocationType::RCkcoreAddrpltHi16.raw(), 38);
        assert_eq!(ElfRelocationType::RCkcoreAddrpltLo16.raw(), 39);
        assert_eq!(ElfRelocationType::RCkcoreAddrHi16.raw(), 24);
        assert_eq!(ElfRelocationType::RCkcoreAddrLo16.raw(), 25);
        assert_eq!(ElfRelocationType::RCkcoreCallgraph.raw(), 61);
        assert_eq!(ElfRelocationType::RCkcoreCopy.raw(), 10);
        assert_eq!(ElfRelocationType::RCkcoreDoffsetImm18.raw(), 44);
        assert_eq!(ElfRelocationType::RCkcoreDoffsetImm182.raw(), 45);
        assert_eq!(ElfRelocationType::RCkcoreDoffsetImm184.raw(), 46);
        assert_eq!(ElfRelocationType::RCkcoreDoffsetLo16.raw(), 42);
        assert_eq!(ElfRelocationType::RCkcoreGlobDat.raw(), 11);
        assert_eq!(ElfRelocationType::RCkcoreGnuVtentry.raw(), 8);
        assert_eq!(ElfRelocationType::RCkcoreGnuVtinherit.raw(), 7);
        assert_eq!(ElfRelocationType::RCkcoreGot12.raw(), 30);
        assert_eq!(ElfRelocationType::RCkcoreGot32.raw(), 15);
        assert_eq!(ElfRelocationType::RCkcoreGotoff.raw(), 13);
        assert_eq!(ElfRelocationType::RCkcoreGotoffHi16.raw(), 28);
        assert_eq!(ElfRelocationType::RCkcoreGotoffImm18.raw(), 47);
        assert_eq!(ElfRelocationType::RCkcoreGotoffLo16.raw(), 29);
        assert_eq!(ElfRelocationType::RCkcoreGotpc.raw(), 14);
        assert_eq!(ElfRelocationType::RCkcoreGotpcHi16.raw(), 26);
        assert_eq!(ElfRelocationType::RCkcoreGotpcLo16.raw(), 27);
        assert_eq!(ElfRelocationType::RCkcoreGotHi16.raw(), 31);
        assert_eq!(ElfRelocationType::RCkcoreGotImm184.raw(), 48);
        assert_eq!(ElfRelocationType::RCkcoreGotLo16.raw(), 32);
        assert_eq!(ElfRelocationType::RCkcoreIrelative.raw(), 62);
        assert_eq!(ElfRelocationType::RCkcoreJumpSlot.raw(), 12);
        assert_eq!(ElfRelocationType::RCkcoreNojsri.raw(), 60);
        assert_eq!(ElfRelocationType::RCkcoreNone.raw(), 0);
        assert_eq!(ElfRelocationType::RCkcorePcrel32.raw(), 5);
        assert_eq!(ElfRelocationType::RCkcorePcrelBloopImm124.raw(), 64);
        assert_eq!(ElfRelocationType::RCkcorePcrelBloopImm44.raw(), 63);
        assert_eq!(ElfRelocationType::RCkcorePcrelFlrwImm84.raw(), 59);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm102.raw(), 22);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm104.raw(), 23);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm112.raw(), 3);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm162.raw(), 20);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm164.raw(), 21);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm182.raw(), 43);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm262.raw(), 19);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm42.raw(), 4);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm74.raw(), 50);
        assert_eq!(ElfRelocationType::RCkcorePcrelImm84.raw(), 2);
        assert_eq!(ElfRelocationType::RCkcorePcrelJsrImm112.raw(), 6);
        assert_eq!(ElfRelocationType::RCkcorePcrelJsrImm262.raw(), 40);
        assert_eq!(ElfRelocationType::RCkcorePcrelVlrwImm121.raw(), 65);
        assert_eq!(ElfRelocationType::RCkcorePcrelVlrwImm122.raw(), 66);
        assert_eq!(ElfRelocationType::RCkcorePcrelVlrwImm124.raw(), 67);
        assert_eq!(ElfRelocationType::RCkcorePcrelVlrwImm128.raw(), 68);
        assert_eq!(ElfRelocationType::RCkcorePlt12.raw(), 33);
        assert_eq!(ElfRelocationType::RCkcorePlt32.raw(), 16);
        assert_eq!(ElfRelocationType::RCkcorePltHi16.raw(), 34);
        assert_eq!(ElfRelocationType::RCkcorePltImm184.raw(), 49);
        assert_eq!(ElfRelocationType::RCkcorePltLo16.raw(), 35);
        assert_eq!(ElfRelocationType::RCkcoreRelative.raw(), 9);
        assert_eq!(ElfRelocationType::RCkcoreTlsDtpmod32.raw(), 56);
        assert_eq!(ElfRelocationType::RCkcoreTlsDtpoff32.raw(), 57);
        assert_eq!(ElfRelocationType::RCkcoreTlsGd32.raw(), 53);
        assert_eq!(ElfRelocationType::RCkcoreTlsIe32.raw(), 52);
        assert_eq!(ElfRelocationType::RCkcoreTlsLdm32.raw(), 54);
        assert_eq!(ElfRelocationType::RCkcoreTlsLdo32.raw(), 55);
        assert_eq!(ElfRelocationType::RCkcoreTlsLe32.raw(), 51);
        assert_eq!(ElfRelocationType::RCkcoreTlsTpoff32.raw(), 58);
        assert_eq!(ElfRelocationType::RCkcoreToffsetLo16.raw(), 41);
        assert_eq!(ElfRelocationType::RHex10X.raw(), 26);
        assert_eq!(ElfRelocationType::RHex11X.raw(), 25);
        assert_eq!(ElfRelocationType::RHex12X.raw(), 24);
        assert_eq!(ElfRelocationType::RHex16.raw(), 7);
        assert_eq!(ElfRelocationType::RHex16X.raw(), 23);
        assert_eq!(ElfRelocationType::RHex23Reg.raw(), 94);
        assert_eq!(ElfRelocationType::RHex27Reg.raw(), 99);
        assert_eq!(ElfRelocationType::RHex32.raw(), 6);
        assert_eq!(ElfRelocationType::RHex326X.raw(), 17);
        assert_eq!(ElfRelocationType::RHex32Pcrel.raw(), 31);
        assert_eq!(ElfRelocationType::RHex6PcrelX.raw(), 65);
        assert_eq!(ElfRelocationType::RHex6X.raw(), 30);
        assert_eq!(ElfRelocationType::RHex7X.raw(), 29);
        assert_eq!(ElfRelocationType::RHex8.raw(), 8);
        assert_eq!(ElfRelocationType::RHex8X.raw(), 28);
        assert_eq!(ElfRelocationType::RHex9X.raw(), 27);
        assert_eq!(ElfRelocationType::RHexB13Pcrel.raw(), 14);
        assert_eq!(ElfRelocationType::RHexB13PcrelX.raw(), 20);
        assert_eq!(ElfRelocationType::RHexB15Pcrel.raw(), 2);
        assert_eq!(ElfRelocationType::RHexB15PcrelX.raw(), 19);
        assert_eq!(ElfRelocationType::RHexB22Pcrel.raw(), 1);
        assert_eq!(ElfRelocationType::RHexB22PcrelX.raw(), 18);
        assert_eq!(ElfRelocationType::RHexB32PcrelX.raw(), 16);
        assert_eq!(ElfRelocationType::RHexB7Pcrel.raw(), 3);
        assert_eq!(ElfRelocationType::RHexB7PcrelX.raw(), 22);
        assert_eq!(ElfRelocationType::RHexB9Pcrel.raw(), 15);
        assert_eq!(ElfRelocationType::RHexB9PcrelX.raw(), 21);
        assert_eq!(ElfRelocationType::RHexCopy.raw(), 32);
        assert_eq!(ElfRelocationType::RHexDtpmod32.raw(), 44);
        assert_eq!(ElfRelocationType::RHexDtprel11X.raw(), 74);
        assert_eq!(ElfRelocationType::RHexDtprel16.raw(), 48);
        assert_eq!(ElfRelocationType::RHexDtprel16X.raw(), 73);
        assert_eq!(ElfRelocationType::RHexDtprel32.raw(), 47);
        assert_eq!(ElfRelocationType::RHexDtprel326X.raw(), 72);
        assert_eq!(ElfRelocationType::RHexDtprelHi16.raw(), 46);
        assert_eq!(ElfRelocationType::RHexDtprelLo16.raw(), 45);
        assert_eq!(ElfRelocationType::RHexGdGot11X.raw(), 77);
        assert_eq!(ElfRelocationType::RHexGdGot16.raw(), 53);
        assert_eq!(ElfRelocationType::RHexGdGot16X.raw(), 76);
        assert_eq!(ElfRelocationType::RHexGdGot32.raw(), 52);
        assert_eq!(ElfRelocationType::RHexGdGot326X.raw(), 75);
        assert_eq!(ElfRelocationType::RHexGdGotHi16.raw(), 51);
        assert_eq!(ElfRelocationType::RHexGdGotLo16.raw(), 50);
        assert_eq!(ElfRelocationType::RHexGdPltB22Pcrel.raw(), 49);
        assert_eq!(ElfRelocationType::RHexGdPltB22PcrelX.raw(), 95);
        assert_eq!(ElfRelocationType::RHexGdPltB32PcrelX.raw(), 96);
        assert_eq!(ElfRelocationType::RHexGlobDat.raw(), 33);
        assert_eq!(ElfRelocationType::RHexGotrel11X.raw(), 68);
        assert_eq!(ElfRelocationType::RHexGotrel16X.raw(), 67);
        assert_eq!(ElfRelocationType::RHexGotrel32.raw(), 39);
        assert_eq!(ElfRelocationType::RHexGotrel326X.raw(), 66);
        assert_eq!(ElfRelocationType::RHexGotrelHi16.raw(), 38);
        assert_eq!(ElfRelocationType::RHexGotrelLo16.raw(), 37);
        assert_eq!(ElfRelocationType::RHexGot11X.raw(), 71);
        assert_eq!(ElfRelocationType::RHexGot16.raw(), 43);
        assert_eq!(ElfRelocationType::RHexGot16X.raw(), 70);
        assert_eq!(ElfRelocationType::RHexGot32.raw(), 42);
        assert_eq!(ElfRelocationType::RHexGot326X.raw(), 69);
        assert_eq!(ElfRelocationType::RHexGotHi16.raw(), 41);
        assert_eq!(ElfRelocationType::RHexGotLo16.raw(), 40);
        assert_eq!(ElfRelocationType::RHexGprel160.raw(), 9);
        assert_eq!(ElfRelocationType::RHexGprel161.raw(), 10);
        assert_eq!(ElfRelocationType::RHexGprel162.raw(), 11);
        assert_eq!(ElfRelocationType::RHexGprel163.raw(), 12);
        assert_eq!(ElfRelocationType::RHexHi16.raw(), 5);
        assert_eq!(ElfRelocationType::RHexHl16.raw(), 13);
        assert_eq!(ElfRelocationType::RHexIe16X.raw(), 79);
        assert_eq!(ElfRelocationType::RHexIe32.raw(), 56);
        assert_eq!(ElfRelocationType::RHexIe326X.raw(), 78);
        assert_eq!(ElfRelocationType::RHexIeGot11X.raw(), 82);
        assert_eq!(ElfRelocationType::RHexIeGot16.raw(), 60);
        assert_eq!(ElfRelocationType::RHexIeGot16X.raw(), 81);
        assert_eq!(ElfRelocationType::RHexIeGot32.raw(), 59);
        assert_eq!(ElfRelocationType::RHexIeGot326X.raw(), 80);
        assert_eq!(ElfRelocationType::RHexIeGotHi16.raw(), 58);
        assert_eq!(ElfRelocationType::RHexIeGotLo16.raw(), 57);
        assert_eq!(ElfRelocationType::RHexIeHi16.raw(), 55);
        assert_eq!(ElfRelocationType::RHexIeLo16.raw(), 54);
        assert_eq!(ElfRelocationType::RHexJmpSlot.raw(), 34);
        assert_eq!(ElfRelocationType::RHexLdGot11X.raw(), 93);
        assert_eq!(ElfRelocationType::RHexLdGot16.raw(), 90);
        assert_eq!(ElfRelocationType::RHexLdGot16X.raw(), 92);
        assert_eq!(ElfRelocationType::RHexLdGot32.raw(), 89);
        assert_eq!(ElfRelocationType::RHexLdGot326X.raw(), 91);
        assert_eq!(ElfRelocationType::RHexLdGotHi16.raw(), 88);
        assert_eq!(ElfRelocationType::RHexLdGotLo16.raw(), 87);
        assert_eq!(ElfRelocationType::RHexLdPltB22Pcrel.raw(), 86);
        assert_eq!(ElfRelocationType::RHexLdPltB22PcrelX.raw(), 97);
        assert_eq!(ElfRelocationType::RHexLdPltB32PcrelX.raw(), 98);
        assert_eq!(ElfRelocationType::RHexLo16.raw(), 4);
        assert_eq!(ElfRelocationType::RHexNone.raw(), 0);
        assert_eq!(ElfRelocationType::RHexPltB22Pcrel.raw(), 36);
        assert_eq!(ElfRelocationType::RHexRelative.raw(), 35);
        assert_eq!(ElfRelocationType::RHexTprel11X.raw(), 85);
        assert_eq!(ElfRelocationType::RHexTprel16.raw(), 64);
        assert_eq!(ElfRelocationType::RHexTprel16X.raw(), 84);
        assert_eq!(ElfRelocationType::RHexTprel32.raw(), 63);
        assert_eq!(ElfRelocationType::RHexTprel326X.raw(), 83);
        assert_eq!(ElfRelocationType::RHexTprelHi16.raw(), 62);
        assert_eq!(ElfRelocationType::RHexTprelLo16.raw(), 61);
        assert_eq!(ElfRelocationType::RLanai21.raw(), 1);
        assert_eq!(ElfRelocationType::RLanai21F.raw(), 2);
        assert_eq!(ElfRelocationType::RLanai25.raw(), 3);
        assert_eq!(ElfRelocationType::RLanai32.raw(), 4);
        assert_eq!(ElfRelocationType::RLanaiHi16.raw(), 5);
        assert_eq!(ElfRelocationType::RLanaiLo16.raw(), 6);
        assert_eq!(ElfRelocationType::RLanaiNone.raw(), 0);
        assert_eq!(ElfRelocationType::RLarch32.raw(), 1);
        assert_eq!(ElfRelocationType::RLarch32Pcrel.raw(), 99);
        assert_eq!(ElfRelocationType::RLarch64.raw(), 2);
        assert_eq!(ElfRelocationType::RLarch64Pcrel.raw(), 109);
        assert_eq!(ElfRelocationType::RLarchAbs64Hi12.raw(), 70);
        assert_eq!(ElfRelocationType::RLarchAbs64Lo20.raw(), 69);
        assert_eq!(ElfRelocationType::RLarchAbsHi20.raw(), 67);
        assert_eq!(ElfRelocationType::RLarchAbsLo12.raw(), 68);
        assert_eq!(ElfRelocationType::RLarchAdd16.raw(), 48);
        assert_eq!(ElfRelocationType::RLarchAdd24.raw(), 49);
        assert_eq!(ElfRelocationType::RLarchAdd32.raw(), 50);
        assert_eq!(ElfRelocationType::RLarchAdd6.raw(), 105);
        assert_eq!(ElfRelocationType::RLarchAdd64.raw(), 51);
        assert_eq!(ElfRelocationType::RLarchAdd8.raw(), 47);
        assert_eq!(ElfRelocationType::RLarchAddUleb128.raw(), 107);
        assert_eq!(ElfRelocationType::RLarchAlign.raw(), 102);
        assert_eq!(ElfRelocationType::RLarchB16.raw(), 64);
        assert_eq!(ElfRelocationType::RLarchB21.raw(), 65);
        assert_eq!(ElfRelocationType::RLarchB26.raw(), 66);
        assert_eq!(ElfRelocationType::RLarchCall36.raw(), 110);
        assert_eq!(ElfRelocationType::RLarchCopy.raw(), 4);
        assert_eq!(ElfRelocationType::RLarchGnuVtentry.raw(), 58);
        assert_eq!(ElfRelocationType::RLarchGnuVtinherit.raw(), 57);
        assert_eq!(ElfRelocationType::RLarchGot64Hi12.raw(), 82);
        assert_eq!(ElfRelocationType::RLarchGot64Lo20.raw(), 81);
        assert_eq!(ElfRelocationType::RLarchGot64PcHi12.raw(), 78);
        assert_eq!(ElfRelocationType::RLarchGot64PcLo20.raw(), 77);
        assert_eq!(ElfRelocationType::RLarchGotHi20.raw(), 79);
        assert_eq!(ElfRelocationType::RLarchGotLo12.raw(), 80);
        assert_eq!(ElfRelocationType::RLarchGotPcHi20.raw(), 75);
        assert_eq!(ElfRelocationType::RLarchGotPcLo12.raw(), 76);
        assert_eq!(ElfRelocationType::RLarchIrelative.raw(), 12);
        assert_eq!(ElfRelocationType::RLarchJumpSlot.raw(), 5);
        assert_eq!(ElfRelocationType::RLarchMarkLa.raw(), 20);
        assert_eq!(ElfRelocationType::RLarchMarkPcrel.raw(), 21);
        assert_eq!(ElfRelocationType::RLarchNone.raw(), 0);
        assert_eq!(ElfRelocationType::RLarchPcala64Hi12.raw(), 74);
        assert_eq!(ElfRelocationType::RLarchPcala64Lo20.raw(), 73);
        assert_eq!(ElfRelocationType::RLarchPcalaHi20.raw(), 71);
        assert_eq!(ElfRelocationType::RLarchPcalaLo12.raw(), 72);
        assert_eq!(ElfRelocationType::RLarchPcrel20S2.raw(), 103);
        assert_eq!(ElfRelocationType::RLarchRelative.raw(), 3);
        assert_eq!(ElfRelocationType::RLarchRelax.raw(), 100);
        assert_eq!(ElfRelocationType::RLarchSopAdd.raw(), 35);
        assert_eq!(ElfRelocationType::RLarchSopAnd.raw(), 36);
        assert_eq!(ElfRelocationType::RLarchSopAssert.raw(), 30);
        assert_eq!(ElfRelocationType::RLarchSopIfElse.raw(), 37);
        assert_eq!(ElfRelocationType::RLarchSopNot.raw(), 31);
        assert_eq!(ElfRelocationType::RLarchSopPop32S0101016S2.raw(), 45);
        assert_eq!(ElfRelocationType::RLarchSopPop32S051016S2.raw(), 44);
        assert_eq!(ElfRelocationType::RLarchSopPop32S1012.raw(), 40);
        assert_eq!(ElfRelocationType::RLarchSopPop32S1016.raw(), 41);
        assert_eq!(ElfRelocationType::RLarchSopPop32S1016S2.raw(), 42);
        assert_eq!(ElfRelocationType::RLarchSopPop32S105.raw(), 38);
        assert_eq!(ElfRelocationType::RLarchSopPop32S520.raw(), 43);
        assert_eq!(ElfRelocationType::RLarchSopPop32U.raw(), 46);
        assert_eq!(ElfRelocationType::RLarchSopPop32U1012.raw(), 39);
        assert_eq!(ElfRelocationType::RLarchSopPushAbsolute.raw(), 23);
        assert_eq!(ElfRelocationType::RLarchSopPushDup.raw(), 24);
        assert_eq!(ElfRelocationType::RLarchSopPushGprel.raw(), 25);
        assert_eq!(ElfRelocationType::RLarchSopPushPcrel.raw(), 22);
        assert_eq!(ElfRelocationType::RLarchSopPushPltPcrel.raw(), 29);
        assert_eq!(ElfRelocationType::RLarchSopPushTlsGd.raw(), 28);
        assert_eq!(ElfRelocationType::RLarchSopPushTlsGot.raw(), 27);
        assert_eq!(ElfRelocationType::RLarchSopPushTlsTprel.raw(), 26);
        assert_eq!(ElfRelocationType::RLarchSopSl.raw(), 33);
        assert_eq!(ElfRelocationType::RLarchSopSr.raw(), 34);
        assert_eq!(ElfRelocationType::RLarchSopSub.raw(), 32);
        assert_eq!(ElfRelocationType::RLarchSub16.raw(), 53);
        assert_eq!(ElfRelocationType::RLarchSub24.raw(), 54);
        assert_eq!(ElfRelocationType::RLarchSub32.raw(), 55);
        assert_eq!(ElfRelocationType::RLarchSub6.raw(), 106);
        assert_eq!(ElfRelocationType::RLarchSub64.raw(), 56);
        assert_eq!(ElfRelocationType::RLarchSub8.raw(), 52);
        assert_eq!(ElfRelocationType::RLarchSubUleb128.raw(), 108);
        assert_eq!(ElfRelocationType::RLarchTlsDesc32.raw(), 13);
        assert_eq!(ElfRelocationType::RLarchTlsDesc64.raw(), 14);
        assert_eq!(ElfRelocationType::RLarchTlsDesc64Hi12.raw(), 118);
        assert_eq!(ElfRelocationType::RLarchTlsDesc64Lo20.raw(), 117);
        assert_eq!(ElfRelocationType::RLarchTlsDesc64PcHi12.raw(), 114);
        assert_eq!(ElfRelocationType::RLarchTlsDesc64PcLo20.raw(), 113);
        assert_eq!(ElfRelocationType::RLarchTlsDescCall.raw(), 120);
        assert_eq!(ElfRelocationType::RLarchTlsDescHi20.raw(), 115);
        assert_eq!(ElfRelocationType::RLarchTlsDescLd.raw(), 119);
        assert_eq!(ElfRelocationType::RLarchTlsDescLo12.raw(), 116);
        assert_eq!(ElfRelocationType::RLarchTlsDescPcrel20S2.raw(), 126);
        assert_eq!(ElfRelocationType::RLarchTlsDescPcHi20.raw(), 111);
        assert_eq!(ElfRelocationType::RLarchTlsDescPcLo12.raw(), 112);
        assert_eq!(ElfRelocationType::RLarchTlsDtpmod32.raw(), 6);
        assert_eq!(ElfRelocationType::RLarchTlsDtpmod64.raw(), 7);
        assert_eq!(ElfRelocationType::RLarchTlsDtprel32.raw(), 8);
        assert_eq!(ElfRelocationType::RLarchTlsDtprel64.raw(), 9);
        assert_eq!(ElfRelocationType::RLarchTlsGdHi20.raw(), 98);
        assert_eq!(ElfRelocationType::RLarchTlsGdPcrel20S2.raw(), 125);
        assert_eq!(ElfRelocationType::RLarchTlsGdPcHi20.raw(), 97);
        assert_eq!(ElfRelocationType::RLarchTlsIe64Hi12.raw(), 94);
        assert_eq!(ElfRelocationType::RLarchTlsIe64Lo20.raw(), 93);
        assert_eq!(ElfRelocationType::RLarchTlsIe64PcHi12.raw(), 90);
        assert_eq!(ElfRelocationType::RLarchTlsIe64PcLo20.raw(), 89);
        assert_eq!(ElfRelocationType::RLarchTlsIeHi20.raw(), 91);
        assert_eq!(ElfRelocationType::RLarchTlsIeLo12.raw(), 92);
        assert_eq!(ElfRelocationType::RLarchTlsIePcHi20.raw(), 87);
        assert_eq!(ElfRelocationType::RLarchTlsIePcLo12.raw(), 88);
        assert_eq!(ElfRelocationType::RLarchTlsLdHi20.raw(), 96);
        assert_eq!(ElfRelocationType::RLarchTlsLdPcrel20S2.raw(), 124);
        assert_eq!(ElfRelocationType::RLarchTlsLdPcHi20.raw(), 95);
        assert_eq!(ElfRelocationType::RLarchTlsLe64Hi12.raw(), 86);
        assert_eq!(ElfRelocationType::RLarchTlsLe64Lo20.raw(), 85);
        assert_eq!(ElfRelocationType::RLarchTlsLeAddR.raw(), 122);
        assert_eq!(ElfRelocationType::RLarchTlsLeHi20.raw(), 83);
        assert_eq!(ElfRelocationType::RLarchTlsLeHi20R.raw(), 121);
        assert_eq!(ElfRelocationType::RLarchTlsLeLo12.raw(), 84);
        assert_eq!(ElfRelocationType::RLarchTlsLeLo12R.raw(), 123);
        assert_eq!(ElfRelocationType::RLarchTlsTprel32.raw(), 10);
        assert_eq!(ElfRelocationType::RLarchTlsTprel64.raw(), 11);
        assert_eq!(ElfRelocationType::RMicromips26S1.raw(), 133);
        assert_eq!(ElfRelocationType::RMicromipsCall16.raw(), 142);
        assert_eq!(ElfRelocationType::RMicromipsCallHi16.raw(), 153);
        assert_eq!(ElfRelocationType::RMicromipsCallLo16.raw(), 154);
        assert_eq!(ElfRelocationType::RMicromipsGot16.raw(), 138);
        assert_eq!(ElfRelocationType::RMicromipsGotDisp.raw(), 145);
        assert_eq!(ElfRelocationType::RMicromipsGotHi16.raw(), 148);
        assert_eq!(ElfRelocationType::RMicromipsGotLo16.raw(), 149);
        assert_eq!(ElfRelocationType::RMicromipsGotOfst.raw(), 147);
        assert_eq!(ElfRelocationType::RMicromipsGotPage.raw(), 146);
        assert_eq!(ElfRelocationType::RMicromipsGprel16.raw(), 136);
        assert_eq!(ElfRelocationType::RMicromipsGprel7S2.raw(), 172);
        assert_eq!(ElfRelocationType::RMicromipsHi0Lo16.raw(), 157);
        assert_eq!(ElfRelocationType::RMicromipsHi16.raw(), 134);
        assert_eq!(ElfRelocationType::RMicromipsHigher.raw(), 151);
        assert_eq!(ElfRelocationType::RMicromipsHighest.raw(), 152);
        assert_eq!(ElfRelocationType::RMicromipsJalr.raw(), 156);
        assert_eq!(ElfRelocationType::RMicromipsLiteral.raw(), 137);
        assert_eq!(ElfRelocationType::RMicromipsLo16.raw(), 135);
        assert_eq!(ElfRelocationType::RMicromipsPc10S1.raw(), 140);
        assert_eq!(ElfRelocationType::RMicromipsPc16S1.raw(), 141);
        assert_eq!(ElfRelocationType::RMicromipsPc18S3.raw(), 176);
        assert_eq!(ElfRelocationType::RMicromipsPc19S2.raw(), 177);
        assert_eq!(ElfRelocationType::RMicromipsPc21S1.raw(), 174);
        assert_eq!(ElfRelocationType::RMicromipsPc23S2.raw(), 173);
        assert_eq!(ElfRelocationType::RMicromipsPc26S1.raw(), 175);
        assert_eq!(ElfRelocationType::RMicromipsPc7S1.raw(), 139);
        assert_eq!(ElfRelocationType::RMicromipsScnDisp.raw(), 155);
        assert_eq!(ElfRelocationType::RMicromipsSub.raw(), 150);
        assert_eq!(ElfRelocationType::RMicromipsTlsDtprelHi16.raw(), 164);
        assert_eq!(ElfRelocationType::RMicromipsTlsDtprelLo16.raw(), 165);
        assert_eq!(ElfRelocationType::RMicromipsTlsGd.raw(), 162);
        assert_eq!(ElfRelocationType::RMicromipsTlsGottprel.raw(), 166);
        assert_eq!(ElfRelocationType::RMicromipsTlsLdm.raw(), 163);
        assert_eq!(ElfRelocationType::RMicromipsTlsTprelHi16.raw(), 169);
        assert_eq!(ElfRelocationType::RMicromipsTlsTprelLo16.raw(), 170);
        assert_eq!(ElfRelocationType::RMips1626.raw(), 100);
        assert_eq!(ElfRelocationType::RMips16Call16.raw(), 103);
        assert_eq!(ElfRelocationType::RMips16Got16.raw(), 102);
        assert_eq!(ElfRelocationType::RMips16Gprel.raw(), 101);
        assert_eq!(ElfRelocationType::RMips16Hi16.raw(), 104);
        assert_eq!(ElfRelocationType::RMips16Lo16.raw(), 105);
        assert_eq!(ElfRelocationType::RMips16TlsDtprelHi16.raw(), 108);
        assert_eq!(ElfRelocationType::RMips16TlsDtprelLo16.raw(), 109);
        assert_eq!(ElfRelocationType::RMips16TlsGd.raw(), 106);
        assert_eq!(ElfRelocationType::RMips16TlsGottprel.raw(), 110);
        assert_eq!(ElfRelocationType::RMips16TlsLdm.raw(), 107);
        assert_eq!(ElfRelocationType::RMips16TlsTprelHi16.raw(), 111);
        assert_eq!(ElfRelocationType::RMips16TlsTprelLo16.raw(), 112);
        assert_eq!(ElfRelocationType::RMips16.raw(), 1);
        assert_eq!(ElfRelocationType::RMips26.raw(), 4);
        assert_eq!(ElfRelocationType::RMips32.raw(), 2);
        assert_eq!(ElfRelocationType::RMips64.raw(), 18);
        assert_eq!(ElfRelocationType::RMipsAddImmediate.raw(), 34);
        assert_eq!(ElfRelocationType::RMipsCall16.raw(), 11);
        assert_eq!(ElfRelocationType::RMipsCallHi16.raw(), 30);
        assert_eq!(ElfRelocationType::RMipsCallLo16.raw(), 31);
        assert_eq!(ElfRelocationType::RMipsCopy.raw(), 126);
        assert_eq!(ElfRelocationType::RMipsDelete.raw(), 27);
        assert_eq!(ElfRelocationType::RMipsEh.raw(), 249);
        assert_eq!(ElfRelocationType::RMipsGlobDat.raw(), 51);
        assert_eq!(ElfRelocationType::RMipsGot16.raw(), 9);
        assert_eq!(ElfRelocationType::RMipsGotDisp.raw(), 19);
        assert_eq!(ElfRelocationType::RMipsGotHi16.raw(), 22);
        assert_eq!(ElfRelocationType::RMipsGotLo16.raw(), 23);
        assert_eq!(ElfRelocationType::RMipsGotOfst.raw(), 21);
        assert_eq!(ElfRelocationType::RMipsGotPage.raw(), 20);
        assert_eq!(ElfRelocationType::RMipsGprel16.raw(), 7);
        assert_eq!(ElfRelocationType::RMipsGprel32.raw(), 12);
        assert_eq!(ElfRelocationType::RMipsHi16.raw(), 5);
        assert_eq!(ElfRelocationType::RMipsHigher.raw(), 28);
        assert_eq!(ElfRelocationType::RMipsHighest.raw(), 29);
        assert_eq!(ElfRelocationType::RMipsInsertA.raw(), 25);
        assert_eq!(ElfRelocationType::RMipsInsertB.raw(), 26);
        assert_eq!(ElfRelocationType::RMipsJalr.raw(), 37);
        assert_eq!(ElfRelocationType::RMipsJumpSlot.raw(), 127);
        assert_eq!(ElfRelocationType::RMipsLiteral.raw(), 8);
        assert_eq!(ElfRelocationType::RMipsLo16.raw(), 6);
        assert_eq!(ElfRelocationType::RMipsNone.raw(), 0);
        assert_eq!(ElfRelocationType::RMipsNum.raw(), 218);
        assert_eq!(ElfRelocationType::RMipsPc16.raw(), 10);
        assert_eq!(ElfRelocationType::RMipsPc18S3.raw(), 62);
        assert_eq!(ElfRelocationType::RMipsPc19S2.raw(), 63);
        assert_eq!(ElfRelocationType::RMipsPc21S2.raw(), 60);
        assert_eq!(ElfRelocationType::RMipsPc26S2.raw(), 61);
        assert_eq!(ElfRelocationType::RMipsPc32.raw(), 248);
        assert_eq!(ElfRelocationType::RMipsPchi16.raw(), 64);
        assert_eq!(ElfRelocationType::RMipsPclo16.raw(), 65);
        assert_eq!(ElfRelocationType::RMipsPjump.raw(), 35);
        assert_eq!(ElfRelocationType::RMipsRel16.raw(), 33);
        assert_eq!(ElfRelocationType::RMipsRel32.raw(), 3);
        assert_eq!(ElfRelocationType::RMipsRelgot.raw(), 36);
        assert_eq!(ElfRelocationType::RMipsScnDisp.raw(), 32);
        assert_eq!(ElfRelocationType::RMipsShift5.raw(), 16);
        assert_eq!(ElfRelocationType::RMipsShift6.raw(), 17);
        assert_eq!(ElfRelocationType::RMipsSub.raw(), 24);
        assert_eq!(ElfRelocationType::RMipsTlsDtpmod32.raw(), 38);
        assert_eq!(ElfRelocationType::RMipsTlsDtpmod64.raw(), 40);
        assert_eq!(ElfRelocationType::RMipsTlsDtprel32.raw(), 39);
        assert_eq!(ElfRelocationType::RMipsTlsDtprel64.raw(), 41);
        assert_eq!(ElfRelocationType::RMipsTlsDtprelHi16.raw(), 44);
        assert_eq!(ElfRelocationType::RMipsTlsDtprelLo16.raw(), 45);
        assert_eq!(ElfRelocationType::RMipsTlsGd.raw(), 42);
        assert_eq!(ElfRelocationType::RMipsTlsGottprel.raw(), 46);
        assert_eq!(ElfRelocationType::RMipsTlsLdm.raw(), 43);
        assert_eq!(ElfRelocationType::RMipsTlsTprel32.raw(), 47);
        assert_eq!(ElfRelocationType::RMipsTlsTprel64.raw(), 48);
        assert_eq!(ElfRelocationType::RMipsTlsTprelHi16.raw(), 49);
        assert_eq!(ElfRelocationType::RMipsTlsTprelLo16.raw(), 50);
        assert_eq!(ElfRelocationType::RMipsUnused1.raw(), 13);
        assert_eq!(ElfRelocationType::RMipsUnused2.raw(), 14);
        assert_eq!(ElfRelocationType::RMipsUnused3.raw(), 15);
        assert_eq!(ElfRelocationType::RMsp43010Pcrel.raw(), 2);
        assert_eq!(ElfRelocationType::RMsp43016.raw(), 3);
        assert_eq!(ElfRelocationType::RMsp43016Byte.raw(), 5);
        assert_eq!(ElfRelocationType::RMsp43016Pcrel.raw(), 4);
        assert_eq!(ElfRelocationType::RMsp43016PcrelByte.raw(), 6);
        assert_eq!(ElfRelocationType::RMsp4302XPcrel.raw(), 7);
        assert_eq!(ElfRelocationType::RMsp43032.raw(), 1);
        assert_eq!(ElfRelocationType::RMsp4308.raw(), 9);
        assert_eq!(ElfRelocationType::RMsp430None.raw(), 0);
        assert_eq!(ElfRelocationType::RMsp430RlPcrel.raw(), 8);
        assert_eq!(ElfRelocationType::RMsp430SymDiff.raw(), 10);
        assert_eq!(ElfRelocationType::RPpc64Addr14.raw(), 7);
        assert_eq!(ElfRelocationType::RPpc64Addr14Brntaken.raw(), 9);
        assert_eq!(ElfRelocationType::RPpc64Addr14Brtaken.raw(), 8);
        assert_eq!(ElfRelocationType::RPpc64Addr16.raw(), 3);
        assert_eq!(ElfRelocationType::RPpc64Addr16Ds.raw(), 56);
        assert_eq!(ElfRelocationType::RPpc64Addr16Ha.raw(), 6);
        assert_eq!(ElfRelocationType::RPpc64Addr16Hi.raw(), 5);
        assert_eq!(ElfRelocationType::RPpc64Addr16High.raw(), 110);
        assert_eq!(ElfRelocationType::RPpc64Addr16Higha.raw(), 111);
        assert_eq!(ElfRelocationType::RPpc64Addr16Higher.raw(), 39);
        assert_eq!(ElfRelocationType::RPpc64Addr16Highera.raw(), 40);
        assert_eq!(ElfRelocationType::RPpc64Addr16Highest.raw(), 41);
        assert_eq!(ElfRelocationType::RPpc64Addr16Highesta.raw(), 42);
        assert_eq!(ElfRelocationType::RPpc64Addr16Lo.raw(), 4);
        assert_eq!(ElfRelocationType::RPpc64Addr16LoDs.raw(), 57);
        assert_eq!(ElfRelocationType::RPpc64Addr24.raw(), 2);
        assert_eq!(ElfRelocationType::RPpc64Addr32.raw(), 1);
        assert_eq!(ElfRelocationType::RPpc64Addr64.raw(), 38);
        assert_eq!(ElfRelocationType::RPpc64Copy.raw(), 19);
        assert_eq!(ElfRelocationType::RPpc64Dtpmod64.raw(), 68);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16.raw(), 74);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Ds.raw(), 101);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Ha.raw(), 77);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Hi.raw(), 76);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16High.raw(), 114);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Higha.raw(), 115);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Higher.raw(), 103);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Highera.raw(), 104);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Highest.raw(), 105);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Highesta.raw(), 106);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16Lo.raw(), 75);
        assert_eq!(ElfRelocationType::RPpc64Dtprel16LoDs.raw(), 102);
        assert_eq!(ElfRelocationType::RPpc64Dtprel34.raw(), 147);
        assert_eq!(ElfRelocationType::RPpc64Dtprel64.raw(), 78);
        assert_eq!(ElfRelocationType::RPpc64GlobDat.raw(), 20);
        assert_eq!(ElfRelocationType::RPpc64Got16.raw(), 14);
        assert_eq!(ElfRelocationType::RPpc64Got16Ds.raw(), 58);
        assert_eq!(ElfRelocationType::RPpc64Got16Ha.raw(), 17);
        assert_eq!(ElfRelocationType::RPpc64Got16Hi.raw(), 16);
        assert_eq!(ElfRelocationType::RPpc64Got16Lo.raw(), 15);
        assert_eq!(ElfRelocationType::RPpc64Got16LoDs.raw(), 59);
        assert_eq!(ElfRelocationType::RPpc64GotDtprel16Ds.raw(), 91);
        assert_eq!(ElfRelocationType::RPpc64GotDtprel16Ha.raw(), 94);
        assert_eq!(ElfRelocationType::RPpc64GotDtprel16Hi.raw(), 93);
        assert_eq!(ElfRelocationType::RPpc64GotDtprel16LoDs.raw(), 92);
        assert_eq!(ElfRelocationType::RPpc64GotPcrel34.raw(), 133);
        assert_eq!(ElfRelocationType::RPpc64GotTlsgd16.raw(), 79);
        assert_eq!(ElfRelocationType::RPpc64GotTlsgd16Ha.raw(), 82);
        assert_eq!(ElfRelocationType::RPpc64GotTlsgd16Hi.raw(), 81);
        assert_eq!(ElfRelocationType::RPpc64GotTlsgd16Lo.raw(), 80);
        assert_eq!(ElfRelocationType::RPpc64GotTlsgdPcrel34.raw(), 148);
        assert_eq!(ElfRelocationType::RPpc64GotTlsld16.raw(), 83);
        assert_eq!(ElfRelocationType::RPpc64GotTlsld16Ha.raw(), 86);
        assert_eq!(ElfRelocationType::RPpc64GotTlsld16Hi.raw(), 85);
        assert_eq!(ElfRelocationType::RPpc64GotTlsld16Lo.raw(), 84);
        assert_eq!(ElfRelocationType::RPpc64GotTlsldPcrel34.raw(), 149);
        assert_eq!(ElfRelocationType::RPpc64GotTprel16Ds.raw(), 87);
        assert_eq!(ElfRelocationType::RPpc64GotTprel16Ha.raw(), 90);
        assert_eq!(ElfRelocationType::RPpc64GotTprel16Hi.raw(), 89);
        assert_eq!(ElfRelocationType::RPpc64GotTprel16LoDs.raw(), 88);
        assert_eq!(ElfRelocationType::RPpc64GotTprelPcrel34.raw(), 150);
        assert_eq!(ElfRelocationType::RPpc64Irelative.raw(), 248);
        assert_eq!(ElfRelocationType::RPpc64JmpSlot.raw(), 21);
        assert_eq!(ElfRelocationType::RPpc64None.raw(), 0);
        assert_eq!(ElfRelocationType::RPpc64Pcrel34.raw(), 132);
        assert_eq!(ElfRelocationType::RPpc64PcrelOpt.raw(), 123);
        assert_eq!(ElfRelocationType::RPpc64Rel14.raw(), 11);
        assert_eq!(ElfRelocationType::RPpc64Rel14Brntaken.raw(), 13);
        assert_eq!(ElfRelocationType::RPpc64Rel14Brtaken.raw(), 12);
        assert_eq!(ElfRelocationType::RPpc64Rel16.raw(), 249);
        assert_eq!(ElfRelocationType::RPpc64Rel16Ha.raw(), 252);
        assert_eq!(ElfRelocationType::RPpc64Rel16Hi.raw(), 251);
        assert_eq!(ElfRelocationType::RPpc64Rel16Lo.raw(), 250);
        assert_eq!(ElfRelocationType::RPpc64Rel24.raw(), 10);
        assert_eq!(ElfRelocationType::RPpc64Rel24Notoc.raw(), 116);
        assert_eq!(ElfRelocationType::RPpc64Rel32.raw(), 26);
        assert_eq!(ElfRelocationType::RPpc64Rel64.raw(), 44);
        assert_eq!(ElfRelocationType::RPpc64Relative.raw(), 22);
        assert_eq!(ElfRelocationType::RPpc64Tls.raw(), 67);
        assert_eq!(ElfRelocationType::RPpc64Tlsgd.raw(), 107);
        assert_eq!(ElfRelocationType::RPpc64Tlsld.raw(), 108);
        assert_eq!(ElfRelocationType::RPpc64Toc.raw(), 51);
        assert_eq!(ElfRelocationType::RPpc64Toc16.raw(), 47);
        assert_eq!(ElfRelocationType::RPpc64Toc16Ds.raw(), 63);
        assert_eq!(ElfRelocationType::RPpc64Toc16Ha.raw(), 50);
        assert_eq!(ElfRelocationType::RPpc64Toc16Hi.raw(), 49);
        assert_eq!(ElfRelocationType::RPpc64Toc16Lo.raw(), 48);
        assert_eq!(ElfRelocationType::RPpc64Toc16LoDs.raw(), 64);
        assert_eq!(ElfRelocationType::RPpc64Tprel16.raw(), 69);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Ds.raw(), 95);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Ha.raw(), 72);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Hi.raw(), 71);
        assert_eq!(ElfRelocationType::RPpc64Tprel16High.raw(), 112);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Higha.raw(), 113);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Higher.raw(), 97);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Highera.raw(), 98);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Highest.raw(), 99);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Highesta.raw(), 100);
        assert_eq!(ElfRelocationType::RPpc64Tprel16Lo.raw(), 70);
        assert_eq!(ElfRelocationType::RPpc64Tprel16LoDs.raw(), 96);
        assert_eq!(ElfRelocationType::RPpc64Tprel34.raw(), 146);
        assert_eq!(ElfRelocationType::RPpc64Tprel64.raw(), 73);
        assert_eq!(ElfRelocationType::RPpcAddr14.raw(), 7);
        assert_eq!(ElfRelocationType::RPpcAddr14Brntaken.raw(), 9);
        assert_eq!(ElfRelocationType::RPpcAddr14Brtaken.raw(), 8);
        assert_eq!(ElfRelocationType::RPpcAddr16.raw(), 3);
        assert_eq!(ElfRelocationType::RPpcAddr16Ha.raw(), 6);
        assert_eq!(ElfRelocationType::RPpcAddr16Hi.raw(), 5);
        assert_eq!(ElfRelocationType::RPpcAddr16Lo.raw(), 4);
        assert_eq!(ElfRelocationType::RPpcAddr24.raw(), 2);
        assert_eq!(ElfRelocationType::RPpcAddr30.raw(), 37);
        assert_eq!(ElfRelocationType::RPpcAddr32.raw(), 1);
        assert_eq!(ElfRelocationType::RPpcCopy.raw(), 19);
        assert_eq!(ElfRelocationType::RPpcDtpmod32.raw(), 68);
        assert_eq!(ElfRelocationType::RPpcDtprel16.raw(), 74);
        assert_eq!(ElfRelocationType::RPpcDtprel16Ha.raw(), 77);
        assert_eq!(ElfRelocationType::RPpcDtprel16Hi.raw(), 76);
        assert_eq!(ElfRelocationType::RPpcDtprel16Lo.raw(), 75);
        assert_eq!(ElfRelocationType::RPpcDtprel32.raw(), 78);
        assert_eq!(ElfRelocationType::RPpcGlobDat.raw(), 20);
        assert_eq!(ElfRelocationType::RPpcGot16.raw(), 14);
        assert_eq!(ElfRelocationType::RPpcGot16Ha.raw(), 17);
        assert_eq!(ElfRelocationType::RPpcGot16Hi.raw(), 16);
        assert_eq!(ElfRelocationType::RPpcGot16Lo.raw(), 15);
        assert_eq!(ElfRelocationType::RPpcGotDtprel16.raw(), 91);
        assert_eq!(ElfRelocationType::RPpcGotDtprel16Ha.raw(), 94);
        assert_eq!(ElfRelocationType::RPpcGotDtprel16Hi.raw(), 93);
        assert_eq!(ElfRelocationType::RPpcGotDtprel16Lo.raw(), 92);
        assert_eq!(ElfRelocationType::RPpcGotTlsgd16.raw(), 79);
        assert_eq!(ElfRelocationType::RPpcGotTlsgd16Ha.raw(), 82);
        assert_eq!(ElfRelocationType::RPpcGotTlsgd16Hi.raw(), 81);
        assert_eq!(ElfRelocationType::RPpcGotTlsgd16Lo.raw(), 80);
        assert_eq!(ElfRelocationType::RPpcGotTlsld16.raw(), 83);
        assert_eq!(ElfRelocationType::RPpcGotTlsld16Ha.raw(), 86);
        assert_eq!(ElfRelocationType::RPpcGotTlsld16Hi.raw(), 85);
        assert_eq!(ElfRelocationType::RPpcGotTlsld16Lo.raw(), 84);
        assert_eq!(ElfRelocationType::RPpcGotTprel16.raw(), 87);
        assert_eq!(ElfRelocationType::RPpcGotTprel16Ha.raw(), 90);
        assert_eq!(ElfRelocationType::RPpcGotTprel16Hi.raw(), 89);
        assert_eq!(ElfRelocationType::RPpcGotTprel16Lo.raw(), 88);
        assert_eq!(ElfRelocationType::RPpcIrelative.raw(), 248);
        assert_eq!(ElfRelocationType::RPpcJmpSlot.raw(), 21);
        assert_eq!(ElfRelocationType::RPpcLocal24Pc.raw(), 23);
        assert_eq!(ElfRelocationType::RPpcNone.raw(), 0);
        assert_eq!(ElfRelocationType::RPpcPlt16Ha.raw(), 31);
        assert_eq!(ElfRelocationType::RPpcPlt16Hi.raw(), 30);
        assert_eq!(ElfRelocationType::RPpcPlt16Lo.raw(), 29);
        assert_eq!(ElfRelocationType::RPpcPlt32.raw(), 27);
        assert_eq!(ElfRelocationType::RPpcPltrel24.raw(), 18);
        assert_eq!(ElfRelocationType::RPpcPltrel32.raw(), 28);
        assert_eq!(ElfRelocationType::RPpcRel14.raw(), 11);
        assert_eq!(ElfRelocationType::RPpcRel14Brntaken.raw(), 13);
        assert_eq!(ElfRelocationType::RPpcRel14Brtaken.raw(), 12);
        assert_eq!(ElfRelocationType::RPpcRel16.raw(), 249);
        assert_eq!(ElfRelocationType::RPpcRel16Ha.raw(), 252);
        assert_eq!(ElfRelocationType::RPpcRel16Hi.raw(), 251);
        assert_eq!(ElfRelocationType::RPpcRel16Lo.raw(), 250);
        assert_eq!(ElfRelocationType::RPpcRel24.raw(), 10);
        assert_eq!(ElfRelocationType::RPpcRel32.raw(), 26);
        assert_eq!(ElfRelocationType::RPpcRelative.raw(), 22);
        assert_eq!(ElfRelocationType::RPpcSdarel16.raw(), 32);
        assert_eq!(ElfRelocationType::RPpcSectoff.raw(), 33);
        assert_eq!(ElfRelocationType::RPpcSectoffHa.raw(), 36);
        assert_eq!(ElfRelocationType::RPpcSectoffHi.raw(), 35);
        assert_eq!(ElfRelocationType::RPpcSectoffLo.raw(), 34);
        assert_eq!(ElfRelocationType::RPpcTls.raw(), 67);
        assert_eq!(ElfRelocationType::RPpcTlsgd.raw(), 95);
        assert_eq!(ElfRelocationType::RPpcTlsld.raw(), 96);
        assert_eq!(ElfRelocationType::RPpcTprel16.raw(), 69);
        assert_eq!(ElfRelocationType::RPpcTprel16Ha.raw(), 72);
        assert_eq!(ElfRelocationType::RPpcTprel16Hi.raw(), 71);
        assert_eq!(ElfRelocationType::RPpcTprel16Lo.raw(), 70);
        assert_eq!(ElfRelocationType::RPpcTprel32.raw(), 73);
        assert_eq!(ElfRelocationType::RPpcUaddr16.raw(), 25);
        assert_eq!(ElfRelocationType::RPpcUaddr32.raw(), 24);
        assert_eq!(ElfRelocationType::RRiscv32.raw(), 1);
        assert_eq!(ElfRelocationType::RRiscv32Pcrel.raw(), 57);
        assert_eq!(ElfRelocationType::RRiscv64.raw(), 2);
        assert_eq!(ElfRelocationType::RRiscvAdd16.raw(), 34);
        assert_eq!(ElfRelocationType::RRiscvAdd32.raw(), 35);
        assert_eq!(ElfRelocationType::RRiscvAdd64.raw(), 36);
        assert_eq!(ElfRelocationType::RRiscvAdd8.raw(), 33);
        assert_eq!(ElfRelocationType::RRiscvAlign.raw(), 43);
        assert_eq!(ElfRelocationType::RRiscvBranch.raw(), 16);
        assert_eq!(ElfRelocationType::RRiscvCall.raw(), 18);
        assert_eq!(ElfRelocationType::RRiscvCallPlt.raw(), 19);
        assert_eq!(ElfRelocationType::RRiscvCopy.raw(), 4);
        assert_eq!(ElfRelocationType::RRiscvCustom192.raw(), 192);
        assert_eq!(ElfRelocationType::RRiscvCustom193.raw(), 193);
        assert_eq!(ElfRelocationType::RRiscvCustom194.raw(), 194);
        assert_eq!(ElfRelocationType::RRiscvCustom195.raw(), 195);
        assert_eq!(ElfRelocationType::RRiscvCustom196.raw(), 196);
        assert_eq!(ElfRelocationType::RRiscvCustom197.raw(), 197);
        assert_eq!(ElfRelocationType::RRiscvCustom198.raw(), 198);
        assert_eq!(ElfRelocationType::RRiscvCustom199.raw(), 199);
        assert_eq!(ElfRelocationType::RRiscvCustom200.raw(), 200);
        assert_eq!(ElfRelocationType::RRiscvCustom201.raw(), 201);
        assert_eq!(ElfRelocationType::RRiscvCustom202.raw(), 202);
        assert_eq!(ElfRelocationType::RRiscvCustom203.raw(), 203);
        assert_eq!(ElfRelocationType::RRiscvCustom204.raw(), 204);
        assert_eq!(ElfRelocationType::RRiscvCustom205.raw(), 205);
        assert_eq!(ElfRelocationType::RRiscvCustom206.raw(), 206);
        assert_eq!(ElfRelocationType::RRiscvCustom207.raw(), 207);
        assert_eq!(ElfRelocationType::RRiscvCustom208.raw(), 208);
        assert_eq!(ElfRelocationType::RRiscvCustom209.raw(), 209);
        assert_eq!(ElfRelocationType::RRiscvCustom210.raw(), 210);
        assert_eq!(ElfRelocationType::RRiscvCustom211.raw(), 211);
        assert_eq!(ElfRelocationType::RRiscvCustom212.raw(), 212);
        assert_eq!(ElfRelocationType::RRiscvCustom213.raw(), 213);
        assert_eq!(ElfRelocationType::RRiscvCustom214.raw(), 214);
        assert_eq!(ElfRelocationType::RRiscvCustom215.raw(), 215);
        assert_eq!(ElfRelocationType::RRiscvCustom216.raw(), 216);
        assert_eq!(ElfRelocationType::RRiscvCustom217.raw(), 217);
        assert_eq!(ElfRelocationType::RRiscvCustom218.raw(), 218);
        assert_eq!(ElfRelocationType::RRiscvCustom219.raw(), 219);
        assert_eq!(ElfRelocationType::RRiscvCustom220.raw(), 220);
        assert_eq!(ElfRelocationType::RRiscvCustom221.raw(), 221);
        assert_eq!(ElfRelocationType::RRiscvCustom222.raw(), 222);
        assert_eq!(ElfRelocationType::RRiscvCustom223.raw(), 223);
        assert_eq!(ElfRelocationType::RRiscvCustom224.raw(), 224);
        assert_eq!(ElfRelocationType::RRiscvCustom225.raw(), 225);
        assert_eq!(ElfRelocationType::RRiscvCustom226.raw(), 226);
        assert_eq!(ElfRelocationType::RRiscvCustom227.raw(), 227);
        assert_eq!(ElfRelocationType::RRiscvCustom228.raw(), 228);
        assert_eq!(ElfRelocationType::RRiscvCustom229.raw(), 229);
        assert_eq!(ElfRelocationType::RRiscvCustom230.raw(), 230);
        assert_eq!(ElfRelocationType::RRiscvCustom231.raw(), 231);
        assert_eq!(ElfRelocationType::RRiscvCustom232.raw(), 232);
        assert_eq!(ElfRelocationType::RRiscvCustom233.raw(), 233);
        assert_eq!(ElfRelocationType::RRiscvCustom234.raw(), 234);
        assert_eq!(ElfRelocationType::RRiscvCustom235.raw(), 235);
        assert_eq!(ElfRelocationType::RRiscvCustom236.raw(), 236);
        assert_eq!(ElfRelocationType::RRiscvCustom237.raw(), 237);
        assert_eq!(ElfRelocationType::RRiscvCustom238.raw(), 238);
        assert_eq!(ElfRelocationType::RRiscvCustom239.raw(), 239);
        assert_eq!(ElfRelocationType::RRiscvCustom240.raw(), 240);
        assert_eq!(ElfRelocationType::RRiscvCustom241.raw(), 241);
        assert_eq!(ElfRelocationType::RRiscvCustom242.raw(), 242);
        assert_eq!(ElfRelocationType::RRiscvCustom243.raw(), 243);
        assert_eq!(ElfRelocationType::RRiscvCustom244.raw(), 244);
        assert_eq!(ElfRelocationType::RRiscvCustom245.raw(), 245);
        assert_eq!(ElfRelocationType::RRiscvCustom246.raw(), 246);
        assert_eq!(ElfRelocationType::RRiscvCustom247.raw(), 247);
        assert_eq!(ElfRelocationType::RRiscvCustom248.raw(), 248);
        assert_eq!(ElfRelocationType::RRiscvCustom249.raw(), 249);
        assert_eq!(ElfRelocationType::RRiscvCustom250.raw(), 250);
        assert_eq!(ElfRelocationType::RRiscvCustom251.raw(), 251);
        assert_eq!(ElfRelocationType::RRiscvCustom252.raw(), 252);
        assert_eq!(ElfRelocationType::RRiscvCustom253.raw(), 253);
        assert_eq!(ElfRelocationType::RRiscvCustom254.raw(), 254);
        assert_eq!(ElfRelocationType::RRiscvCustom255.raw(), 255);
        assert_eq!(ElfRelocationType::RRiscvGot32Pcrel.raw(), 41);
        assert_eq!(ElfRelocationType::RRiscvGotHi20.raw(), 20);
        assert_eq!(ElfRelocationType::RRiscvHi20.raw(), 26);
        assert_eq!(ElfRelocationType::RRiscvIrelative.raw(), 58);
        assert_eq!(ElfRelocationType::RRiscvJal.raw(), 17);
        assert_eq!(ElfRelocationType::RRiscvJumpSlot.raw(), 5);
        assert_eq!(ElfRelocationType::RRiscvLo12I.raw(), 27);
        assert_eq!(ElfRelocationType::RRiscvLo12S.raw(), 28);
        assert_eq!(ElfRelocationType::RRiscvNone.raw(), 0);
        assert_eq!(ElfRelocationType::RRiscvPcrelHi20.raw(), 23);
        assert_eq!(ElfRelocationType::RRiscvPcrelLo12I.raw(), 24);
        assert_eq!(ElfRelocationType::RRiscvPcrelLo12S.raw(), 25);
        assert_eq!(ElfRelocationType::RRiscvPlt32.raw(), 59);
        assert_eq!(ElfRelocationType::RRiscvRelative.raw(), 3);
        assert_eq!(ElfRelocationType::RRiscvRelax.raw(), 51);
        assert_eq!(ElfRelocationType::RRiscvRvcBranch.raw(), 44);
        assert_eq!(ElfRelocationType::RRiscvRvcJump.raw(), 45);
        assert_eq!(ElfRelocationType::RRiscvSet16.raw(), 55);
        assert_eq!(ElfRelocationType::RRiscvSet32.raw(), 56);
        assert_eq!(ElfRelocationType::RRiscvSet6.raw(), 53);
        assert_eq!(ElfRelocationType::RRiscvSet8.raw(), 54);
        assert_eq!(ElfRelocationType::RRiscvSetUleb128.raw(), 60);
        assert_eq!(ElfRelocationType::RRiscvSub16.raw(), 38);
        assert_eq!(ElfRelocationType::RRiscvSub32.raw(), 39);
        assert_eq!(ElfRelocationType::RRiscvSub6.raw(), 52);
        assert_eq!(ElfRelocationType::RRiscvSub64.raw(), 40);
        assert_eq!(ElfRelocationType::RRiscvSub8.raw(), 37);
        assert_eq!(ElfRelocationType::RRiscvSubUleb128.raw(), 61);
        assert_eq!(ElfRelocationType::RRiscvTlsdesc.raw(), 12);
        assert_eq!(ElfRelocationType::RRiscvTlsdescAddLo12.raw(), 64);
        assert_eq!(ElfRelocationType::RRiscvTlsdescCall.raw(), 65);
        assert_eq!(ElfRelocationType::RRiscvTlsdescHi20.raw(), 62);
        assert_eq!(ElfRelocationType::RRiscvTlsdescLoadLo12.raw(), 63);
        assert_eq!(ElfRelocationType::RRiscvTlsDtpmod32.raw(), 6);
        assert_eq!(ElfRelocationType::RRiscvTlsDtpmod64.raw(), 7);
        assert_eq!(ElfRelocationType::RRiscvTlsDtprel32.raw(), 8);
        assert_eq!(ElfRelocationType::RRiscvTlsDtprel64.raw(), 9);
        assert_eq!(ElfRelocationType::RRiscvTlsGdHi20.raw(), 22);
        assert_eq!(ElfRelocationType::RRiscvTlsGotHi20.raw(), 21);
        assert_eq!(ElfRelocationType::RRiscvTlsTprel32.raw(), 10);
        assert_eq!(ElfRelocationType::RRiscvTlsTprel64.raw(), 11);
        assert_eq!(ElfRelocationType::RRiscvTprelAdd.raw(), 32);
        assert_eq!(ElfRelocationType::RRiscvTprelHi20.raw(), 29);
        assert_eq!(ElfRelocationType::RRiscvTprelLo12I.raw(), 30);
        assert_eq!(ElfRelocationType::RRiscvTprelLo12S.raw(), 31);
        assert_eq!(ElfRelocationType::RRiscvVendor.raw(), 191);
        assert_eq!(ElfRelocationType::RSparc10.raw(), 30);
        assert_eq!(ElfRelocationType::RSparc11.raw(), 31);
        assert_eq!(ElfRelocationType::RSparc13.raw(), 11);
        assert_eq!(ElfRelocationType::RSparc16.raw(), 2);
        assert_eq!(ElfRelocationType::RSparc22.raw(), 10);
        assert_eq!(ElfRelocationType::RSparc32.raw(), 3);
        assert_eq!(ElfRelocationType::RSparc5.raw(), 44);
        assert_eq!(ElfRelocationType::RSparc6.raw(), 45);
        assert_eq!(ElfRelocationType::RSparc64.raw(), 32);
        assert_eq!(ElfRelocationType::RSparc7.raw(), 43);
        assert_eq!(ElfRelocationType::RSparc8.raw(), 1);
        assert_eq!(ElfRelocationType::RSparcCopy.raw(), 19);
        assert_eq!(ElfRelocationType::RSparcDisp16.raw(), 5);
        assert_eq!(ElfRelocationType::RSparcDisp32.raw(), 6);
        assert_eq!(ElfRelocationType::RSparcDisp64.raw(), 46);
        assert_eq!(ElfRelocationType::RSparcDisp8.raw(), 4);
        assert_eq!(ElfRelocationType::RSparcGlobDat.raw(), 20);
        assert_eq!(ElfRelocationType::RSparcGot10.raw(), 13);
        assert_eq!(ElfRelocationType::RSparcGot13.raw(), 14);
        assert_eq!(ElfRelocationType::RSparcGot22.raw(), 15);
        assert_eq!(ElfRelocationType::RSparcGotdataHix22.raw(), 80);
        assert_eq!(ElfRelocationType::RSparcGotdataLox10.raw(), 81);
        assert_eq!(ElfRelocationType::RSparcGotdataOp.raw(), 84);
        assert_eq!(ElfRelocationType::RSparcGotdataOpHix22.raw(), 82);
        assert_eq!(ElfRelocationType::RSparcGotdataOpLox10.raw(), 83);
        assert_eq!(ElfRelocationType::RSparcH44.raw(), 50);
        assert_eq!(ElfRelocationType::RSparcHh22.raw(), 34);
        assert_eq!(ElfRelocationType::RSparcHi22.raw(), 9);
        assert_eq!(ElfRelocationType::RSparcHiplt22.raw(), 25);
        assert_eq!(ElfRelocationType::RSparcHix22.raw(), 48);
        assert_eq!(ElfRelocationType::RSparcHm10.raw(), 35);
        assert_eq!(ElfRelocationType::RSparcJmpSlot.raw(), 21);
        assert_eq!(ElfRelocationType::RSparcL44.raw(), 52);
        assert_eq!(ElfRelocationType::RSparcLm22.raw(), 36);
        assert_eq!(ElfRelocationType::RSparcLo10.raw(), 12);
        assert_eq!(ElfRelocationType::RSparcLoplt10.raw(), 26);
        assert_eq!(ElfRelocationType::RSparcLox10.raw(), 49);
        assert_eq!(ElfRelocationType::RSparcM44.raw(), 51);
        assert_eq!(ElfRelocationType::RSparcNone.raw(), 0);
        assert_eq!(ElfRelocationType::RSparcOlo10.raw(), 33);
        assert_eq!(ElfRelocationType::RSparcPc10.raw(), 16);
        assert_eq!(ElfRelocationType::RSparcPc22.raw(), 17);
        assert_eq!(ElfRelocationType::RSparcPcplt10.raw(), 29);
        assert_eq!(ElfRelocationType::RSparcPcplt22.raw(), 28);
        assert_eq!(ElfRelocationType::RSparcPcplt32.raw(), 27);
        assert_eq!(ElfRelocationType::RSparcPcHh22.raw(), 37);
        assert_eq!(ElfRelocationType::RSparcPcHm10.raw(), 38);
        assert_eq!(ElfRelocationType::RSparcPcLm22.raw(), 39);
        assert_eq!(ElfRelocationType::RSparcPlt32.raw(), 24);
        assert_eq!(ElfRelocationType::RSparcPlt64.raw(), 47);
        assert_eq!(ElfRelocationType::RSparcRegister.raw(), 53);
        assert_eq!(ElfRelocationType::RSparcRelative.raw(), 22);
        assert_eq!(ElfRelocationType::RSparcTlsDtpmod32.raw(), 74);
        assert_eq!(ElfRelocationType::RSparcTlsDtpmod64.raw(), 75);
        assert_eq!(ElfRelocationType::RSparcTlsDtpoff32.raw(), 76);
        assert_eq!(ElfRelocationType::RSparcTlsDtpoff64.raw(), 77);
        assert_eq!(ElfRelocationType::RSparcTlsGdAdd.raw(), 58);
        assert_eq!(ElfRelocationType::RSparcTlsGdCall.raw(), 59);
        assert_eq!(ElfRelocationType::RSparcTlsGdHi22.raw(), 56);
        assert_eq!(ElfRelocationType::RSparcTlsGdLo10.raw(), 57);
        assert_eq!(ElfRelocationType::RSparcTlsIeAdd.raw(), 71);
        assert_eq!(ElfRelocationType::RSparcTlsIeHi22.raw(), 67);
        assert_eq!(ElfRelocationType::RSparcTlsIeLd.raw(), 69);
        assert_eq!(ElfRelocationType::RSparcTlsIeLdx.raw(), 70);
        assert_eq!(ElfRelocationType::RSparcTlsIeLo10.raw(), 68);
        assert_eq!(ElfRelocationType::RSparcTlsLdmAdd.raw(), 62);
        assert_eq!(ElfRelocationType::RSparcTlsLdmCall.raw(), 63);
        assert_eq!(ElfRelocationType::RSparcTlsLdmHi22.raw(), 60);
        assert_eq!(ElfRelocationType::RSparcTlsLdmLo10.raw(), 61);
        assert_eq!(ElfRelocationType::RSparcTlsLdoAdd.raw(), 66);
        assert_eq!(ElfRelocationType::RSparcTlsLdoHix22.raw(), 64);
        assert_eq!(ElfRelocationType::RSparcTlsLdoLox10.raw(), 65);
        assert_eq!(ElfRelocationType::RSparcTlsLeHix22.raw(), 72);
        assert_eq!(ElfRelocationType::RSparcTlsLeLox10.raw(), 73);
        assert_eq!(ElfRelocationType::RSparcTlsTpoff32.raw(), 78);
        assert_eq!(ElfRelocationType::RSparcTlsTpoff64.raw(), 79);
        assert_eq!(ElfRelocationType::RSparcUa16.raw(), 55);
        assert_eq!(ElfRelocationType::RSparcUa32.raw(), 23);
        assert_eq!(ElfRelocationType::RSparcUa64.raw(), 54);
        assert_eq!(ElfRelocationType::RSparcWdisp16.raw(), 40);
        assert_eq!(ElfRelocationType::RSparcWdisp19.raw(), 41);
        assert_eq!(ElfRelocationType::RSparcWdisp22.raw(), 8);
        assert_eq!(ElfRelocationType::RSparcWdisp30.raw(), 7);
        assert_eq!(ElfRelocationType::RSparcWplt30.raw(), 18);
        assert_eq!(ElfRelocationType::RVeCallHi32.raw(), 35);
        assert_eq!(ElfRelocationType::RVeCallLo32.raw(), 36);
        assert_eq!(ElfRelocationType::RVeCopy.raw(), 20);
        assert_eq!(ElfRelocationType::RVeDtpmod64.raw(), 22);
        assert_eq!(ElfRelocationType::RVeDtpoff32.raw(), 29);
        assert_eq!(ElfRelocationType::RVeDtpoff64.raw(), 23);
        assert_eq!(ElfRelocationType::RVeGlobDat.raw(), 18);
        assert_eq!(ElfRelocationType::RVeGot32.raw(), 8);
        assert_eq!(ElfRelocationType::RVeGotoff32.raw(), 11);
        assert_eq!(ElfRelocationType::RVeGotoffHi32.raw(), 12);
        assert_eq!(ElfRelocationType::RVeGotoffLo32.raw(), 13);
        assert_eq!(ElfRelocationType::RVeGotHi32.raw(), 9);
        assert_eq!(ElfRelocationType::RVeGotLo32.raw(), 10);
        assert_eq!(ElfRelocationType::RVeHi32.raw(), 4);
        assert_eq!(ElfRelocationType::RVeJumpSlot.raw(), 19);
        assert_eq!(ElfRelocationType::RVeLo32.raw(), 5);
        assert_eq!(ElfRelocationType::RVeNone.raw(), 0);
        assert_eq!(ElfRelocationType::RVePcHi32.raw(), 6);
        assert_eq!(ElfRelocationType::RVePcLo32.raw(), 7);
        assert_eq!(ElfRelocationType::RVePlt32.raw(), 14);
        assert_eq!(ElfRelocationType::RVePltHi32.raw(), 15);
        assert_eq!(ElfRelocationType::RVePltLo32.raw(), 16);
        assert_eq!(ElfRelocationType::RVeReflong.raw(), 1);
        assert_eq!(ElfRelocationType::RVeRefquad.raw(), 2);
        assert_eq!(ElfRelocationType::RVeRelative.raw(), 17);
        assert_eq!(ElfRelocationType::RVeSrel32.raw(), 3);
        assert_eq!(ElfRelocationType::RVeTlsGdHi32.raw(), 25);
        assert_eq!(ElfRelocationType::RVeTlsGdLo32.raw(), 26);
        assert_eq!(ElfRelocationType::RVeTlsIeHi32.raw(), 30);
        assert_eq!(ElfRelocationType::RVeTlsIeLo32.raw(), 31);
        assert_eq!(ElfRelocationType::RVeTlsLdHi32.raw(), 27);
        assert_eq!(ElfRelocationType::RVeTlsLdLo32.raw(), 28);
        assert_eq!(ElfRelocationType::RVeTpoff32.raw(), 34);
        assert_eq!(ElfRelocationType::RVeTpoff64.raw(), 24);
        assert_eq!(ElfRelocationType::RVeTpoffHi32.raw(), 32);
        assert_eq!(ElfRelocationType::RVeTpoffLo32.raw(), 33);
        assert_eq!(ElfRelocationType::RX866416.raw(), 12);
        assert_eq!(ElfRelocationType::RX866432.raw(), 10);
        assert_eq!(ElfRelocationType::RX866432S.raw(), 11);
        assert_eq!(ElfRelocationType::RX866464.raw(), 1);
        assert_eq!(ElfRelocationType::RX86648.raw(), 14);
        assert_eq!(ElfRelocationType::RX8664Code4Gotpc32Tlsdesc.raw(), 45);
        assert_eq!(ElfRelocationType::RX8664Code4Gotpcrelx.raw(), 43);
        assert_eq!(ElfRelocationType::RX8664Code4Gottpoff.raw(), 44);
        assert_eq!(ElfRelocationType::RX8664Code6Gottpoff.raw(), 50);
        assert_eq!(ElfRelocationType::RX8664Copy.raw(), 5);
        assert_eq!(ElfRelocationType::RX8664Dtpmod64.raw(), 16);
        assert_eq!(ElfRelocationType::RX8664Dtpoff32.raw(), 21);
        assert_eq!(ElfRelocationType::RX8664Dtpoff64.raw(), 17);
        assert_eq!(ElfRelocationType::RX8664GlobDat.raw(), 6);
        assert_eq!(ElfRelocationType::RX8664Got32.raw(), 3);
        assert_eq!(ElfRelocationType::RX8664Got64.raw(), 27);
        assert_eq!(ElfRelocationType::RX8664Gotoff64.raw(), 25);
        assert_eq!(ElfRelocationType::RX8664Gotpc32.raw(), 26);
        assert_eq!(ElfRelocationType::RX8664Gotpc32Tlsdesc.raw(), 34);
        assert_eq!(ElfRelocationType::RX8664Gotpc64.raw(), 29);
        assert_eq!(ElfRelocationType::RX8664Gotpcrel.raw(), 9);
        assert_eq!(ElfRelocationType::RX8664Gotpcrel64.raw(), 28);
        assert_eq!(ElfRelocationType::RX8664Gotpcrelx.raw(), 41);
        assert_eq!(ElfRelocationType::RX8664Gotplt64.raw(), 30);
        assert_eq!(ElfRelocationType::RX8664Gottpoff.raw(), 22);
        assert_eq!(ElfRelocationType::RX8664Irelative.raw(), 37);
        assert_eq!(ElfRelocationType::RX8664JumpSlot.raw(), 7);
        assert_eq!(ElfRelocationType::RX8664None.raw(), 0);
        assert_eq!(ElfRelocationType::RX8664Pc16.raw(), 13);
        assert_eq!(ElfRelocationType::RX8664Pc32.raw(), 2);
        assert_eq!(ElfRelocationType::RX8664Pc64.raw(), 24);
        assert_eq!(ElfRelocationType::RX8664Pc8.raw(), 15);
        assert_eq!(ElfRelocationType::RX8664Plt32.raw(), 4);
        assert_eq!(ElfRelocationType::RX8664Pltoff64.raw(), 31);
        assert_eq!(ElfRelocationType::RX8664Relative.raw(), 8);
        assert_eq!(ElfRelocationType::RX8664RexGotpcrelx.raw(), 42);
        assert_eq!(ElfRelocationType::RX8664Size32.raw(), 32);
        assert_eq!(ElfRelocationType::RX8664Size64.raw(), 33);
        assert_eq!(ElfRelocationType::RX8664Tlsdesc.raw(), 36);
        assert_eq!(ElfRelocationType::RX8664TlsdescCall.raw(), 35);
        assert_eq!(ElfRelocationType::RX8664Tlsgd.raw(), 19);
        assert_eq!(ElfRelocationType::RX8664Tlsld.raw(), 20);
        assert_eq!(ElfRelocationType::RX8664Tpoff32.raw(), 23);
        assert_eq!(ElfRelocationType::RX8664Tpoff64.raw(), 18);
        assert_eq!(ElfRelocationType::RXtensa32.raw(), 1);
        assert_eq!(ElfRelocationType::RXtensa32Pcrel.raw(), 14);
        assert_eq!(ElfRelocationType::RXtensaAsmExpand.raw(), 11);
        assert_eq!(ElfRelocationType::RXtensaAsmSimplify.raw(), 12);
        assert_eq!(ElfRelocationType::RXtensaDiff16.raw(), 18);
        assert_eq!(ElfRelocationType::RXtensaDiff32.raw(), 19);
        assert_eq!(ElfRelocationType::RXtensaDiff8.raw(), 17);
        assert_eq!(ElfRelocationType::RXtensaGlobDat.raw(), 3);
        assert_eq!(ElfRelocationType::RXtensaGnuVtentry.raw(), 16);
        assert_eq!(ElfRelocationType::RXtensaGnuVtinherit.raw(), 15);
        assert_eq!(ElfRelocationType::RXtensaJmpSlot.raw(), 4);
        assert_eq!(ElfRelocationType::RXtensaNone.raw(), 0);
        assert_eq!(ElfRelocationType::RXtensaOp0.raw(), 8);
        assert_eq!(ElfRelocationType::RXtensaOp1.raw(), 9);
        assert_eq!(ElfRelocationType::RXtensaOp2.raw(), 10);
        assert_eq!(ElfRelocationType::RXtensaPlt.raw(), 6);
        assert_eq!(ElfRelocationType::RXtensaRelative.raw(), 5);
        assert_eq!(ElfRelocationType::RXtensaRtld.raw(), 2);
        assert_eq!(ElfRelocationType::RXtensaSlot0Alt.raw(), 35);
        assert_eq!(ElfRelocationType::RXtensaSlot0Op.raw(), 20);
        assert_eq!(ElfRelocationType::RXtensaSlot10Alt.raw(), 45);
        assert_eq!(ElfRelocationType::RXtensaSlot10Op.raw(), 30);
        assert_eq!(ElfRelocationType::RXtensaSlot11Alt.raw(), 46);
        assert_eq!(ElfRelocationType::RXtensaSlot11Op.raw(), 31);
        assert_eq!(ElfRelocationType::RXtensaSlot12Alt.raw(), 47);
        assert_eq!(ElfRelocationType::RXtensaSlot12Op.raw(), 32);
        assert_eq!(ElfRelocationType::RXtensaSlot13Alt.raw(), 48);
        assert_eq!(ElfRelocationType::RXtensaSlot13Op.raw(), 33);
        assert_eq!(ElfRelocationType::RXtensaSlot14Alt.raw(), 49);
        assert_eq!(ElfRelocationType::RXtensaSlot14Op.raw(), 34);
        assert_eq!(ElfRelocationType::RXtensaSlot1Alt.raw(), 36);
        assert_eq!(ElfRelocationType::RXtensaSlot1Op.raw(), 21);
        assert_eq!(ElfRelocationType::RXtensaSlot2Alt.raw(), 37);
        assert_eq!(ElfRelocationType::RXtensaSlot2Op.raw(), 22);
        assert_eq!(ElfRelocationType::RXtensaSlot3Alt.raw(), 38);
        assert_eq!(ElfRelocationType::RXtensaSlot3Op.raw(), 23);
        assert_eq!(ElfRelocationType::RXtensaSlot4Alt.raw(), 39);
        assert_eq!(ElfRelocationType::RXtensaSlot4Op.raw(), 24);
        assert_eq!(ElfRelocationType::RXtensaSlot5Alt.raw(), 40);
        assert_eq!(ElfRelocationType::RXtensaSlot5Op.raw(), 25);
        assert_eq!(ElfRelocationType::RXtensaSlot6Alt.raw(), 41);
        assert_eq!(ElfRelocationType::RXtensaSlot6Op.raw(), 26);
        assert_eq!(ElfRelocationType::RXtensaSlot7Alt.raw(), 42);
        assert_eq!(ElfRelocationType::RXtensaSlot7Op.raw(), 27);
        assert_eq!(ElfRelocationType::RXtensaSlot8Alt.raw(), 43);
        assert_eq!(ElfRelocationType::RXtensaSlot8Op.raw(), 28);
        assert_eq!(ElfRelocationType::RXtensaSlot9Alt.raw(), 44);
        assert_eq!(ElfRelocationType::RXtensaSlot9Op.raw(), 29);
        assert_eq!(ElfRelocationType::RXtensaTlsdescArg.raw(), 51);
        assert_eq!(ElfRelocationType::RXtensaTlsdescFn.raw(), 50);
        assert_eq!(ElfRelocationType::RXtensaTlsArg.raw(), 55);
        assert_eq!(ElfRelocationType::RXtensaTlsCall.raw(), 56);
        assert_eq!(ElfRelocationType::RXtensaTlsDtpoff.raw(), 52);
        assert_eq!(ElfRelocationType::RXtensaTlsFunc.raw(), 54);
        assert_eq!(ElfRelocationType::RXtensaTlsTpoff.raw(), 53);
        assert_eq!(ElfRelocationType::from_raw(0).raw(), 0);
        assert_eq!(ElfRelocationType::from_raw(20).raw(), 20);
        assert_eq!(ElfRelocationType::from_raw(1).raw(), 1);
        assert_eq!(ElfRelocationType::from_raw(11).raw(), 11);
        assert_eq!(ElfRelocationType::from_raw(22).raw(), 22);
        assert_eq!(ElfRelocationType::from_raw(5).raw(), 5);
        assert_eq!(ElfRelocationType::from_raw(6).raw(), 6);
        assert_eq!(ElfRelocationType::from_raw(3).raw(), 3);
        assert_eq!(ElfRelocationType::from_raw(43).raw(), 43);
        assert_eq!(ElfRelocationType::from_raw(9).raw(), 9);
        assert_eq!(ElfRelocationType::from_raw(10).raw(), 10);
        assert_eq!(ElfRelocationType::from_raw(42).raw(), 42);
        assert_eq!(ElfRelocationType::from_raw(7).raw(), 7);
        assert_eq!(ElfRelocationType::from_raw(21).raw(), 21);
        assert_eq!(ElfRelocationType::from_raw(2).raw(), 2);
        assert_eq!(ElfRelocationType::from_raw(23).raw(), 23);
        assert_eq!(ElfRelocationType::from_raw(4).raw(), 4);
        assert_eq!(ElfRelocationType::from_raw(8).raw(), 8);
        assert_eq!(ElfRelocationType::from_raw(41).raw(), 41);
        assert_eq!(ElfRelocationType::from_raw(40).raw(), 40);
        assert_eq!(ElfRelocationType::from_raw(35).raw(), 35);
        assert_eq!(ElfRelocationType::from_raw(36).raw(), 36);
        assert_eq!(ElfRelocationType::from_raw(18).raw(), 18);
        assert_eq!(ElfRelocationType::from_raw(24).raw(), 24);
        assert_eq!(ElfRelocationType::from_raw(26).raw(), 26);
        assert_eq!(ElfRelocationType::from_raw(27).raw(), 27);
        assert_eq!(ElfRelocationType::from_raw(25).raw(), 25);
        assert_eq!(ElfRelocationType::from_raw(39).raw(), 39);
        assert_eq!(ElfRelocationType::from_raw(16).raw(), 16);
        assert_eq!(ElfRelocationType::from_raw(15).raw(), 15);
        assert_eq!(ElfRelocationType::from_raw(33).raw(), 33);
        assert_eq!(ElfRelocationType::from_raw(19).raw(), 19);
        assert_eq!(ElfRelocationType::from_raw(28).raw(), 28);
        assert_eq!(ElfRelocationType::from_raw(30).raw(), 30);
        assert_eq!(ElfRelocationType::from_raw(31).raw(), 31);
        assert_eq!(ElfRelocationType::from_raw(29).raw(), 29);
        assert_eq!(ElfRelocationType::from_raw(32).raw(), 32);
        assert_eq!(ElfRelocationType::from_raw(17).raw(), 17);
        assert_eq!(ElfRelocationType::from_raw(34).raw(), 34);
        assert_eq!(ElfRelocationType::from_raw(14).raw(), 14);
        assert_eq!(ElfRelocationType::from_raw(37).raw(), 37);
        assert_eq!(ElfRelocationType::from_raw(57).raw(), 57);
        assert_eq!(ElfRelocationType::from_raw(58).raw(), 58);
        assert_eq!(ElfRelocationType::from_raw(13).raw(), 13);
        assert_eq!(ElfRelocationType::from_raw(59).raw(), 59);
        assert_eq!(ElfRelocationType::from_raw(61).raw(), 61);
        assert_eq!(ElfRelocationType::from_raw(62).raw(), 62);
        assert_eq!(ElfRelocationType::from_raw(64).raw(), 64);
        assert_eq!(ElfRelocationType::from_raw(63).raw(), 63);
        assert_eq!(ElfRelocationType::from_raw(65).raw(), 65);
        assert_eq!(ElfRelocationType::from_raw(12).raw(), 12);
        assert_eq!(ElfRelocationType::from_raw(54).raw(), 54);
        assert_eq!(ElfRelocationType::from_raw(55).raw(), 55);
        assert_eq!(ElfRelocationType::from_raw(38).raw(), 38);
        assert_eq!(ElfRelocationType::from_raw(60).raw(), 60);
        assert_eq!(ElfRelocationType::from_raw(44).raw(), 44);
        assert_eq!(ElfRelocationType::from_raw(47).raw(), 47);
        assert_eq!(ElfRelocationType::from_raw(48).raw(), 48);
        assert_eq!(ElfRelocationType::from_raw(49).raw(), 49);
        assert_eq!(ElfRelocationType::from_raw(45).raw(), 45);
        assert_eq!(ElfRelocationType::from_raw(46).raw(), 46);
        assert_eq!(ElfRelocationType::from_raw(52).raw(), 52);
        assert_eq!(ElfRelocationType::from_raw(53).raw(), 53);
        assert_eq!(ElfRelocationType::from_raw(50).raw(), 50);
        assert_eq!(ElfRelocationType::from_raw(51).raw(), 51);
        assert_eq!(ElfRelocationType::from_raw(56).raw(), 56);
        assert_eq!(ElfRelocationType::from_raw(259).raw(), 259);
        assert_eq!(ElfRelocationType::from_raw(258).raw(), 258);
        assert_eq!(ElfRelocationType::from_raw(257).raw(), 257);
        assert_eq!(ElfRelocationType::from_raw(277).raw(), 277);
        assert_eq!(ElfRelocationType::from_raw(311).raw(), 311);
        assert_eq!(ElfRelocationType::from_raw(274).raw(), 274);
        assert_eq!(ElfRelocationType::from_raw(275).raw(), 275);
        assert_eq!(ElfRelocationType::from_raw(276).raw(), 276);
        assert_eq!(ElfRelocationType::from_raw(580).raw(), 580);
        assert_eq!(ElfRelocationType::from_raw(590).raw(), 590);
        assert_eq!(ElfRelocationType::from_raw(1042).raw(), 1042);
        assert_eq!(ElfRelocationType::from_raw(593).raw(), 593);
        assert_eq!(ElfRelocationType::from_raw(594).raw(), 594);
        assert_eq!(ElfRelocationType::from_raw(588).raw(), 588);
        assert_eq!(ElfRelocationType::from_raw(1044).raw(), 1044);
        assert_eq!(ElfRelocationType::from_raw(589).raw(), 589);
        assert_eq!(ElfRelocationType::from_raw(592).raw(), 592);
        assert_eq!(ElfRelocationType::from_raw(591).raw(), 591);
        assert_eq!(ElfRelocationType::from_raw(581).raw(), 581);
        assert_eq!(ElfRelocationType::from_raw(582).raw(), 582);
        assert_eq!(ElfRelocationType::from_raw(583).raw(), 583);
        assert_eq!(ElfRelocationType::from_raw(584).raw(), 584);
        assert_eq!(ElfRelocationType::from_raw(585).raw(), 585);
        assert_eq!(ElfRelocationType::from_raw(586).raw(), 586);
        assert_eq!(ElfRelocationType::from_raw(587).raw(), 587);
        assert_eq!(ElfRelocationType::from_raw(1041).raw(), 1041);
        assert_eq!(ElfRelocationType::from_raw(1043).raw(), 1043);
        assert_eq!(ElfRelocationType::from_raw(597).raw(), 597);
        assert_eq!(ElfRelocationType::from_raw(595).raw(), 595);
        assert_eq!(ElfRelocationType::from_raw(596).raw(), 596);
        assert_eq!(ElfRelocationType::from_raw(283).raw(), 283);
        assert_eq!(ElfRelocationType::from_raw(280).raw(), 280);
        assert_eq!(ElfRelocationType::from_raw(1024).raw(), 1024);
        assert_eq!(ElfRelocationType::from_raw(1025).raw(), 1025);
        assert_eq!(ElfRelocationType::from_raw(315).raw(), 315);
        assert_eq!(ElfRelocationType::from_raw(308).raw(), 308);
        assert_eq!(ElfRelocationType::from_raw(307).raw(), 307);
        assert_eq!(ElfRelocationType::from_raw(309).raw(), 309);
        assert_eq!(ElfRelocationType::from_raw(1032).raw(), 1032);
        assert_eq!(ElfRelocationType::from_raw(282).raw(), 282);
        assert_eq!(ElfRelocationType::from_raw(1026).raw(), 1026);
        assert_eq!(ElfRelocationType::from_raw(310).raw(), 310);
        assert_eq!(ElfRelocationType::from_raw(313).raw(), 313);
        assert_eq!(ElfRelocationType::from_raw(312).raw(), 312);
        assert_eq!(ElfRelocationType::from_raw(299).raw(), 299);
        assert_eq!(ElfRelocationType::from_raw(284).raw(), 284);
        assert_eq!(ElfRelocationType::from_raw(285).raw(), 285);
        assert_eq!(ElfRelocationType::from_raw(286).raw(), 286);
        assert_eq!(ElfRelocationType::from_raw(278).raw(), 278);
        assert_eq!(ElfRelocationType::from_raw(273).raw(), 273);
        assert_eq!(ElfRelocationType::from_raw(300).raw(), 300);
        assert_eq!(ElfRelocationType::from_raw(301).raw(), 301);
        assert_eq!(ElfRelocationType::from_raw(302).raw(), 302);
        assert_eq!(ElfRelocationType::from_raw(303).raw(), 303);
        assert_eq!(ElfRelocationType::from_raw(304).raw(), 304);
        assert_eq!(ElfRelocationType::from_raw(305).raw(), 305);
        assert_eq!(ElfRelocationType::from_raw(306).raw(), 306);
        assert_eq!(ElfRelocationType::from_raw(287).raw(), 287);
        assert_eq!(ElfRelocationType::from_raw(288).raw(), 288);
        assert_eq!(ElfRelocationType::from_raw(289).raw(), 289);
        assert_eq!(ElfRelocationType::from_raw(290).raw(), 290);
        assert_eq!(ElfRelocationType::from_raw(291).raw(), 291);
        assert_eq!(ElfRelocationType::from_raw(292).raw(), 292);
        assert_eq!(ElfRelocationType::from_raw(293).raw(), 293);
        assert_eq!(ElfRelocationType::from_raw(270).raw(), 270);
        assert_eq!(ElfRelocationType::from_raw(271).raw(), 271);
        assert_eq!(ElfRelocationType::from_raw(272).raw(), 272);
        assert_eq!(ElfRelocationType::from_raw(263).raw(), 263);
        assert_eq!(ElfRelocationType::from_raw(264).raw(), 264);
        assert_eq!(ElfRelocationType::from_raw(265).raw(), 265);
        assert_eq!(ElfRelocationType::from_raw(266).raw(), 266);
        assert_eq!(ElfRelocationType::from_raw(267).raw(), 267);
        assert_eq!(ElfRelocationType::from_raw(268).raw(), 268);
        assert_eq!(ElfRelocationType::from_raw(269).raw(), 269);
        assert_eq!(ElfRelocationType::from_raw(180).raw(), 180);
        assert_eq!(ElfRelocationType::from_raw(181).raw(), 181);
        assert_eq!(ElfRelocationType::from_raw(188).raw(), 188);
        assert_eq!(ElfRelocationType::from_raw(182).raw(), 182);
        assert_eq!(ElfRelocationType::from_raw(183).raw(), 183);
        assert_eq!(ElfRelocationType::from_raw(187).raw(), 187);
        assert_eq!(ElfRelocationType::from_raw(126).raw(), 126);
        assert_eq!(ElfRelocationType::from_raw(124).raw(), 124);
        assert_eq!(ElfRelocationType::from_raw(123).raw(), 123);
        assert_eq!(ElfRelocationType::from_raw(127).raw(), 127);
        assert_eq!(ElfRelocationType::from_raw(125).raw(), 125);
        assert_eq!(ElfRelocationType::from_raw(122).raw(), 122);
        assert_eq!(ElfRelocationType::from_raw(82).raw(), 82);
        assert_eq!(ElfRelocationType::from_raw(81).raw(), 81);
        assert_eq!(ElfRelocationType::from_raw(80).raw(), 80);
        assert_eq!(ElfRelocationType::from_raw(103).raw(), 103);
        assert_eq!(ElfRelocationType::from_raw(104).raw(), 104);
        assert_eq!(ElfRelocationType::from_raw(105).raw(), 105);
        assert_eq!(ElfRelocationType::from_raw(90).raw(), 90);
        assert_eq!(ElfRelocationType::from_raw(91).raw(), 91);
        assert_eq!(ElfRelocationType::from_raw(92).raw(), 92);
        assert_eq!(ElfRelocationType::from_raw(85).raw(), 85);
        assert_eq!(ElfRelocationType::from_raw(84).raw(), 84);
        assert_eq!(ElfRelocationType::from_raw(83).raw(), 83);
        assert_eq!(ElfRelocationType::from_raw(101).raw(), 101);
        assert_eq!(ElfRelocationType::from_raw(102).raw(), 102);
        assert_eq!(ElfRelocationType::from_raw(95).raw(), 95);
        assert_eq!(ElfRelocationType::from_raw(96).raw(), 96);
        assert_eq!(ElfRelocationType::from_raw(97).raw(), 97);
        assert_eq!(ElfRelocationType::from_raw(98).raw(), 98);
        assert_eq!(ElfRelocationType::from_raw(99).raw(), 99);
        assert_eq!(ElfRelocationType::from_raw(100).raw(), 100);
        assert_eq!(ElfRelocationType::from_raw(93).raw(), 93);
        assert_eq!(ElfRelocationType::from_raw(94).raw(), 94);
        assert_eq!(ElfRelocationType::from_raw(86).raw(), 86);
        assert_eq!(ElfRelocationType::from_raw(88).raw(), 88);
        assert_eq!(ElfRelocationType::from_raw(89).raw(), 89);
        assert_eq!(ElfRelocationType::from_raw(87).raw(), 87);
        assert_eq!(ElfRelocationType::from_raw(109).raw(), 109);
        assert_eq!(ElfRelocationType::from_raw(110).raw(), 110);
        assert_eq!(ElfRelocationType::from_raw(111).raw(), 111);
        assert_eq!(ElfRelocationType::from_raw(120).raw(), 120);
        assert_eq!(ElfRelocationType::from_raw(121).raw(), 121);
        assert_eq!(ElfRelocationType::from_raw(114).raw(), 114);
        assert_eq!(ElfRelocationType::from_raw(115).raw(), 115);
        assert_eq!(ElfRelocationType::from_raw(116).raw(), 116);
        assert_eq!(ElfRelocationType::from_raw(117).raw(), 117);
        assert_eq!(ElfRelocationType::from_raw(118).raw(), 118);
        assert_eq!(ElfRelocationType::from_raw(119).raw(), 119);
        assert_eq!(ElfRelocationType::from_raw(112).raw(), 112);
        assert_eq!(ElfRelocationType::from_raw(113).raw(), 113);
        assert_eq!(ElfRelocationType::from_raw(107).raw(), 107);
        assert_eq!(ElfRelocationType::from_raw(108).raw(), 108);
        assert_eq!(ElfRelocationType::from_raw(106).raw(), 106);
        assert_eq!(ElfRelocationType::from_raw(185).raw(), 185);
        assert_eq!(ElfRelocationType::from_raw(184).raw(), 184);
        assert_eq!(ElfRelocationType::from_raw(186).raw(), 186);
        assert_eq!(ElfRelocationType::from_raw(314).raw(), 314);
        assert_eq!(ElfRelocationType::from_raw(262).raw(), 262);
        assert_eq!(ElfRelocationType::from_raw(261).raw(), 261);
        assert_eq!(ElfRelocationType::from_raw(260).raw(), 260);
        assert_eq!(ElfRelocationType::from_raw(1027).raw(), 1027);
        assert_eq!(ElfRelocationType::from_raw(1031).raw(), 1031);
        assert_eq!(ElfRelocationType::from_raw(568).raw(), 568);
        assert_eq!(ElfRelocationType::from_raw(564).raw(), 564);
        assert_eq!(ElfRelocationType::from_raw(562).raw(), 562);
        assert_eq!(ElfRelocationType::from_raw(561).raw(), 561);
        assert_eq!(ElfRelocationType::from_raw(569).raw(), 569);
        assert_eq!(ElfRelocationType::from_raw(563).raw(), 563);
        assert_eq!(ElfRelocationType::from_raw(567).raw(), 567);
        assert_eq!(ElfRelocationType::from_raw(560).raw(), 560);
        assert_eq!(ElfRelocationType::from_raw(566).raw(), 566);
        assert_eq!(ElfRelocationType::from_raw(565).raw(), 565);
        assert_eq!(ElfRelocationType::from_raw(514).raw(), 514);
        assert_eq!(ElfRelocationType::from_raw(513).raw(), 513);
        assert_eq!(ElfRelocationType::from_raw(512).raw(), 512);
        assert_eq!(ElfRelocationType::from_raw(516).raw(), 516);
        assert_eq!(ElfRelocationType::from_raw(515).raw(), 515);
        assert_eq!(ElfRelocationType::from_raw(541).raw(), 541);
        assert_eq!(ElfRelocationType::from_raw(542).raw(), 542);
        assert_eq!(ElfRelocationType::from_raw(543).raw(), 543);
        assert_eq!(ElfRelocationType::from_raw(540).raw(), 540);
        assert_eq!(ElfRelocationType::from_raw(539).raw(), 539);
        assert_eq!(ElfRelocationType::from_raw(528).raw(), 528);
        assert_eq!(ElfRelocationType::from_raw(529).raw(), 529);
        assert_eq!(ElfRelocationType::from_raw(530).raw(), 530);
        assert_eq!(ElfRelocationType::from_raw(519).raw(), 519);
        assert_eq!(ElfRelocationType::from_raw(518).raw(), 518);
        assert_eq!(ElfRelocationType::from_raw(517).raw(), 517);
        assert_eq!(ElfRelocationType::from_raw(572).raw(), 572);
        assert_eq!(ElfRelocationType::from_raw(573).raw(), 573);
        assert_eq!(ElfRelocationType::from_raw(533).raw(), 533);
        assert_eq!(ElfRelocationType::from_raw(534).raw(), 534);
        assert_eq!(ElfRelocationType::from_raw(535).raw(), 535);
        assert_eq!(ElfRelocationType::from_raw(536).raw(), 536);
        assert_eq!(ElfRelocationType::from_raw(537).raw(), 537);
        assert_eq!(ElfRelocationType::from_raw(538).raw(), 538);
        assert_eq!(ElfRelocationType::from_raw(531).raw(), 531);
        assert_eq!(ElfRelocationType::from_raw(532).raw(), 532);
        assert_eq!(ElfRelocationType::from_raw(522).raw(), 522);
        assert_eq!(ElfRelocationType::from_raw(526).raw(), 526);
        assert_eq!(ElfRelocationType::from_raw(527).raw(), 527);
        assert_eq!(ElfRelocationType::from_raw(524).raw(), 524);
        assert_eq!(ElfRelocationType::from_raw(525).raw(), 525);
        assert_eq!(ElfRelocationType::from_raw(523).raw(), 523);
        assert_eq!(ElfRelocationType::from_raw(521).raw(), 521);
        assert_eq!(ElfRelocationType::from_raw(520).raw(), 520);
        assert_eq!(ElfRelocationType::from_raw(549).raw(), 549);
        assert_eq!(ElfRelocationType::from_raw(550).raw(), 550);
        assert_eq!(ElfRelocationType::from_raw(551).raw(), 551);
        assert_eq!(ElfRelocationType::from_raw(570).raw(), 570);
        assert_eq!(ElfRelocationType::from_raw(571).raw(), 571);
        assert_eq!(ElfRelocationType::from_raw(554).raw(), 554);
        assert_eq!(ElfRelocationType::from_raw(555).raw(), 555);
        assert_eq!(ElfRelocationType::from_raw(556).raw(), 556);
        assert_eq!(ElfRelocationType::from_raw(557).raw(), 557);
        assert_eq!(ElfRelocationType::from_raw(558).raw(), 558);
        assert_eq!(ElfRelocationType::from_raw(559).raw(), 559);
        assert_eq!(ElfRelocationType::from_raw(552).raw(), 552);
        assert_eq!(ElfRelocationType::from_raw(553).raw(), 553);
        assert_eq!(ElfRelocationType::from_raw(547).raw(), 547);
        assert_eq!(ElfRelocationType::from_raw(548).raw(), 548);
        assert_eq!(ElfRelocationType::from_raw(545).raw(), 545);
        assert_eq!(ElfRelocationType::from_raw(546).raw(), 546);
        assert_eq!(ElfRelocationType::from_raw(544).raw(), 544);
        assert_eq!(ElfRelocationType::from_raw(1028).raw(), 1028);
        assert_eq!(ElfRelocationType::from_raw(1029).raw(), 1029);
        assert_eq!(ElfRelocationType::from_raw(1030).raw(), 1030);
        assert_eq!(ElfRelocationType::from_raw(279).raw(), 279);
        assert_eq!(ElfRelocationType::from_raw(78).raw(), 78);
        assert_eq!(ElfRelocationType::from_raw(77).raw(), 77);
        assert_eq!(ElfRelocationType::from_raw(76).raw(), 76);
        assert_eq!(ElfRelocationType::from_raw(66).raw(), 66);
        assert_eq!(ElfRelocationType::from_raw(67).raw(), 67);
        assert_eq!(ElfRelocationType::from_raw(73).raw(), 73);
        assert_eq!(ElfRelocationType::from_raw(71).raw(), 71);
        assert_eq!(ElfRelocationType::from_raw(69).raw(), 69);
        assert_eq!(ElfRelocationType::from_raw(70).raw(), 70);
        assert_eq!(ElfRelocationType::from_raw(72).raw(), 72);
        assert_eq!(ElfRelocationType::from_raw(75).raw(), 75);
        assert_eq!(ElfRelocationType::from_raw(74).raw(), 74);
        assert_eq!(ElfRelocationType::from_raw(68).raw(), 68);
        assert_eq!(ElfRelocationType::from_raw(163).raw(), 163);
        assert_eq!(ElfRelocationType::from_raw(164).raw(), 164);
        assert_eq!(ElfRelocationType::from_raw(161).raw(), 161);
        assert_eq!(ElfRelocationType::from_raw(162).raw(), 162);
        assert_eq!(ElfRelocationType::from_raw(160).raw(), 160);
        assert_eq!(ElfRelocationType::from_raw(79).raw(), 79);
        assert_eq!(ElfRelocationType::from_raw(128).raw(), 128);
        assert_eq!(ElfRelocationType::from_raw(132).raw(), 132);
        assert_eq!(ElfRelocationType::from_raw(133).raw(), 133);
        assert_eq!(ElfRelocationType::from_raw(134).raw(), 134);
        assert_eq!(ElfRelocationType::from_raw(135).raw(), 135);
        assert_eq!(ElfRelocationType::from_raw(137).raw(), 137);
        assert_eq!(ElfRelocationType::from_raw(136).raw(), 136);
        assert_eq!(ElfRelocationType::from_raw(138).raw(), 138);
        assert_eq!(ElfRelocationType::from_raw(129).raw(), 129);
        assert_eq!(ElfRelocationType::from_raw(130).raw(), 130);
        assert_eq!(ElfRelocationType::from_raw(165).raw(), 165);
        assert_eq!(ElfRelocationType::from_raw(167).raw(), 167);
        assert_eq!(ElfRelocationType::from_raw(166).raw(), 166);
        assert_eq!(ElfRelocationType::from_raw(142).raw(), 142);
        assert_eq!(ElfRelocationType::from_raw(153).raw(), 153);
        assert_eq!(ElfRelocationType::from_raw(154).raw(), 154);
        assert_eq!(ElfRelocationType::from_raw(145).raw(), 145);
        assert_eq!(ElfRelocationType::from_raw(148).raw(), 148);
        assert_eq!(ElfRelocationType::from_raw(149).raw(), 149);
        assert_eq!(ElfRelocationType::from_raw(147).raw(), 147);
        assert_eq!(ElfRelocationType::from_raw(146).raw(), 146);
        assert_eq!(ElfRelocationType::from_raw(172).raw(), 172);
        assert_eq!(ElfRelocationType::from_raw(157).raw(), 157);
        assert_eq!(ElfRelocationType::from_raw(151).raw(), 151);
        assert_eq!(ElfRelocationType::from_raw(152).raw(), 152);
        assert_eq!(ElfRelocationType::from_raw(156).raw(), 156);
        assert_eq!(ElfRelocationType::from_raw(140).raw(), 140);
        assert_eq!(ElfRelocationType::from_raw(141).raw(), 141);
        assert_eq!(ElfRelocationType::from_raw(176).raw(), 176);
        assert_eq!(ElfRelocationType::from_raw(177).raw(), 177);
        assert_eq!(ElfRelocationType::from_raw(174).raw(), 174);
        assert_eq!(ElfRelocationType::from_raw(173).raw(), 173);
        assert_eq!(ElfRelocationType::from_raw(175).raw(), 175);
        assert_eq!(ElfRelocationType::from_raw(139).raw(), 139);
        assert_eq!(ElfRelocationType::from_raw(155).raw(), 155);
        assert_eq!(ElfRelocationType::from_raw(150).raw(), 150);
        assert_eq!(ElfRelocationType::from_raw(169).raw(), 169);
        assert_eq!(ElfRelocationType::from_raw(170).raw(), 170);
        assert_eq!(ElfRelocationType::from_raw(249).raw(), 249);
        assert_eq!(ElfRelocationType::from_raw(218).raw(), 218);
        assert_eq!(ElfRelocationType::from_raw(248).raw(), 248);
        assert_eq!(ElfRelocationType::from_raw(252).raw(), 252);
        assert_eq!(ElfRelocationType::from_raw(251).raw(), 251);
        assert_eq!(ElfRelocationType::from_raw(250).raw(), 250);
        assert_eq!(ElfRelocationType::from_raw(192).raw(), 192);
        assert_eq!(ElfRelocationType::from_raw(193).raw(), 193);
        assert_eq!(ElfRelocationType::from_raw(194).raw(), 194);
        assert_eq!(ElfRelocationType::from_raw(195).raw(), 195);
        assert_eq!(ElfRelocationType::from_raw(196).raw(), 196);
        assert_eq!(ElfRelocationType::from_raw(197).raw(), 197);
        assert_eq!(ElfRelocationType::from_raw(198).raw(), 198);
        assert_eq!(ElfRelocationType::from_raw(199).raw(), 199);
        assert_eq!(ElfRelocationType::from_raw(200).raw(), 200);
        assert_eq!(ElfRelocationType::from_raw(201).raw(), 201);
        assert_eq!(ElfRelocationType::from_raw(202).raw(), 202);
        assert_eq!(ElfRelocationType::from_raw(203).raw(), 203);
        assert_eq!(ElfRelocationType::from_raw(204).raw(), 204);
        assert_eq!(ElfRelocationType::from_raw(205).raw(), 205);
        assert_eq!(ElfRelocationType::from_raw(206).raw(), 206);
        assert_eq!(ElfRelocationType::from_raw(207).raw(), 207);
        assert_eq!(ElfRelocationType::from_raw(208).raw(), 208);
        assert_eq!(ElfRelocationType::from_raw(209).raw(), 209);
        assert_eq!(ElfRelocationType::from_raw(210).raw(), 210);
        assert_eq!(ElfRelocationType::from_raw(211).raw(), 211);
        assert_eq!(ElfRelocationType::from_raw(212).raw(), 212);
        assert_eq!(ElfRelocationType::from_raw(213).raw(), 213);
        assert_eq!(ElfRelocationType::from_raw(214).raw(), 214);
        assert_eq!(ElfRelocationType::from_raw(215).raw(), 215);
        assert_eq!(ElfRelocationType::from_raw(216).raw(), 216);
        assert_eq!(ElfRelocationType::from_raw(217).raw(), 217);
        assert_eq!(ElfRelocationType::from_raw(219).raw(), 219);
        assert_eq!(ElfRelocationType::from_raw(220).raw(), 220);
        assert_eq!(ElfRelocationType::from_raw(221).raw(), 221);
        assert_eq!(ElfRelocationType::from_raw(222).raw(), 222);
        assert_eq!(ElfRelocationType::from_raw(223).raw(), 223);
        assert_eq!(ElfRelocationType::from_raw(224).raw(), 224);
        assert_eq!(ElfRelocationType::from_raw(225).raw(), 225);
        assert_eq!(ElfRelocationType::from_raw(226).raw(), 226);
        assert_eq!(ElfRelocationType::from_raw(227).raw(), 227);
        assert_eq!(ElfRelocationType::from_raw(228).raw(), 228);
        assert_eq!(ElfRelocationType::from_raw(229).raw(), 229);
        assert_eq!(ElfRelocationType::from_raw(230).raw(), 230);
        assert_eq!(ElfRelocationType::from_raw(231).raw(), 231);
        assert_eq!(ElfRelocationType::from_raw(232).raw(), 232);
        assert_eq!(ElfRelocationType::from_raw(233).raw(), 233);
        assert_eq!(ElfRelocationType::from_raw(234).raw(), 234);
        assert_eq!(ElfRelocationType::from_raw(235).raw(), 235);
        assert_eq!(ElfRelocationType::from_raw(236).raw(), 236);
        assert_eq!(ElfRelocationType::from_raw(237).raw(), 237);
        assert_eq!(ElfRelocationType::from_raw(238).raw(), 238);
        assert_eq!(ElfRelocationType::from_raw(239).raw(), 239);
        assert_eq!(ElfRelocationType::from_raw(240).raw(), 240);
        assert_eq!(ElfRelocationType::from_raw(241).raw(), 241);
        assert_eq!(ElfRelocationType::from_raw(242).raw(), 242);
        assert_eq!(ElfRelocationType::from_raw(243).raw(), 243);
        assert_eq!(ElfRelocationType::from_raw(244).raw(), 244);
        assert_eq!(ElfRelocationType::from_raw(245).raw(), 245);
        assert_eq!(ElfRelocationType::from_raw(246).raw(), 246);
        assert_eq!(ElfRelocationType::from_raw(247).raw(), 247);
        assert_eq!(ElfRelocationType::from_raw(253).raw(), 253);
        assert_eq!(ElfRelocationType::from_raw(254).raw(), 254);
        assert_eq!(ElfRelocationType::from_raw(255).raw(), 255);
        assert_eq!(ElfRelocationType::from_raw(191).raw(), 191);
        assert_eq!(ElfRelocationType::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfDynamicTag>::default().raw(), 0);
        assert_eq!(ElfDynamicTag::Null.raw(), 0);
        assert_eq!(ElfDynamicTag::Needed.raw(), 1);
        assert_eq!(ElfDynamicTag::PltRelSize.raw(), 2);
        assert_eq!(ElfDynamicTag::PltGot.raw(), 3);
        assert_eq!(ElfDynamicTag::Hash.raw(), 4);
        assert_eq!(ElfDynamicTag::StringTable.raw(), 5);
        assert_eq!(ElfDynamicTag::SymbolTable.raw(), 6);
        assert_eq!(ElfDynamicTag::Rela.raw(), 7);
        assert_eq!(ElfDynamicTag::RelaSize.raw(), 8);
        assert_eq!(ElfDynamicTag::RelaEntrySize.raw(), 9);
        assert_eq!(ElfDynamicTag::StringSize.raw(), 10);
        assert_eq!(ElfDynamicTag::SymbolEntrySize.raw(), 11);
        assert_eq!(ElfDynamicTag::Init.raw(), 12);
        assert_eq!(ElfDynamicTag::Fini.raw(), 13);
        assert_eq!(ElfDynamicTag::Soname.raw(), 14);
        assert_eq!(ElfDynamicTag::Rpath.raw(), 15);
        assert_eq!(ElfDynamicTag::Symbolic.raw(), 16);
        assert_eq!(ElfDynamicTag::Rel.raw(), 17);
        assert_eq!(ElfDynamicTag::RelSize.raw(), 18);
        assert_eq!(ElfDynamicTag::RelEntrySize.raw(), 19);
        assert_eq!(ElfDynamicTag::PltRel.raw(), 20);
        assert_eq!(ElfDynamicTag::Debug.raw(), 21);
        assert_eq!(ElfDynamicTag::TextRel.raw(), 22);
        assert_eq!(ElfDynamicTag::JmpRel.raw(), 23);
        assert_eq!(ElfDynamicTag::BindNow.raw(), 24);
        assert_eq!(ElfDynamicTag::InitArray.raw(), 25);
        assert_eq!(ElfDynamicTag::FiniArray.raw(), 26);
        assert_eq!(ElfDynamicTag::InitArraySize.raw(), 27);
        assert_eq!(ElfDynamicTag::FiniArraySize.raw(), 28);
        assert_eq!(ElfDynamicTag::Runpath.raw(), 29);
        assert_eq!(ElfDynamicTag::Flags.raw(), 30);
        assert_eq!(ElfDynamicTag::Aarch64AuthRelr.raw(), 0x7000_0012);
        assert_eq!(ElfDynamicTag::Aarch64AuthRelrent.raw(), 0x7000_0013);
        assert_eq!(ElfDynamicTag::Aarch64AuthRelrsz.raw(), 0x7000_0011);
        assert_eq!(ElfDynamicTag::Aarch64BtiPlt.raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::Aarch64MemtagGlobals.raw(), 0x7000_000d);
        assert_eq!(ElfDynamicTag::Aarch64MemtagGlobalssz.raw(), 0x7000_000f);
        assert_eq!(ElfDynamicTag::Aarch64MemtagHeap.raw(), 0x7000_000b);
        assert_eq!(ElfDynamicTag::Aarch64MemtagMode.raw(), 0x7000_0009);
        assert_eq!(ElfDynamicTag::Aarch64MemtagStack.raw(), 0x7000_000c);
        assert_eq!(ElfDynamicTag::Aarch64PacPlt.raw(), 0x7000_0003);
        assert_eq!(ElfDynamicTag::Aarch64VariantPcs.raw(), 0x7000_0005);
        assert_eq!(ElfDynamicTag::AndroidRel.raw(), 0x6000_000f);
        assert_eq!(ElfDynamicTag::AndroidRela.raw(), 0x6000_0011);
        assert_eq!(ElfDynamicTag::AndroidRelasz.raw(), 0x6000_0012);
        assert_eq!(ElfDynamicTag::AndroidRelr.raw(), 0x6fff_e000);
        assert_eq!(ElfDynamicTag::AndroidRelrent.raw(), 0x6fff_e003);
        assert_eq!(ElfDynamicTag::AndroidRelrsz.raw(), 0x6fff_e001);
        assert_eq!(ElfDynamicTag::AndroidRelsz.raw(), 0x6000_0010);
        assert_eq!(ElfDynamicTag::Auxiliary.raw(), 0x7fff_fffd);
        assert_eq!(ElfDynamicTag::Crel.raw(), 0x4000_0026);
        assert_eq!(ElfDynamicTag::Filter.raw(), 0x7fff_ffff);
        assert_eq!(ElfDynamicTag::FiniArraysz.raw(), 28);
        assert_eq!(ElfDynamicTag::Flags1.raw(), 0x6fff_fffb);
        assert_eq!(ElfDynamicTag::GnuHash.raw(), 0x6fff_fef5);
        assert_eq!(ElfDynamicTag::HexagonPlt.raw(), 0x7000_0002);
        assert_eq!(ElfDynamicTag::HexagonSymsz.raw(), 0x7000_0000);
        assert_eq!(ElfDynamicTag::HexagonVer.raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::InitArraysz.raw(), 27);
        assert_eq!(ElfDynamicTag::Jmprel.raw(), 23);
        assert_eq!(ElfDynamicTag::MipsAuxDynamic.raw(), 0x7000_0031);
        assert_eq!(ElfDynamicTag::MipsBaseAddress.raw(), 0x7000_0006);
        assert_eq!(ElfDynamicTag::MipsCompactSize.raw(), 0x7000_002f);
        assert_eq!(ElfDynamicTag::MipsConflict.raw(), 0x7000_0008);
        assert_eq!(ElfDynamicTag::MipsConflictno.raw(), 0x7000_000b);
        assert_eq!(ElfDynamicTag::MipsCxxFlags.raw(), 0x7000_0022);
        assert_eq!(ElfDynamicTag::MipsDeltaClass.raw(), 0x7000_0017);
        assert_eq!(ElfDynamicTag::MipsDeltaClasssym.raw(), 0x7000_0020);
        assert_eq!(ElfDynamicTag::MipsDeltaClasssymNo.raw(), 0x7000_0021);
        assert_eq!(ElfDynamicTag::MipsDeltaClassNo.raw(), 0x7000_0018);
        assert_eq!(ElfDynamicTag::MipsDeltaInstance.raw(), 0x7000_0019);
        assert_eq!(ElfDynamicTag::MipsDeltaInstanceNo.raw(), 0x7000_001a);
        assert_eq!(ElfDynamicTag::MipsDeltaReloc.raw(), 0x7000_001b);
        assert_eq!(ElfDynamicTag::MipsDeltaRelocNo.raw(), 0x7000_001c);
        assert_eq!(ElfDynamicTag::MipsDeltaSym.raw(), 0x7000_001d);
        assert_eq!(ElfDynamicTag::MipsDeltaSymNo.raw(), 0x7000_001e);
        assert_eq!(ElfDynamicTag::MipsDynstrAlign.raw(), 0x7000_002b);
        assert_eq!(ElfDynamicTag::MipsFlags.raw(), 0x7000_0005);
        assert_eq!(ElfDynamicTag::MipsGotsym.raw(), 0x7000_0013);
        assert_eq!(ElfDynamicTag::MipsGpValue.raw(), 0x7000_0030);
        assert_eq!(ElfDynamicTag::MipsHiddenGotidx.raw(), 0x7000_0027);
        assert_eq!(ElfDynamicTag::MipsHipageno.raw(), 0x7000_0014);
        assert_eq!(ElfDynamicTag::MipsIchecksum.raw(), 0x7000_0003);
        assert_eq!(ElfDynamicTag::MipsInterface.raw(), 0x7000_002a);
        assert_eq!(ElfDynamicTag::MipsInterfaceSize.raw(), 0x7000_002c);
        assert_eq!(ElfDynamicTag::MipsIversion.raw(), 0x7000_0004);
        assert_eq!(ElfDynamicTag::MipsLiblist.raw(), 0x7000_0009);
        assert_eq!(ElfDynamicTag::MipsLiblistno.raw(), 0x7000_0010);
        assert_eq!(ElfDynamicTag::MipsLocalpageGotidx.raw(), 0x7000_0025);
        assert_eq!(ElfDynamicTag::MipsLocalGotidx.raw(), 0x7000_0026);
        assert_eq!(ElfDynamicTag::MipsLocalGotno.raw(), 0x7000_000a);
        assert_eq!(ElfDynamicTag::MipsMsym.raw(), 0x7000_0007);
        assert_eq!(ElfDynamicTag::MipsOptions.raw(), 0x7000_0029);
        assert_eq!(ElfDynamicTag::MipsPerfSuffix.raw(), 0x7000_002e);
        assert_eq!(ElfDynamicTag::MipsPixieInit.raw(), 0x7000_0023);
        assert_eq!(ElfDynamicTag::MipsPltgot.raw(), 0x7000_0032);
        assert_eq!(ElfDynamicTag::MipsProtectedGotidx.raw(), 0x7000_0028);
        assert_eq!(ElfDynamicTag::MipsRldMap.raw(), 0x7000_0016);
        assert_eq!(ElfDynamicTag::MipsRldMapRel.raw(), 0x7000_0035);
        assert_eq!(ElfDynamicTag::MipsRldTextResolveAddr.raw(), 0x7000_002d);
        assert_eq!(ElfDynamicTag::MipsRldVersion.raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::MipsRwplt.raw(), 0x7000_0034);
        assert_eq!(ElfDynamicTag::MipsSymbolLib.raw(), 0x7000_0024);
        assert_eq!(ElfDynamicTag::MipsSymtabno.raw(), 0x7000_0011);
        assert_eq!(ElfDynamicTag::MipsTimeStamp.raw(), 0x7000_0002);
        assert_eq!(ElfDynamicTag::MipsUnrefextno.raw(), 0x7000_0012);
        assert_eq!(ElfDynamicTag::MipsXhash.raw(), 0x7000_0036);
        assert_eq!(ElfDynamicTag::Pltgot.raw(), 3);
        assert_eq!(ElfDynamicTag::Pltrel.raw(), 20);
        assert_eq!(ElfDynamicTag::Pltrelsz.raw(), 2);
        assert_eq!(ElfDynamicTag::Ppc64Glink.raw(), 0x7000_0000);
        assert_eq!(ElfDynamicTag::Ppc64Opt.raw(), 0x7000_0003);
        assert_eq!(ElfDynamicTag::PpcGot.raw(), 0x7000_0000);
        assert_eq!(ElfDynamicTag::PpcOpt.raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::PreinitArray.raw(), 32);
        assert_eq!(ElfDynamicTag::PreinitArraysz.raw(), 33);
        assert_eq!(ElfDynamicTag::Relacount.raw(), 0x6fff_fff9);
        assert_eq!(ElfDynamicTag::Relaent.raw(), 9);
        assert_eq!(ElfDynamicTag::Relasz.raw(), 8);
        assert_eq!(ElfDynamicTag::Relcount.raw(), 0x6fff_fffa);
        assert_eq!(ElfDynamicTag::Relent.raw(), 19);
        assert_eq!(ElfDynamicTag::Relr.raw(), 36);
        assert_eq!(ElfDynamicTag::Relrent.raw(), 37);
        assert_eq!(ElfDynamicTag::Relrsz.raw(), 35);
        assert_eq!(ElfDynamicTag::Relsz.raw(), 18);
        assert_eq!(ElfDynamicTag::RiscvVariantCc.raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::Strsz.raw(), 10);
        assert_eq!(ElfDynamicTag::Strtab.raw(), 5);
        assert_eq!(ElfDynamicTag::Syment.raw(), 11);
        assert_eq!(ElfDynamicTag::Symtab.raw(), 6);
        assert_eq!(ElfDynamicTag::SymtabShndx.raw(), 34);
        assert_eq!(ElfDynamicTag::Textrel.raw(), 22);
        assert_eq!(ElfDynamicTag::TlsdescGot.raw(), 0x6fff_fef7);
        assert_eq!(ElfDynamicTag::TlsdescPlt.raw(), 0x6fff_fef6);
        assert_eq!(ElfDynamicTag::Used.raw(), 0x7fff_fffe);
        assert_eq!(ElfDynamicTag::Verdef.raw(), 0x6fff_fffc);
        assert_eq!(ElfDynamicTag::Verdefnum.raw(), 0x6fff_fffd);
        assert_eq!(ElfDynamicTag::Verneed.raw(), 0x6fff_fffe);
        assert_eq!(ElfDynamicTag::Verneednum.raw(), 0x6fff_ffff);
        assert_eq!(ElfDynamicTag::Versym.raw(), 0x6fff_fff0);
        assert_eq!(ElfDynamicTag::from_raw(0).raw(), 0);
        assert_eq!(ElfDynamicTag::from_raw(1).raw(), 1);
        assert_eq!(ElfDynamicTag::from_raw(2).raw(), 2);
        assert_eq!(ElfDynamicTag::from_raw(3).raw(), 3);
        assert_eq!(ElfDynamicTag::from_raw(4).raw(), 4);
        assert_eq!(ElfDynamicTag::from_raw(5).raw(), 5);
        assert_eq!(ElfDynamicTag::from_raw(6).raw(), 6);
        assert_eq!(ElfDynamicTag::from_raw(7).raw(), 7);
        assert_eq!(ElfDynamicTag::from_raw(8).raw(), 8);
        assert_eq!(ElfDynamicTag::from_raw(9).raw(), 9);
        assert_eq!(ElfDynamicTag::from_raw(10).raw(), 10);
        assert_eq!(ElfDynamicTag::from_raw(11).raw(), 11);
        assert_eq!(ElfDynamicTag::from_raw(12).raw(), 12);
        assert_eq!(ElfDynamicTag::from_raw(13).raw(), 13);
        assert_eq!(ElfDynamicTag::from_raw(14).raw(), 14);
        assert_eq!(ElfDynamicTag::from_raw(15).raw(), 15);
        assert_eq!(ElfDynamicTag::from_raw(16).raw(), 16);
        assert_eq!(ElfDynamicTag::from_raw(17).raw(), 17);
        assert_eq!(ElfDynamicTag::from_raw(18).raw(), 18);
        assert_eq!(ElfDynamicTag::from_raw(19).raw(), 19);
        assert_eq!(ElfDynamicTag::from_raw(20).raw(), 20);
        assert_eq!(ElfDynamicTag::from_raw(21).raw(), 21);
        assert_eq!(ElfDynamicTag::from_raw(22).raw(), 22);
        assert_eq!(ElfDynamicTag::from_raw(23).raw(), 23);
        assert_eq!(ElfDynamicTag::from_raw(24).raw(), 24);
        assert_eq!(ElfDynamicTag::from_raw(25).raw(), 25);
        assert_eq!(ElfDynamicTag::from_raw(26).raw(), 26);
        assert_eq!(ElfDynamicTag::from_raw(27).raw(), 27);
        assert_eq!(ElfDynamicTag::from_raw(28).raw(), 28);
        assert_eq!(ElfDynamicTag::from_raw(29).raw(), 29);
        assert_eq!(ElfDynamicTag::from_raw(30).raw(), 30);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0012).raw(), 0x7000_0012);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0013).raw(), 0x7000_0013);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0011).raw(), 0x7000_0011);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0001).raw(), 0x7000_0001);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_000d).raw(), 0x7000_000d);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_000f).raw(), 0x7000_000f);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_000b).raw(), 0x7000_000b);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0009).raw(), 0x7000_0009);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_000c).raw(), 0x7000_000c);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0003).raw(), 0x7000_0003);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0005).raw(), 0x7000_0005);
        assert_eq!(ElfDynamicTag::from_raw(0x6000_000f).raw(), 0x6000_000f);
        assert_eq!(ElfDynamicTag::from_raw(0x6000_0011).raw(), 0x6000_0011);
        assert_eq!(ElfDynamicTag::from_raw(0x6000_0012).raw(), 0x6000_0012);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_e000).raw(), 0x6fff_e000);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_e003).raw(), 0x6fff_e003);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_e001).raw(), 0x6fff_e001);
        assert_eq!(ElfDynamicTag::from_raw(0x6000_0010).raw(), 0x6000_0010);
        assert_eq!(ElfDynamicTag::from_raw(0x7fff_fffd).raw(), 0x7fff_fffd);
        assert_eq!(ElfDynamicTag::from_raw(0x4000_0026).raw(), 0x4000_0026);
        assert_eq!(ElfDynamicTag::from_raw(0x7fff_ffff).raw(), 0x7fff_ffff);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fffb).raw(), 0x6fff_fffb);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fef5).raw(), 0x6fff_fef5);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0002).raw(), 0x7000_0002);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0000).raw(), 0x7000_0000);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0031).raw(), 0x7000_0031);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0006).raw(), 0x7000_0006);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002f).raw(), 0x7000_002f);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0008).raw(), 0x7000_0008);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0022).raw(), 0x7000_0022);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0017).raw(), 0x7000_0017);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0020).raw(), 0x7000_0020);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0021).raw(), 0x7000_0021);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0018).raw(), 0x7000_0018);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0019).raw(), 0x7000_0019);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_001a).raw(), 0x7000_001a);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_001b).raw(), 0x7000_001b);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_001c).raw(), 0x7000_001c);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_001d).raw(), 0x7000_001d);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_001e).raw(), 0x7000_001e);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002b).raw(), 0x7000_002b);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0030).raw(), 0x7000_0030);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0027).raw(), 0x7000_0027);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0014).raw(), 0x7000_0014);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002a).raw(), 0x7000_002a);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002c).raw(), 0x7000_002c);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0004).raw(), 0x7000_0004);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0010).raw(), 0x7000_0010);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0025).raw(), 0x7000_0025);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0026).raw(), 0x7000_0026);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_000a).raw(), 0x7000_000a);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0007).raw(), 0x7000_0007);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0029).raw(), 0x7000_0029);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002e).raw(), 0x7000_002e);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0023).raw(), 0x7000_0023);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0032).raw(), 0x7000_0032);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0028).raw(), 0x7000_0028);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0016).raw(), 0x7000_0016);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0035).raw(), 0x7000_0035);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_002d).raw(), 0x7000_002d);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0034).raw(), 0x7000_0034);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0024).raw(), 0x7000_0024);
        assert_eq!(ElfDynamicTag::from_raw(0x7000_0036).raw(), 0x7000_0036);
        assert_eq!(ElfDynamicTag::from_raw(32).raw(), 32);
        assert_eq!(ElfDynamicTag::from_raw(33).raw(), 33);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fff9).raw(), 0x6fff_fff9);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fffa).raw(), 0x6fff_fffa);
        assert_eq!(ElfDynamicTag::from_raw(36).raw(), 36);
        assert_eq!(ElfDynamicTag::from_raw(37).raw(), 37);
        assert_eq!(ElfDynamicTag::from_raw(35).raw(), 35);
        assert_eq!(ElfDynamicTag::from_raw(34).raw(), 34);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fef7).raw(), 0x6fff_fef7);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fef6).raw(), 0x6fff_fef6);
        assert_eq!(ElfDynamicTag::from_raw(0x7fff_fffe).raw(), 0x7fff_fffe);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fffc).raw(), 0x6fff_fffc);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fffd).raw(), 0x6fff_fffd);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fffe).raw(), 0x6fff_fffe);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_ffff).raw(), 0x6fff_ffff);
        assert_eq!(ElfDynamicTag::from_raw(0x6fff_fff0).raw(), 0x6fff_fff0);
        assert_eq!(ElfDynamicTag::from_raw(-1).raw(), -1);
        assert_eq!(<ElfNoteType>::default().raw(), 0);
        assert_eq!(ElfNoteType::X386Ioperm.raw(), 513);
        assert_eq!(ElfNoteType::X386Tls.raw(), 512);
        assert_eq!(ElfNoteType::AmdgpuMetadata.raw(), 32);
        assert_eq!(ElfNoteType::AmdHsaCodeObjectVersion.raw(), 1);
        assert_eq!(ElfNoteType::AmdHsaHsail.raw(), 2);
        assert_eq!(ElfNoteType::AmdHsaIsaName.raw(), 11);
        assert_eq!(ElfNoteType::AmdHsaIsaVersion.raw(), 3);
        assert_eq!(ElfNoteType::AmdHsaMetadata.raw(), 10);
        assert_eq!(ElfNoteType::AmdPalMetadata.raw(), 12);
        assert_eq!(ElfNoteType::AndroidTypeIdent.raw(), 1);
        assert_eq!(ElfNoteType::AndroidTypeKuser.raw(), 3);
        assert_eq!(ElfNoteType::AndroidTypeMemtag.raw(), 4);
        assert_eq!(ElfNoteType::Arch.raw(), 2);
        assert_eq!(ElfNoteType::ArmFpmr.raw(), 1038);
        assert_eq!(ElfNoteType::ArmGcs.raw(), 1040);
        assert_eq!(ElfNoteType::ArmHwBreak.raw(), 1026);
        assert_eq!(ElfNoteType::ArmHwWatch.raw(), 1027);
        assert_eq!(ElfNoteType::ArmPacMask.raw(), 1030);
        assert_eq!(ElfNoteType::ArmSsve.raw(), 1035);
        assert_eq!(ElfNoteType::ArmSve.raw(), 1029);
        assert_eq!(ElfNoteType::ArmTaggedAddrCtrl.raw(), 1033);
        assert_eq!(ElfNoteType::ArmTls.raw(), 1025);
        assert_eq!(ElfNoteType::ArmVfp.raw(), 1024);
        assert_eq!(ElfNoteType::ArmZa.raw(), 1036);
        assert_eq!(ElfNoteType::ArmZt.raw(), 1037);
        assert_eq!(ElfNoteType::Auxv.raw(), 6);
        assert_eq!(ElfNoteType::File.raw(), 0x4649_4c45);
        assert_eq!(ElfNoteType::Fpregs.raw(), 12);
        assert_eq!(ElfNoteType::Fpregset.raw(), 2);
        assert_eq!(ElfNoteType::FreebsdAbiTag.raw(), 1);
        assert_eq!(ElfNoteType::FreebsdArchTag.raw(), 3);
        assert_eq!(ElfNoteType::FreebsdFctlAsgDisable.raw(), 32);
        assert_eq!(ElfNoteType::FreebsdFctlAslrDisable.raw(), 1);
        assert_eq!(ElfNoteType::FreebsdFctlLa48.raw(), 16);
        assert_eq!(ElfNoteType::FreebsdFctlProtmaxDisable.raw(), 2);
        assert_eq!(ElfNoteType::FreebsdFctlStkgapDisable.raw(), 4);
        assert_eq!(ElfNoteType::FreebsdFctlWxneeded.raw(), 8);
        assert_eq!(ElfNoteType::FreebsdFeatureCtl.raw(), 4);
        assert_eq!(ElfNoteType::FreebsdNoinitTag.raw(), 2);
        assert_eq!(ElfNoteType::FreebsdProcstatAuxv.raw(), 16);
        assert_eq!(ElfNoteType::FreebsdProcstatFiles.raw(), 9);
        assert_eq!(ElfNoteType::FreebsdProcstatGroups.raw(), 11);
        assert_eq!(ElfNoteType::FreebsdProcstatOsrel.raw(), 14);
        assert_eq!(ElfNoteType::FreebsdProcstatProc.raw(), 8);
        assert_eq!(ElfNoteType::FreebsdProcstatPsstrings.raw(), 15);
        assert_eq!(ElfNoteType::FreebsdProcstatRlimit.raw(), 13);
        assert_eq!(ElfNoteType::FreebsdProcstatUmask.raw(), 12);
        assert_eq!(ElfNoteType::FreebsdProcstatVmmap.raw(), 10);
        assert_eq!(ElfNoteType::FreebsdThrmisc.raw(), 7);
        assert_eq!(ElfNoteType::GnuAbiTag.raw(), 1);
        assert_eq!(ElfNoteType::GnuBuildAttributeFunc.raw(), 257);
        assert_eq!(ElfNoteType::GnuBuildAttributeOpen.raw(), 256);
        assert_eq!(ElfNoteType::GnuBuildId.raw(), 3);
        assert_eq!(ElfNoteType::GnuGoldVersion.raw(), 4);
        assert_eq!(ElfNoteType::GnuHwcap.raw(), 2);
        assert_eq!(ElfNoteType::GnuPropertyType0.raw(), 5);
        assert_eq!(ElfNoteType::LlvmHwasanGlobals.raw(), 3);
        assert_eq!(ElfNoteType::LlvmOpenmpOffloadProducer.raw(), 2);
        assert_eq!(ElfNoteType::LlvmOpenmpOffloadProducerVersion.raw(), 3);
        assert_eq!(ElfNoteType::LlvmOpenmpOffloadVersion.raw(), 1);
        assert_eq!(ElfNoteType::Lwpsinfo.raw(), 17);
        assert_eq!(ElfNoteType::Lwpstatus.raw(), 16);
        assert_eq!(ElfNoteType::MemtagHeap.raw(), 4);
        assert_eq!(ElfNoteType::MemtagLevelAsync.raw(), 1);
        assert_eq!(ElfNoteType::MemtagLevelMask.raw(), 3);
        assert_eq!(ElfNoteType::MemtagLevelNone.raw(), 0);
        assert_eq!(ElfNoteType::MemtagLevelSync.raw(), 2);
        assert_eq!(ElfNoteType::MemtagStack.raw(), 8);
        assert_eq!(ElfNoteType::NetbsdcoreAuxv.raw(), 2);
        assert_eq!(ElfNoteType::NetbsdcoreLwpstatus.raw(), 24);
        assert_eq!(ElfNoteType::NetbsdcoreProcinfo.raw(), 1);
        assert_eq!(ElfNoteType::OpenbsdAuxv.raw(), 11);
        assert_eq!(ElfNoteType::OpenbsdFpregs.raw(), 21);
        assert_eq!(ElfNoteType::OpenbsdProcinfo.raw(), 10);
        assert_eq!(ElfNoteType::OpenbsdRegs.raw(), 20);
        assert_eq!(ElfNoteType::OpenbsdWcookie.raw(), 23);
        assert_eq!(ElfNoteType::OpenbsdXfpregs.raw(), 22);
        assert_eq!(ElfNoteType::PpcDscr.raw(), 261);
        assert_eq!(ElfNoteType::PpcEbb.raw(), 262);
        assert_eq!(ElfNoteType::PpcPmu.raw(), 263);
        assert_eq!(ElfNoteType::PpcPpr.raw(), 260);
        assert_eq!(ElfNoteType::PpcTar.raw(), 259);
        assert_eq!(ElfNoteType::PpcTmCdscr.raw(), 271);
        assert_eq!(ElfNoteType::PpcTmCfpr.raw(), 265);
        assert_eq!(ElfNoteType::PpcTmCgpr.raw(), 264);
        assert_eq!(ElfNoteType::PpcTmCppr.raw(), 270);
        assert_eq!(ElfNoteType::PpcTmCtar.raw(), 269);
        assert_eq!(ElfNoteType::PpcTmCvmx.raw(), 266);
        assert_eq!(ElfNoteType::PpcTmCvsx.raw(), 267);
        assert_eq!(ElfNoteType::PpcTmSpr.raw(), 268);
        assert_eq!(ElfNoteType::PpcVmx.raw(), 256);
        assert_eq!(ElfNoteType::PpcVsx.raw(), 258);
        assert_eq!(ElfNoteType::Prpsinfo.raw(), 3);
        assert_eq!(ElfNoteType::Prstatus.raw(), 1);
        assert_eq!(ElfNoteType::Prxfpreg.raw(), 0x46e6_2b7f);
        assert_eq!(ElfNoteType::Psinfo.raw(), 13);
        assert_eq!(ElfNoteType::Pstatus.raw(), 10);
        assert_eq!(ElfNoteType::S390Ctrs.raw(), 772);
        assert_eq!(ElfNoteType::S390GsBc.raw(), 780);
        assert_eq!(ElfNoteType::S390GsCb.raw(), 779);
        assert_eq!(ElfNoteType::S390HighGprs.raw(), 768);
        assert_eq!(ElfNoteType::S390LastBreak.raw(), 774);
        assert_eq!(ElfNoteType::S390Prefix.raw(), 773);
        assert_eq!(ElfNoteType::S390SystemCall.raw(), 775);
        assert_eq!(ElfNoteType::S390Tdb.raw(), 776);
        assert_eq!(ElfNoteType::S390Timer.raw(), 769);
        assert_eq!(ElfNoteType::S390Todcmp.raw(), 770);
        assert_eq!(ElfNoteType::S390Todpreg.raw(), 771);
        assert_eq!(ElfNoteType::S390VxrsHigh.raw(), 778);
        assert_eq!(ElfNoteType::S390VxrsLow.raw(), 777);
        assert_eq!(ElfNoteType::Siginfo.raw(), 0x5349_4749);
        assert_eq!(ElfNoteType::Taskstruct.raw(), 4);
        assert_eq!(ElfNoteType::Version.raw(), 1);
        assert_eq!(ElfNoteType::Win32Pstatus.raw(), 18);
        assert_eq!(ElfNoteType::X86Xstate.raw(), 514);
        assert_eq!(ElfNoteType::from_raw(513).raw(), 513);
        assert_eq!(ElfNoteType::from_raw(512).raw(), 512);
        assert_eq!(ElfNoteType::from_raw(32).raw(), 32);
        assert_eq!(ElfNoteType::from_raw(1).raw(), 1);
        assert_eq!(ElfNoteType::from_raw(2).raw(), 2);
        assert_eq!(ElfNoteType::from_raw(11).raw(), 11);
        assert_eq!(ElfNoteType::from_raw(3).raw(), 3);
        assert_eq!(ElfNoteType::from_raw(10).raw(), 10);
        assert_eq!(ElfNoteType::from_raw(12).raw(), 12);
        assert_eq!(ElfNoteType::from_raw(4).raw(), 4);
        assert_eq!(ElfNoteType::from_raw(1038).raw(), 1038);
        assert_eq!(ElfNoteType::from_raw(1040).raw(), 1040);
        assert_eq!(ElfNoteType::from_raw(1026).raw(), 1026);
        assert_eq!(ElfNoteType::from_raw(1027).raw(), 1027);
        assert_eq!(ElfNoteType::from_raw(1030).raw(), 1030);
        assert_eq!(ElfNoteType::from_raw(1035).raw(), 1035);
        assert_eq!(ElfNoteType::from_raw(1029).raw(), 1029);
        assert_eq!(ElfNoteType::from_raw(1033).raw(), 1033);
        assert_eq!(ElfNoteType::from_raw(1025).raw(), 1025);
        assert_eq!(ElfNoteType::from_raw(1024).raw(), 1024);
        assert_eq!(ElfNoteType::from_raw(1036).raw(), 1036);
        assert_eq!(ElfNoteType::from_raw(1037).raw(), 1037);
        assert_eq!(ElfNoteType::from_raw(6).raw(), 6);
        assert_eq!(ElfNoteType::from_raw(0x4649_4c45).raw(), 0x4649_4c45);
        assert_eq!(ElfNoteType::from_raw(16).raw(), 16);
        assert_eq!(ElfNoteType::from_raw(8).raw(), 8);
        assert_eq!(ElfNoteType::from_raw(9).raw(), 9);
        assert_eq!(ElfNoteType::from_raw(14).raw(), 14);
        assert_eq!(ElfNoteType::from_raw(15).raw(), 15);
        assert_eq!(ElfNoteType::from_raw(13).raw(), 13);
        assert_eq!(ElfNoteType::from_raw(7).raw(), 7);
        assert_eq!(ElfNoteType::from_raw(257).raw(), 257);
        assert_eq!(ElfNoteType::from_raw(256).raw(), 256);
        assert_eq!(ElfNoteType::from_raw(5).raw(), 5);
        assert_eq!(ElfNoteType::from_raw(17).raw(), 17);
        assert_eq!(ElfNoteType::from_raw(0).raw(), 0);
        assert_eq!(ElfNoteType::from_raw(24).raw(), 24);
        assert_eq!(ElfNoteType::from_raw(21).raw(), 21);
        assert_eq!(ElfNoteType::from_raw(20).raw(), 20);
        assert_eq!(ElfNoteType::from_raw(23).raw(), 23);
        assert_eq!(ElfNoteType::from_raw(22).raw(), 22);
        assert_eq!(ElfNoteType::from_raw(261).raw(), 261);
        assert_eq!(ElfNoteType::from_raw(262).raw(), 262);
        assert_eq!(ElfNoteType::from_raw(263).raw(), 263);
        assert_eq!(ElfNoteType::from_raw(260).raw(), 260);
        assert_eq!(ElfNoteType::from_raw(259).raw(), 259);
        assert_eq!(ElfNoteType::from_raw(271).raw(), 271);
        assert_eq!(ElfNoteType::from_raw(265).raw(), 265);
        assert_eq!(ElfNoteType::from_raw(264).raw(), 264);
        assert_eq!(ElfNoteType::from_raw(270).raw(), 270);
        assert_eq!(ElfNoteType::from_raw(269).raw(), 269);
        assert_eq!(ElfNoteType::from_raw(266).raw(), 266);
        assert_eq!(ElfNoteType::from_raw(267).raw(), 267);
        assert_eq!(ElfNoteType::from_raw(268).raw(), 268);
        assert_eq!(ElfNoteType::from_raw(258).raw(), 258);
        assert_eq!(ElfNoteType::from_raw(0x46e6_2b7f).raw(), 0x46e6_2b7f);
        assert_eq!(ElfNoteType::from_raw(772).raw(), 772);
        assert_eq!(ElfNoteType::from_raw(780).raw(), 780);
        assert_eq!(ElfNoteType::from_raw(779).raw(), 779);
        assert_eq!(ElfNoteType::from_raw(768).raw(), 768);
        assert_eq!(ElfNoteType::from_raw(774).raw(), 774);
        assert_eq!(ElfNoteType::from_raw(773).raw(), 773);
        assert_eq!(ElfNoteType::from_raw(775).raw(), 775);
        assert_eq!(ElfNoteType::from_raw(776).raw(), 776);
        assert_eq!(ElfNoteType::from_raw(769).raw(), 769);
        assert_eq!(ElfNoteType::from_raw(770).raw(), 770);
        assert_eq!(ElfNoteType::from_raw(771).raw(), 771);
        assert_eq!(ElfNoteType::from_raw(778).raw(), 778);
        assert_eq!(ElfNoteType::from_raw(777).raw(), 777);
        assert_eq!(ElfNoteType::from_raw(0x5349_4749).raw(), 0x5349_4749);
        assert_eq!(ElfNoteType::from_raw(18).raw(), 18);
        assert_eq!(ElfNoteType::from_raw(514).raw(), 514);
        assert_eq!(ElfNoteType::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfAarch64PauthPlatform>::default().raw(), 0);
        assert_eq!(ElfAarch64PauthPlatform::Baremetal.raw(), 1);
        assert_eq!(ElfAarch64PauthPlatform::Invalid.raw(), 0);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinux.raw(), 0x1000_0002);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionAuthtraps.raw(), 3);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionCalls.raw(), 1);
        assert_eq!(
            ElfAarch64PauthPlatform::LlvmLinuxVersionFptrtypediscr.raw(),
            11
        );
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionGot.raw(), 8);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionGotos.raw(), 9);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionInitfini.raw(), 6);
        assert_eq!(
            ElfAarch64PauthPlatform::LlvmLinuxVersionInitfiniaddrdisc.raw(),
            7
        );
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionIntrinsics.raw(), 0);
        assert_eq!(ElfAarch64PauthPlatform::LlvmLinuxVersionReturns.raw(), 2);
        assert_eq!(
            ElfAarch64PauthPlatform::LlvmLinuxVersionTypeinfovptrdiscr.raw(),
            10
        );
        assert_eq!(
            ElfAarch64PauthPlatform::LlvmLinuxVersionVptraddrdiscr.raw(),
            4
        );
        assert_eq!(
            ElfAarch64PauthPlatform::LlvmLinuxVersionVptrtypediscr.raw(),
            5
        );
        assert_eq!(ElfAarch64PauthPlatform::from_raw(1).raw(), 1);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(0).raw(), 0);
        assert_eq!(
            ElfAarch64PauthPlatform::from_raw(0x1000_0002).raw(),
            0x1000_0002
        );
        assert_eq!(ElfAarch64PauthPlatform::from_raw(3).raw(), 3);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(11).raw(), 11);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(8).raw(), 8);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(9).raw(), 9);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(6).raw(), 6);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(7).raw(), 7);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(2).raw(), 2);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(10).raw(), 10);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(4).raw(), 4);
        assert_eq!(ElfAarch64PauthPlatform::from_raw(5).raw(), 5);
        assert_eq!(
            ElfAarch64PauthPlatform::from_raw(0xffff_fffe).raw(),
            0xffff_fffe
        );
        assert_eq!(<ElfCompressionType>::default().raw(), 0);
        assert_eq!(ElfCompressionType::Hios.raw(), 0x6fff_ffff);
        assert_eq!(ElfCompressionType::Hiproc.raw(), 0x7fff_ffff);
        assert_eq!(ElfCompressionType::Loos.raw(), 0x6000_0000);
        assert_eq!(ElfCompressionType::Loproc.raw(), 0x7000_0000);
        assert_eq!(ElfCompressionType::Zlib.raw(), 1);
        assert_eq!(ElfCompressionType::Zstd.raw(), 2);
        assert_eq!(ElfCompressionType::from_raw(0x6fff_ffff).raw(), 0x6fff_ffff);
        assert_eq!(ElfCompressionType::from_raw(0x7fff_ffff).raw(), 0x7fff_ffff);
        assert_eq!(ElfCompressionType::from_raw(0x6000_0000).raw(), 0x6000_0000);
        assert_eq!(ElfCompressionType::from_raw(0x7000_0000).raw(), 0x7000_0000);
        assert_eq!(ElfCompressionType::from_raw(1).raw(), 1);
        assert_eq!(ElfCompressionType::from_raw(2).raw(), 2);
        assert_eq!(ElfCompressionType::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfGnuAbiTag>::default().raw(), 0);
        assert_eq!(ElfGnuAbiTag::Freebsd.raw(), 3);
        assert_eq!(ElfGnuAbiTag::Hurd.raw(), 1);
        assert_eq!(ElfGnuAbiTag::Linux.raw(), 0);
        assert_eq!(ElfGnuAbiTag::Nacl.raw(), 6);
        assert_eq!(ElfGnuAbiTag::Netbsd.raw(), 4);
        assert_eq!(ElfGnuAbiTag::Solaris.raw(), 2);
        assert_eq!(ElfGnuAbiTag::Syllable.raw(), 5);
        assert_eq!(ElfGnuAbiTag::from_raw(3).raw(), 3);
        assert_eq!(ElfGnuAbiTag::from_raw(1).raw(), 1);
        assert_eq!(ElfGnuAbiTag::from_raw(0).raw(), 0);
        assert_eq!(ElfGnuAbiTag::from_raw(6).raw(), 6);
        assert_eq!(ElfGnuAbiTag::from_raw(4).raw(), 4);
        assert_eq!(ElfGnuAbiTag::from_raw(2).raw(), 2);
        assert_eq!(ElfGnuAbiTag::from_raw(5).raw(), 5);
        assert_eq!(ElfGnuAbiTag::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfGnuProperty>::default().raw(), 0);
        assert_eq!(ElfGnuProperty::Aarch64Feature1And.raw(), 0xc000_0000);
        assert_eq!(ElfGnuProperty::Aarch64Feature1Bti.raw(), 1);
        assert_eq!(ElfGnuProperty::Aarch64Feature1Gcs.raw(), 4);
        assert_eq!(ElfGnuProperty::Aarch64Feature1Pac.raw(), 2);
        assert_eq!(ElfGnuProperty::Aarch64FeaturePauth.raw(), 0xc000_0001);
        assert_eq!(ElfGnuProperty::NoCopyOnProtected.raw(), 2);
        assert_eq!(ElfGnuProperty::StackSize.raw(), 1);
        assert_eq!(ElfGnuProperty::X86Feature1And.raw(), 0xc000_0002);
        assert_eq!(ElfGnuProperty::X86Feature1Ibt.raw(), 1);
        assert_eq!(ElfGnuProperty::X86Feature1Shstk.raw(), 2);
        assert_eq!(ElfGnuProperty::X86Feature2Fxsr.raw(), 64);
        assert_eq!(ElfGnuProperty::X86Feature2Mmx.raw(), 4);
        assert_eq!(ElfGnuProperty::X86Feature2Needed.raw(), 0xc000_8001);
        assert_eq!(ElfGnuProperty::X86Feature2Used.raw(), 0xc001_0001);
        assert_eq!(ElfGnuProperty::X86Feature2X86.raw(), 1);
        assert_eq!(ElfGnuProperty::X86Feature2X87.raw(), 2);
        assert_eq!(ElfGnuProperty::X86Feature2Xmm.raw(), 8);
        assert_eq!(ElfGnuProperty::X86Feature2Xsave.raw(), 128);
        assert_eq!(ElfGnuProperty::X86Feature2Xsavec.raw(), 512);
        assert_eq!(ElfGnuProperty::X86Feature2Xsaveopt.raw(), 256);
        assert_eq!(ElfGnuProperty::X86Feature2Ymm.raw(), 16);
        assert_eq!(ElfGnuProperty::X86Feature2Zmm.raw(), 32);
        assert_eq!(ElfGnuProperty::X86Isa1Baseline.raw(), 1);
        assert_eq!(ElfGnuProperty::X86Isa1Needed.raw(), 0xc000_8002);
        assert_eq!(ElfGnuProperty::X86Isa1Used.raw(), 0xc001_0002);
        assert_eq!(ElfGnuProperty::X86Isa1V2.raw(), 2);
        assert_eq!(ElfGnuProperty::X86Isa1V3.raw(), 4);
        assert_eq!(ElfGnuProperty::X86Isa1V4.raw(), 8);
        assert_eq!(ElfGnuProperty::X86Uint32OrAndLo.raw(), 0xc001_0000);
        assert_eq!(ElfGnuProperty::X86Uint32OrLo.raw(), 0xc000_8000);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_0000).raw(), 0xc000_0000);
        assert_eq!(ElfGnuProperty::from_raw(1).raw(), 1);
        assert_eq!(ElfGnuProperty::from_raw(4).raw(), 4);
        assert_eq!(ElfGnuProperty::from_raw(2).raw(), 2);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_0001).raw(), 0xc000_0001);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_0002).raw(), 0xc000_0002);
        assert_eq!(ElfGnuProperty::from_raw(64).raw(), 64);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_8001).raw(), 0xc000_8001);
        assert_eq!(ElfGnuProperty::from_raw(0xc001_0001).raw(), 0xc001_0001);
        assert_eq!(ElfGnuProperty::from_raw(8).raw(), 8);
        assert_eq!(ElfGnuProperty::from_raw(128).raw(), 128);
        assert_eq!(ElfGnuProperty::from_raw(512).raw(), 512);
        assert_eq!(ElfGnuProperty::from_raw(256).raw(), 256);
        assert_eq!(ElfGnuProperty::from_raw(16).raw(), 16);
        assert_eq!(ElfGnuProperty::from_raw(32).raw(), 32);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_8002).raw(), 0xc000_8002);
        assert_eq!(ElfGnuProperty::from_raw(0xc001_0002).raw(), 0xc001_0002);
        assert_eq!(ElfGnuProperty::from_raw(0xc001_0000).raw(), 0xc001_0000);
        assert_eq!(ElfGnuProperty::from_raw(0xc000_8000).raw(), 0xc000_8000);
        assert_eq!(ElfGnuProperty::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfVersionIndex>::default().raw(), 0);
        assert_eq!(ElfVersionIndex::Hidden.raw(), 0x8000);
        assert_eq!(ElfVersionIndex::Version.raw(), 0x7fff);
        assert_eq!(ElfVersionIndex::Global.raw(), 1);
        assert_eq!(ElfVersionIndex::Local.raw(), 0);
        assert_eq!(ElfVersionIndex::from_raw(0x8000).raw(), 0x8000);
        assert_eq!(ElfVersionIndex::from_raw(0x7fff).raw(), 0x7fff);
        assert_eq!(ElfVersionIndex::from_raw(1).raw(), 1);
        assert_eq!(ElfVersionIndex::from_raw(0).raw(), 0);
        assert_eq!(ElfVersionIndex::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfMipsOptionKind>::default().raw(), 0);
        assert_eq!(ElfMipsOptionKind::Exceptions.raw(), 2);
        assert_eq!(ElfMipsOptionKind::Fill.raw(), 5);
        assert_eq!(ElfMipsOptionKind::GpGroup.raw(), 9);
        assert_eq!(ElfMipsOptionKind::Hwand.raw(), 7);
        assert_eq!(ElfMipsOptionKind::Hwor.raw(), 8);
        assert_eq!(ElfMipsOptionKind::Hwpatch.raw(), 4);
        assert_eq!(ElfMipsOptionKind::Ident.raw(), 10);
        assert_eq!(ElfMipsOptionKind::Null.raw(), 0);
        assert_eq!(ElfMipsOptionKind::Pad.raw(), 3);
        assert_eq!(ElfMipsOptionKind::Pagesize.raw(), 11);
        assert_eq!(ElfMipsOptionKind::Reginfo.raw(), 1);
        assert_eq!(ElfMipsOptionKind::Tags.raw(), 6);
        assert_eq!(ElfMipsOptionKind::from_raw(2).raw(), 2);
        assert_eq!(ElfMipsOptionKind::from_raw(5).raw(), 5);
        assert_eq!(ElfMipsOptionKind::from_raw(9).raw(), 9);
        assert_eq!(ElfMipsOptionKind::from_raw(7).raw(), 7);
        assert_eq!(ElfMipsOptionKind::from_raw(8).raw(), 8);
        assert_eq!(ElfMipsOptionKind::from_raw(4).raw(), 4);
        assert_eq!(ElfMipsOptionKind::from_raw(10).raw(), 10);
        assert_eq!(ElfMipsOptionKind::from_raw(0).raw(), 0);
        assert_eq!(ElfMipsOptionKind::from_raw(3).raw(), 3);
        assert_eq!(ElfMipsOptionKind::from_raw(11).raw(), 11);
        assert_eq!(ElfMipsOptionKind::from_raw(1).raw(), 1);
        assert_eq!(ElfMipsOptionKind::from_raw(6).raw(), 6);
        assert_eq!(ElfMipsOptionKind::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfMipsRuntimeSymbol>::default().raw(), 0);
        assert_eq!(ElfMipsRuntimeSymbol::Gp.raw(), 1);
        assert_eq!(ElfMipsRuntimeSymbol::Gp0.raw(), 2);
        assert_eq!(ElfMipsRuntimeSymbol::Loc.raw(), 3);
        assert_eq!(ElfMipsRuntimeSymbol::Undef.raw(), 0);
        assert_eq!(ElfMipsRuntimeSymbol::from_raw(1).raw(), 1);
        assert_eq!(ElfMipsRuntimeSymbol::from_raw(2).raw(), 2);
        assert_eq!(ElfMipsRuntimeSymbol::from_raw(3).raw(), 3);
        assert_eq!(ElfMipsRuntimeSymbol::from_raw(0).raw(), 0);
        assert_eq!(
            ElfMipsRuntimeSymbol::from_raw(0xffff_fffe).raw(),
            0xffff_fffe
        );
        assert_eq!(<ElfSymbolEntrySize>::default().raw(), 0);
        assert_eq!(ElfSymbolEntrySize::X32.raw(), 16);
        assert_eq!(ElfSymbolEntrySize::X64.raw(), 24);
        assert_eq!(ElfSymbolEntrySize::from_raw(16).raw(), 16);
        assert_eq!(ElfSymbolEntrySize::from_raw(24).raw(), 24);
        assert_eq!(ElfSymbolEntrySize::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfFdoNote>::default().raw(), 0);
        assert_eq!(ElfFdoNote::PackagingMetadata.raw(), 0xcafe_1a7e);
        assert_eq!(ElfFdoNote::from_raw(0xcafe_1a7e).raw(), 0xcafe_1a7e);
        assert_eq!(ElfFdoNote::from_raw(0xffff_fffe).raw(), 0xffff_fffe);
        assert_eq!(<ElfSegmentFlags>::default().raw(), 0);
        assert_eq!(ElfSegmentFlags::PF_MASKOS.raw(), 0xff0_0000);
        assert_eq!(ElfSegmentFlags::PF_MASKPROC.raw(), 0xf000_0000);
        assert_eq!(ElfSegmentFlags::PF_R.raw(), 4);
        assert_eq!(ElfSegmentFlags::PF_W.raw(), 2);
        assert_eq!(ElfSegmentFlags::PF_X.raw(), 1);
        assert_eq!(ElfSegmentFlags::from_raw(0xaaaa_5555).raw(), 0xaaaa_5555);
        assert_eq!(<ElfSectionFlags>::default().raw(), 0);
        assert_eq!(ElfSectionFlags::SHF_ALLOC.raw(), 2);
        assert_eq!(ElfSectionFlags::SHF_ARM_PURECODE.raw(), 0x2000_0000);
        assert_eq!(ElfSectionFlags::SHF_COMPRESSED.raw(), 2048);
        assert_eq!(ElfSectionFlags::SHF_EXCLUDE.raw(), 0x8000_0000);
        assert_eq!(ElfSectionFlags::SHF_EXECINSTR.raw(), 4);
        assert_eq!(ElfSectionFlags::SHF_GNU_RETAIN.raw(), 0x20_0000);
        assert_eq!(ElfSectionFlags::SHF_GROUP.raw(), 512);
        assert_eq!(ElfSectionFlags::SHF_HEX_GPREL.raw(), 0x1000_0000);
        assert_eq!(ElfSectionFlags::SHF_INFO_LINK.raw(), 64);
        assert_eq!(ElfSectionFlags::SHF_LINK_ORDER.raw(), 128);
        assert_eq!(ElfSectionFlags::SHF_MASKOS.raw(), 0xff0_0000);
        assert_eq!(ElfSectionFlags::SHF_MASKPROC.raw(), 0xf000_0000);
        assert_eq!(ElfSectionFlags::SHF_MERGE.raw(), 16);
        assert_eq!(ElfSectionFlags::SHF_MIPS_ADDR.raw(), 0x4000_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_GPREL.raw(), 0x1000_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_LOCAL.raw(), 0x400_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_MERGE.raw(), 0x2000_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_NAMES.raw(), 0x200_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_NODUPES.raw(), 0x100_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_NOSTRIP.raw(), 0x800_0000);
        assert_eq!(ElfSectionFlags::SHF_MIPS_STRING.raw(), 0x8000_0000);
        assert_eq!(ElfSectionFlags::SHF_OS_NONCONFORMING.raw(), 256);
        assert_eq!(ElfSectionFlags::SHF_STRINGS.raw(), 32);
        assert_eq!(ElfSectionFlags::SHF_SUNW_NODISCARD.raw(), 0x10_0000);
        assert_eq!(ElfSectionFlags::SHF_TLS.raw(), 1024);
        assert_eq!(ElfSectionFlags::SHF_WRITE.raw(), 1);
        assert_eq!(ElfSectionFlags::SHF_X86_64_LARGE.raw(), 0x1000_0000);
        assert_eq!(ElfSectionFlags::XCORE_SHF_CP_SECTION.raw(), 0x2000_0000);
        assert_eq!(ElfSectionFlags::XCORE_SHF_DP_SECTION.raw(), 0x1000_0000);
        assert_eq!(
            ElfSectionFlags::from_raw(0xaaaa_5555_aaaa_5555).raw(),
            0xaaaa_5555_aaaa_5555
        );
        assert_eq!(<ElfDynamicFlags>::default().raw(), 0);
        assert_eq!(ElfDynamicFlags::DF_1_CONFALT.raw(), 8192);
        assert_eq!(ElfDynamicFlags::DF_1_DIRECT.raw(), 256);
        assert_eq!(ElfDynamicFlags::DF_1_DISPRELDNE.raw(), 0x8000);
        assert_eq!(ElfDynamicFlags::DF_1_DISPRELPND.raw(), 0x1_0000);
        assert_eq!(ElfDynamicFlags::DF_1_EDITED.raw(), 0x20_0000);
        assert_eq!(ElfDynamicFlags::DF_1_ENDFILTEE.raw(), 0x4000);
        assert_eq!(ElfDynamicFlags::DF_1_GLOBAL.raw(), 2);
        assert_eq!(ElfDynamicFlags::DF_1_GLOBAUDIT.raw(), 0x100_0000);
        assert_eq!(ElfDynamicFlags::DF_1_GROUP.raw(), 4);
        assert_eq!(ElfDynamicFlags::DF_1_IGNMULDEF.raw(), 0x4_0000);
        assert_eq!(ElfDynamicFlags::DF_1_INITFIRST.raw(), 32);
        assert_eq!(ElfDynamicFlags::DF_1_INTERPOSE.raw(), 1024);
        assert_eq!(ElfDynamicFlags::DF_1_LOADFLTR.raw(), 16);
        assert_eq!(ElfDynamicFlags::DF_1_NODEFLIB.raw(), 2048);
        assert_eq!(ElfDynamicFlags::DF_1_NODELETE.raw(), 8);
        assert_eq!(ElfDynamicFlags::DF_1_NODIRECT.raw(), 0x2_0000);
        assert_eq!(ElfDynamicFlags::DF_1_NODUMP.raw(), 4096);
        assert_eq!(ElfDynamicFlags::DF_1_NOHDR.raw(), 0x10_0000);
        assert_eq!(ElfDynamicFlags::DF_1_NOKSYMS.raw(), 0x8_0000);
        assert_eq!(ElfDynamicFlags::DF_1_NOOPEN.raw(), 64);
        assert_eq!(ElfDynamicFlags::DF_1_NORELOC.raw(), 0x40_0000);
        assert_eq!(ElfDynamicFlags::DF_1_NOW.raw(), 1);
        assert_eq!(ElfDynamicFlags::DF_1_ORIGIN.raw(), 128);
        assert_eq!(ElfDynamicFlags::DF_1_PIE.raw(), 0x800_0000);
        assert_eq!(ElfDynamicFlags::DF_1_SINGLETON.raw(), 0x200_0000);
        assert_eq!(ElfDynamicFlags::DF_1_SYMINTPOSE.raw(), 0x80_0000);
        assert_eq!(ElfDynamicFlags::DF_1_TRANS.raw(), 512);
        assert_eq!(ElfDynamicFlags::DF_BIND_NOW.raw(), 8);
        assert_eq!(ElfDynamicFlags::DF_ORIGIN.raw(), 1);
        assert_eq!(ElfDynamicFlags::DF_STATIC_TLS.raw(), 16);
        assert_eq!(ElfDynamicFlags::DF_SYMBOLIC.raw(), 2);
        assert_eq!(ElfDynamicFlags::DF_TEXTREL.raw(), 4);
        assert_eq!(
            ElfDynamicFlags::from_raw(0xaaaa_5555_aaaa_5555).raw(),
            0xaaaa_5555_aaaa_5555
        );
        assert_eq!(ElfDynamicFlags::from(0x5555_aaaa_u64).raw(), 0x5555_aaaa);
        assert_eq!(<ElfGroupFlags>::default().raw(), 0);
        assert_eq!(ElfGroupFlags::GRP_COMDAT.raw(), 1);
        assert_eq!(ElfGroupFlags::GRP_MASKOS.raw(), 0xff0_0000);
        assert_eq!(ElfGroupFlags::GRP_MASKPROC.raw(), 0xf000_0000);
        assert_eq!(ElfGroupFlags::from_raw(0xaaaa_5555).raw(), 0xaaaa_5555);
        assert_eq!(ElfGroupFlags::from(0x5555_aaaa_u32).raw(), 0x5555_aaaa);
        assert_eq!(<ElfRelocationGroupFlags>::default().raw(), 0);
        assert_eq!(
            ElfRelocationGroupFlags::RELOCATION_GROUP_HAS_ADDEND_FLAG.raw(),
            8
        );
        assert_eq!(
            ElfRelocationGroupFlags::from_raw(0xaaaa_5555).raw(),
            0xaaaa_5555
        );
        assert_eq!(
            ElfRelocationGroupFlags::from(0x5555_aaaa_u32).raw(),
            0x5555_aaaa
        );
        assert_eq!(<ElfHeaderFlags>::default().raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_ANY_V4.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_OFF_V4.raw(), 2048);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_ON_V4.raw(), 3072);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_UNSUPPORTED_V4.raw(),
            0
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_V3.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_SRAMECC_V4.raw(), 3072);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_TRAP_HANDLER_V2.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_ANY_V4.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_OFF_V4.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_ON_V4.raw(), 768);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_UNSUPPORTED_V4.raw(),
            0
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_V2.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_V3.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_FEATURE_XNACK_V4.raw(), 768);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_GENERIC_VERSION.raw(), 0xff00_0000);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_GENERIC_VERSION_MAX.raw(), 255);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_GENERIC_VERSION_MIN.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_GENERIC_VERSION_OFFSET.raw(), 24);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH.raw(), 255);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_FIRST.raw(), 32);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1010.raw(), 51);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1011.raw(), 52);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1012.raw(), 53);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1013.raw(), 66);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1030.raw(), 54);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1031.raw(), 55);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1032.raw(), 56);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1033.raw(), 57);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1034.raw(), 62);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1035.raw(), 61);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1036.raw(), 69);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX10_1_GENERIC.raw(),
            82
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX10_3_GENERIC.raw(),
            83
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1100.raw(), 65);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1101.raw(), 70);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1102.raw(), 71);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1103.raw(), 68);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1150.raw(), 67);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1151.raw(), 74);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1152.raw(), 85);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1153.raw(), 88);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX11_GENERIC.raw(),
            84
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1200.raw(), 72);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX1201.raw(), 78);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX12_GENERIC.raw(),
            89
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX600.raw(), 32);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX601.raw(), 33);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX602.raw(), 58);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX700.raw(), 34);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX701.raw(), 35);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX702.raw(), 36);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX703.raw(), 37);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX704.raw(), 38);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX705.raw(), 59);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX801.raw(), 40);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX802.raw(), 41);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX803.raw(), 42);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX805.raw(), 60);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX810.raw(), 43);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX900.raw(), 44);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX902.raw(), 45);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX904.raw(), 46);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX906.raw(), 47);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX908.raw(), 48);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX909.raw(), 49);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX90A.raw(), 63);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX90C.raw(), 50);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX940.raw(), 64);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX941.raw(), 75);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX942.raw(), 76);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX950.raw(), 79);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX9_4_GENERIC.raw(),
            95
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_GFX9_GENERIC.raw(), 81);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_LAST.raw(), 95);
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X27.raw(),
            39
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X49.raw(),
            73
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X4D.raw(),
            77
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X50.raw(),
            80
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X56.raw(),
            86
        );
        assert_eq!(
            ElfHeaderFlags::EF_AMDGPU_MACH_AMDGCN_RESERVED_0X57.raw(),
            87
        );
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_NONE.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_BARTS.raw(), 13);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_CAICOS.raw(), 14);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_CAYMAN.raw(), 15);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_CEDAR.raw(), 8);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_CYPRESS.raw(), 9);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_FIRST.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_JUNIPER.raw(), 10);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_LAST.raw(), 16);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_R600.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_R630.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_REDWOOD.raw(), 11);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RESERVED_FIRST.raw(), 17);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RESERVED_LAST.raw(), 31);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RS880.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RV670.raw(), 4);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RV710.raw(), 5);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RV730.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_RV770.raw(), 7);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_SUMO.raw(), 12);
        assert_eq!(ElfHeaderFlags::EF_AMDGPU_MACH_R600_TURKS.raw(), 16);
        assert_eq!(ElfHeaderFlags::EF_ARC_CPU_ARCV2EM.raw(), 5);
        assert_eq!(ElfHeaderFlags::EF_ARC_CPU_ARCV2HS.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_ARC_MACH_MSK.raw(), 255);
        assert_eq!(ElfHeaderFlags::EF_ARC_OSABI_MSK.raw(), 3840);
        assert_eq!(ElfHeaderFlags::EF_ARC_PIC.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_ARM_ABI_FLOAT_HARD.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_ARM_ABI_FLOAT_SOFT.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_ARM_BE8.raw(), 0x80_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABIMASK.raw(), 0xff00_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_UNKNOWN.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_VER1.raw(), 0x100_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_VER2.raw(), 0x200_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_VER3.raw(), 0x300_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_VER4.raw(), 0x400_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_EABI_VER5.raw(), 0x500_0000);
        assert_eq!(ElfHeaderFlags::EF_ARM_SOFT_FLOAT.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_ARM_VFP_FLOAT.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR1.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR2.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR25.raw(), 25);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR3.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR31.raw(), 31);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR35.raw(), 35);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR4.raw(), 4);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR5.raw(), 5);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR51.raw(), 51);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVR6.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_AVRTINY.raw(), 100);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_MASK.raw(), 127);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA1.raw(), 101);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA2.raw(), 102);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA3.raw(), 103);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA4.raw(), 104);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA5.raw(), 105);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA6.raw(), 106);
        assert_eq!(ElfHeaderFlags::EF_AVR_ARCH_XMEGA7.raw(), 107);
        assert_eq!(ElfHeaderFlags::EF_AVR_LINKRELAX_PREPARED.raw(), 128);
        assert_eq!(ElfHeaderFlags::EF_CSKY_800.raw(), 31);
        assert_eq!(ElfHeaderFlags::EF_CSKY_801.raw(), 10);
        assert_eq!(ElfHeaderFlags::EF_CSKY_802.raw(), 16);
        assert_eq!(ElfHeaderFlags::EF_CSKY_803.raw(), 9);
        assert_eq!(ElfHeaderFlags::EF_CSKY_805.raw(), 17);
        assert_eq!(ElfHeaderFlags::EF_CSKY_807.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_CSKY_810.raw(), 8);
        assert_eq!(ElfHeaderFlags::EF_CSKY_860.raw(), 11);
        assert_eq!(ElfHeaderFlags::EF_CSKY_ABIV2.raw(), 0x2000_0000);
        assert_eq!(ElfHeaderFlags::EF_CSKY_DSP.raw(), 0x4000);
        assert_eq!(ElfHeaderFlags::EF_CSKY_EFV1.raw(), 0x100_0000);
        assert_eq!(ElfHeaderFlags::EF_CSKY_EFV2.raw(), 0x200_0000);
        assert_eq!(ElfHeaderFlags::EF_CSKY_EFV3.raw(), 0x300_0000);
        assert_eq!(ElfHeaderFlags::EF_CSKY_FLOAT.raw(), 8192);
        assert_eq!(ElfHeaderFlags::EF_CUDA_64BIT_ADDRESS.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_CUDA_ACCELERATORS.raw(), 2048);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM.raw(), 255);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM20.raw(), 20);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM21.raw(), 21);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM30.raw(), 30);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM32.raw(), 32);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM35.raw(), 35);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM37.raw(), 37);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM50.raw(), 50);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM52.raw(), 52);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM53.raw(), 53);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM60.raw(), 60);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM61.raw(), 61);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM62.raw(), 62);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM70.raw(), 70);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM72.raw(), 72);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM75.raw(), 75);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM80.raw(), 80);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM86.raw(), 86);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM87.raw(), 87);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM89.raw(), 89);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SM90.raw(), 90);
        assert_eq!(ElfHeaderFlags::EF_CUDA_SW_FLAG_V2.raw(), 4096);
        assert_eq!(ElfHeaderFlags::EF_CUDA_TEXMODE_INDEPENDANT.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_CUDA_TEXMODE_UNIFIED.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_CUDA_VIRTUAL_SM.raw(), 0xff_0000);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA.raw(), 1023);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_MACH.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V2.raw(), 16);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V3.raw(), 32);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V4.raw(), 48);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V5.raw(), 64);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V55.raw(), 80);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V60.raw(), 96);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V61.raw(), 97);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V62.raw(), 98);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V65.raw(), 101);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V66.raw(), 102);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V67.raw(), 103);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V68.raw(), 104);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V69.raw(), 105);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V71.raw(), 113);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V73.raw(), 115);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V75.raw(), 117);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V77.raw(), 119);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V79.raw(), 121);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V81.raw(), 129);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V83.raw(), 131);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_ISA_V85.raw(), 133);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH.raw(), 1023);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V2.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V3.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V4.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V5.raw(), 4);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V55.raw(), 5);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V60.raw(), 96);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V61.raw(), 97);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V62.raw(), 98);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V65.raw(), 101);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V66.raw(), 102);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V67.raw(), 103);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V67T.raw(), 0x8067);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V68.raw(), 104);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V69.raw(), 105);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V71.raw(), 113);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V71T.raw(), 0x8071);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V73.raw(), 115);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V75.raw(), 117);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V77.raw(), 119);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V79.raw(), 121);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V81.raw(), 129);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V83.raw(), 131);
        assert_eq!(ElfHeaderFlags::EF_HEXAGON_MACH_V85.raw(), 133);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_ABI_DOUBLE_FLOAT.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_ABI_MODIFIER_MASK.raw(), 7);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_ABI_SINGLE_FLOAT.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_ABI_SOFT_FLOAT.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_OBJABI_MASK.raw(), 192);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_OBJABI_V0.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_LOONGARCH_OBJABI_V1.raw(), 64);
        assert_eq!(ElfHeaderFlags::EF_MIPS_32BITMODE.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI.raw(), 0xf000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI2.raw(), 32);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI_EABI32.raw(), 0x3000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI_EABI64.raw(), 0x4000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI_O32.raw(), 4096);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ABI_O64.raw(), 8192);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH.raw(), 0xf000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_1.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_2.raw(), 0x1000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_3.raw(), 0x2000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_32.raw(), 0x5000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_32R2.raw(), 0x7000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_32R6.raw(), 0x9000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_4.raw(), 0x3000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_5.raw(), 0x4000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_64.raw(), 0x6000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_64R2.raw(), 0x8000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_64R6.raw(), 0xa000_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_ASE.raw(), 0xf00_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_ASE_M16.raw(), 0x400_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_ARCH_ASE_MDMX.raw(), 0x800_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_CPIC.raw(), 4);
        assert_eq!(ElfHeaderFlags::EF_MIPS_FP64.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH.raw(), 0xff_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_3900.raw(), 0x81_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_4010.raw(), 0x82_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_4100.raw(), 0x83_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_4111.raw(), 0x88_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_4120.raw(), 0x87_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_4650.raw(), 0x85_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_5400.raw(), 0x91_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_5500.raw(), 0x98_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_5900.raw(), 0x92_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_9000.raw(), 0x99_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_LS2E.raw(), 0xa0_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_LS2F.raw(), 0xa1_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_LS3A.raw(), 0xa2_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_NONE.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_OCTEON.raw(), 0x8b_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_OCTEON2.raw(), 0x8d_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_OCTEON3.raw(), 0x8e_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_SB1.raw(), 0x8a_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MACH_XLR.raw(), 0x8c_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_MICROMIPS.raw(), 0x200_0000);
        assert_eq!(ElfHeaderFlags::EF_MIPS_NAN2008.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_MIPS_NOREORDER.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_MIPS_PIC.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_MSP430_MACH_MSP430X.raw(), 45);
        assert_eq!(ElfHeaderFlags::EF_PPC64_ABI.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_RISCV_FLOAT_ABI.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_RISCV_FLOAT_ABI_DOUBLE.raw(), 4);
        assert_eq!(ElfHeaderFlags::EF_RISCV_FLOAT_ABI_QUAD.raw(), 6);
        assert_eq!(ElfHeaderFlags::EF_RISCV_FLOAT_ABI_SINGLE.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_RISCV_FLOAT_ABI_SOFT.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_RISCV_RVC.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_RISCV_RVE.raw(), 8);
        assert_eq!(ElfHeaderFlags::EF_RISCV_TSO.raw(), 16);
        assert_eq!(ElfHeaderFlags::EF_SPARCV9_MM.raw(), 3);
        assert_eq!(ElfHeaderFlags::EF_SPARCV9_PSO.raw(), 1);
        assert_eq!(ElfHeaderFlags::EF_SPARCV9_RMO.raw(), 2);
        assert_eq!(ElfHeaderFlags::EF_SPARCV9_TSO.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_SPARC_32PLUS.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_SPARC_EXT_MASK.raw(), 0xff_ff00);
        assert_eq!(ElfHeaderFlags::EF_SPARC_HAL_R1.raw(), 1024);
        assert_eq!(ElfHeaderFlags::EF_SPARC_SUN_US1.raw(), 512);
        assert_eq!(ElfHeaderFlags::EF_SPARC_SUN_US3.raw(), 2048);
        assert_eq!(ElfHeaderFlags::EF_XTENSA_MACH.raw(), 15);
        assert_eq!(ElfHeaderFlags::EF_XTENSA_MACH_NONE.raw(), 0);
        assert_eq!(ElfHeaderFlags::EF_XTENSA_XT_INSN.raw(), 256);
        assert_eq!(ElfHeaderFlags::EF_XTENSA_XT_LIT.raw(), 512);
        assert_eq!(ElfHeaderFlags::E_ARC_MACH_ARC600.raw(), 2);
        assert_eq!(ElfHeaderFlags::E_ARC_MACH_ARC601.raw(), 4);
        assert_eq!(ElfHeaderFlags::E_ARC_MACH_ARC700.raw(), 3);
        assert_eq!(ElfHeaderFlags::E_ARC_OSABI_ORIG.raw(), 0);
        assert_eq!(ElfHeaderFlags::E_ARC_OSABI_V2.raw(), 512);
        assert_eq!(ElfHeaderFlags::E_ARC_OSABI_V3.raw(), 768);
        assert_eq!(ElfHeaderFlags::E_ARC_OSABI_V4.raw(), 1024);
        assert_eq!(
            ElfHeaderFlags::from_raw(0xaaaa_5555_aaaa_5555).raw(),
            0xaaaa_5555_aaaa_5555
        );
        assert_eq!(ElfHeaderFlags::from(0x5555_aaaa_u64).raw(), 0x5555_aaaa);
        assert_eq!(<ElfMipsRuntimeFlags>::default().raw(), 0);
        assert_eq!(ElfMipsRuntimeFlags::RHF_CORD.raw(), 4096);
        assert_eq!(ElfMipsRuntimeFlags::RHF_DEFAULT_DELAY_LOAD.raw(), 512);
        assert_eq!(ElfMipsRuntimeFlags::RHF_DELTA_C_PLUS_PLUS.raw(), 64);
        assert_eq!(ElfMipsRuntimeFlags::RHF_GUARANTEE_INIT.raw(), 32);
        assert_eq!(ElfMipsRuntimeFlags::RHF_GUARANTEE_START_INIT.raw(), 128);
        assert_eq!(ElfMipsRuntimeFlags::RHF_NONE.raw(), 0);
        assert_eq!(ElfMipsRuntimeFlags::RHF_NOTPOT.raw(), 2);
        assert_eq!(ElfMipsRuntimeFlags::RHF_NO_MOVE.raw(), 8);
        assert_eq!(ElfMipsRuntimeFlags::RHF_NO_UNRES_UNDEF.raw(), 8192);
        assert_eq!(ElfMipsRuntimeFlags::RHF_PIXIE.raw(), 256);
        assert_eq!(ElfMipsRuntimeFlags::RHF_QUICKSTART.raw(), 1);
        assert_eq!(ElfMipsRuntimeFlags::RHF_REQUICKSTART.raw(), 1024);
        assert_eq!(ElfMipsRuntimeFlags::RHF_REQUICKSTARTED.raw(), 2048);
        assert_eq!(ElfMipsRuntimeFlags::RHF_RLD_ORDER_SAFE.raw(), 0x4000);
        assert_eq!(ElfMipsRuntimeFlags::RHF_SGI_ONLY.raw(), 16);
        assert_eq!(ElfMipsRuntimeFlags::RHS_NO_LIBRARY_REPLACEMENT.raw(), 4);
        assert_eq!(
            ElfMipsRuntimeFlags::from_raw(0xaaaa_5555_aaaa_5555).raw(),
            0xaaaa_5555_aaaa_5555
        );
        assert_eq!(
            ElfMipsRuntimeFlags::from(0x5555_aaaa_u64).raw(),
            0x5555_aaaa
        );
        assert_eq!(<ElfSymbolOtherFlags>::default().raw(), 0);
        assert_eq!(ElfSymbolOtherFlags::STO_AARCH64_VARIANT_PCS.raw(), 128);
        assert_eq!(ElfSymbolOtherFlags::STO_MIPS_MICROMIPS.raw(), 128);
        assert_eq!(ElfSymbolOtherFlags::STO_MIPS_MIPS16.raw(), 240);
        assert_eq!(ElfSymbolOtherFlags::STO_MIPS_OPTIONAL.raw(), 4);
        assert_eq!(ElfSymbolOtherFlags::STO_MIPS_PIC.raw(), 32);
        assert_eq!(ElfSymbolOtherFlags::STO_MIPS_PLT.raw(), 8);
        assert_eq!(ElfSymbolOtherFlags::STO_PPC64_LOCAL_BIT.raw(), 5);
        assert_eq!(ElfSymbolOtherFlags::STO_PPC64_LOCAL_MASK.raw(), 224);
        assert_eq!(ElfSymbolOtherFlags::STO_RISCV_VARIANT_CC.raw(), 128);
        assert_eq!(
            ElfSymbolOtherFlags::from_raw(0xaaaa_5555_aaaa_5555).raw(),
            0xaaaa_5555_aaaa_5555
        );
        assert_eq!(
            ElfSymbolOtherFlags::from(0x5555_aaaa_u64).raw(),
            0x5555_aaaa
        );
    }

    #[test]
    fn truncated_inputs_cover_private_read_boundaries() {
        let hello = hello_bytes();
        assert_all_truncated_prefixes_fail(&hello);

        let program_tables = program_dynamic_and_note_elf64();
        assert_all_truncated_prefixes_fail(&program_tables);

        let samples = samples::structural_samples().unwrap();
        for (name, module) in samples {
            if matches!(name.as_str(), "x86_64" | "aarch64_be" | "i386" | "powerpc") {
                let bytes = write(&module).unwrap();
                assert_all_truncated_prefixes_fail(&bytes);
            }
        }
    }

    #[test]
    fn mutated_inputs_cover_private_error_boundaries() {
        let mut fixtures = Vec::new();
        fixtures.push(hello_bytes());
        fixtures.push(program_dynamic_and_note_elf64());
        let samples = samples::structural_samples().unwrap();
        for (name, module) in samples {
            if matches!(name.as_str(), "x86_64" | "aarch64_be" | "i386" | "powerpc") {
                fixtures.push(write(&module).unwrap());
            }
        }

        for bytes in fixtures {
            for offset in 0..bytes.len() {
                for value in [0_u8, 0xff] {
                    let original = *bytes.get(offset).unwrap();
                    if original == value {
                        continue;
                    }
                    let mut mutated = bytes.clone();
                    *mutated.get_mut(offset).unwrap() = value;
                    let _ = ElfFile::parse(&mutated).and_then(|file| file.to_oir());
                }
            }
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture exercises native ELF32 and edge helper coverage"
    )]
    fn native_edge_paths_are_covered() {
        let elf32 = minimal_elf32(ElfMachine::Other(0xffff));
        let parsed = ElfFile::parse(&elf32).unwrap();
        assert_eq!(parsed.ident.class, PtrWidth::W32);
        assert_eq!(parsed.header.machine, ElfMachine::from_raw(0xffff));
        assert_eq!(
            parsed.to_oir().unwrap().target().arch,
            Architecture::Other(0xffff)
        );

        let mut bad_version = elf32.clone();
        patch(&mut bad_version, 20, &2_u32.to_le_bytes());
        assert!(ElfFile::parse(&bad_version).is_err());

        let mut invalid_program_entry_size = elf32.clone();
        patch(&mut invalid_program_entry_size, 42, &1_u16.to_le_bytes());
        patch(&mut invalid_program_entry_size, 44, &1_u16.to_le_bytes());
        assert!(ElfFile::parse(&invalid_program_entry_size).is_err());

        let mut invalid_section_entry_size = elf32.clone();
        patch(&mut invalid_section_entry_size, 46, &1_u16.to_le_bytes());
        patch(&mut invalid_section_entry_size, 48, &1_u16.to_le_bytes());
        assert!(ElfFile::parse(&invalid_section_entry_size).is_err());

        let mut changed = parsed.clone();
        changed.header.entry = 1;
        assert!(changed.to_bytes().is_err());

        let program_tables = program_dynamic_and_note_elf64();
        let file = ElfFile::parse(&program_tables).unwrap();
        assert_eq!(file.dynamic_entries.len(), 1);
        assert_eq!(file.notes.len(), 1);

        let mut symbol32 = Vec::new();
        push_u32(&mut symbol32, 1);
        push_u32(&mut symbol32, 0x1234);
        push_u32(&mut symbol32, 4);
        symbol32.push((2 << 4) | 3);
        symbol32.push(2);
        push_u16(&mut symbol32, 1);
        let symbol = read_native_symbol(
            &symbol32,
            Endianness::Little,
            PtrWidth::W32,
            7,
            1,
            Some(b"\0sym\0"),
        )
        .unwrap();
        assert_eq!(symbol.bind, ElfSymbolBind::from_raw(2));
        assert_eq!(symbol.symbol_type, ElfSymbolType::from_raw(3));

        let mut rel32 = Vec::new();
        push_u32(&mut rel32, 4);
        push_u32(&mut rel32, 1 << 8);
        let rel = read_native_relocation(
            &rel32,
            Endianness::Little,
            PtrWidth::W32,
            ElfSectionType::Rel,
            2,
            0,
        )
        .unwrap();
        assert_eq!(rel.addend, None);

        let mut relocation_header = section_header(2, ElfSectionType::Rel);
        relocation_header.size = native_relocation_size(ElfSectionType::Rel, PtrWidth::W32);
        let relocs = read_native_relocations(
            &rel32,
            Endianness::Little,
            PtrWidth::W32,
            &[relocation_header],
        )
        .unwrap();
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs.first().unwrap().offset, 4);

        let mut rel64 = Vec::new();
        push_u64(&mut rel64, 8);
        push_u64(&mut rel64, 1_u64 << 32);
        let rel = read_native_relocation(
            &rel64,
            Endianness::Little,
            PtrWidth::W64,
            ElfSectionType::Rel,
            3,
            0,
        )
        .unwrap();
        assert_eq!(rel.addend, None);

        let mut dyn32 = Vec::new();
        push_u32(&mut dyn32, u32::MAX);
        push_u32(&mut dyn32, 9);
        let dynamic = read_dynamic_entries(
            &dyn32,
            Endianness::Little,
            PtrWidth::W32,
            ElfDynamicSource::Section(1),
        )
        .unwrap();
        assert_eq!(dynamic.first().unwrap().tag, ElfDynamicTag::from_raw(-1));

        let non_strtab = [ElfSectionHeader {
            index: 0,
            name_offset: 0,
            name: None,
            section_type: ElfSectionType::Null,
            flags: ElfSectionFlags::from_raw(0),
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            address_align: 0,
            entry_size: 0,
        }];
        assert!(linked_string_table(&[], &non_strtab, 0).is_none());
        assert_eq!(
            native_relocation_size(ElfSectionType::Rel, PtrWidth::W32),
            elf32::REL_SIZE
        );
        assert_eq!(
            native_relocation_size(ElfSectionType::Rel, PtrWidth::W64),
            elf64::REL_SIZE
        );
        assert_eq!(
            native_relocation_size(ElfSectionType::Null, PtrWidth::W64),
            0
        );
        assert!(read_range(&[], u64::MAX, 1).is_err());
        assert!(require_entry_size(1, 2, "entry").is_err());
        assert!(entry_count(3, 2, "count").is_err());
        assert_eq!(align_up(7, 1), 7);
        assert_eq!(
            machine_arch(ElfMachine::Arm.raw(), PtrWidth::W32),
            Architecture::Arm
        );
        assert_eq!(
            machine_arch(ElfMachine::Riscv.raw(), PtrWidth::W64),
            Architecture::Riscv64
        );
        assert_eq!(
            machine_arch(ElfMachine::PowerPc64.raw(), PtrWidth::W64),
            Architecture::PowerPc64
        );
        assert_eq!(
            machine_arch(ElfMachine::S390.raw(), PtrWidth::W64),
            Architecture::S390x
        );
        assert_eq!(
            machine_arch(ElfMachine::Mips.raw(), PtrWidth::W32),
            Architecture::Mips
        );
        assert_eq!(
            machine_arch(ElfMachine::Mips.raw(), PtrWidth::W64),
            Architecture::Mips64
        );
        assert_eq!(
            machine_arch(ElfMachine::LoongArch.raw(), PtrWidth::W64),
            Architecture::LoongArch64
        );
        assert_eq!(
            machine_arch(ElfMachine::SparcV9.raw(), PtrWidth::W64),
            Architecture::Sparc64
        );
        let header = non_strtab.first().unwrap();
        assert_eq!(
            classify_projected_section(".debug_info", header),
            SectionKind::Debug
        );
        assert_eq!(project_symbol_kind(3), SymbolKind::Section);
        assert_eq!(project_symbol_binding(2), SymbolBinding::Weak);

        let relocation_cases = [
            (Architecture::X86_64, 2, RelocKind::Relative32),
            (Architecture::X86_64, 4, RelocKind::PltRelative),
            (Architecture::X86_64, 9, RelocKind::GotRelative),
            (Architecture::X86, 2, RelocKind::Relative32),
            (Architecture::Aarch64, 258, RelocKind::Absolute32),
            (Architecture::Aarch64, 261, RelocKind::Relative32),
            (Architecture::Arm, 2, RelocKind::Absolute32),
            (Architecture::Arm, 3, RelocKind::Relative32),
            (Architecture::Riscv64, 2, RelocKind::Absolute64),
            (Architecture::Riscv64, 39, RelocKind::Relative32),
            (Architecture::PowerPc64, 38, RelocKind::Absolute64),
            (Architecture::PowerPc64, 26, RelocKind::Relative32),
            (Architecture::Mips, 2, RelocKind::Absolute32),
            (Architecture::Mips64, 2, RelocKind::Absolute32),
            (Architecture::Mips64, 18, RelocKind::Absolute64),
            (Architecture::S390x, 22, RelocKind::Absolute64),
            (Architecture::S390x, 5, RelocKind::Relative32),
            (Architecture::LoongArch64, 2, RelocKind::Absolute64),
            (Architecture::Sparc64, 32, RelocKind::Absolute64),
            (Architecture::Other(0), 1, RelocKind::Absolute32),
            (Architecture::Other(0), 2, RelocKind::Relative32),
            (Architecture::Other(0), 99, RelocKind::Other(99)),
        ];
        for (arch, raw, expected) in relocation_cases {
            assert_eq!(project_relocation_kind(arch, raw), expected);
        }

        let mut invalid_segment = ElfFile::parse_owned(hello_bytes()).unwrap();
        let first_segment = invalid_segment.program_headers.first_mut().unwrap();
        first_segment.file_size = 2;
        first_segment.memory_size = 1;
        assert!(invalid_segment.to_oir().is_err());

        let file = ElfFile::parse_owned(hello_bytes()).unwrap();
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        let name = module.intern(".text").unwrap();
        let id = module
            .add_section(Section {
                name,
                kind: SectionKind::Text,
                address: 0,
                align: 1,
                flags: SectionFlags::code(),
                data: Vec::new(),
                size: 0,
            })
            .unwrap();
        add_projected_segments(&mut module, &file, &[(u32::MAX, id)]).unwrap();
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "single fixture targets native private malformed-input error edges"
    )]
    fn native_malformed_private_errors_are_covered() {
        let mut extended_program_without_section_zero = minimal_elf32(ElfMachine::X86);
        patch(
            &mut extended_program_without_section_zero,
            42,
            &u16::try_from(elf32::PHDR_SIZE).unwrap().to_le_bytes(),
        );
        patch(
            &mut extended_program_without_section_zero,
            44,
            &PN_XNUM.to_le_bytes(),
        );
        assert!(ElfFile::parse(&extended_program_without_section_zero).is_err());

        let mut symtab = section_header(1, ElfSectionType::Symtab);
        symtab.entry_size = 1;
        symtab.size = native_sym_size(PtrWidth::W64);
        assert!(
            read_native_symbols(&[], Endianness::Little, PtrWidth::W64, &[symtab.clone()]).is_err()
        );

        symtab.entry_size = native_sym_size(PtrWidth::W64);
        assert!(read_native_symbols(&[], Endianness::Little, PtrWidth::W64, &[symtab]).is_err());

        let mut rela = section_header(2, ElfSectionType::Rela);
        rela.entry_size = 1;
        rela.size = native_relocation_size(ElfSectionType::Rela, PtrWidth::W64);
        assert!(
            read_native_relocations(&[], Endianness::Little, PtrWidth::W64, &[rela.clone()])
                .is_err()
        );

        rela.entry_size = native_relocation_size(ElfSectionType::Rela, PtrWidth::W64);
        assert!(read_native_relocations(&[], Endianness::Little, PtrWidth::W64, &[rela]).is_err());

        let mut dynamic = section_header(3, ElfSectionType::Dynamic);
        dynamic.offset = 1;
        dynamic.size = 16;
        assert!(
            read_section_dynamic_entries(&[], Endianness::Little, PtrWidth::W64, &[dynamic])
                .is_err()
        );

        let mut dynamic_phdr = program_header(0, ElfSegmentType::Dynamic);
        dynamic_phdr.file_size = 1;
        assert!(
            read_program_dynamic_entries(&[0], Endianness::Little, PtrWidth::W64, &[dynamic_phdr])
                .is_err()
        );

        let mut note = section_header(4, ElfSectionType::Note);
        note.offset = 1;
        note.size = 12;
        assert!(read_section_notes(&[], Endianness::Little, &[note]).is_err());
        assert!(entry_count(u64::from(u32::MAX) + 1, 1, "count").is_err());

        let mut segment_end = ElfFile::parse_owned(hello_bytes()).unwrap();
        let phdr = segment_end.program_headers.first_mut().unwrap();
        phdr.file_size = 0;
        phdr.memory_size = 1;
        phdr.virtual_address = u64::MAX;
        assert!(segment_end.to_oir().is_err());

        let mut section_end = ElfFile::parse_owned(hello_bytes()).unwrap();
        let phdr = section_end.program_headers.first_mut().unwrap();
        phdr.file_size = 0;
        phdr.memory_size = u64::MAX;
        phdr.virtual_address = 0;
        let header = section_end
            .section_headers
            .iter_mut()
            .find(|header| should_project_section(header.section_type))
            .unwrap();
        header.flags = ElfSectionFlags::SHF_ALLOC;
        header.address = u64::MAX;
        header.size = 1;
        assert!(section_end.to_oir().is_err());

        let file = ElfFile::parse_owned(hello_bytes()).unwrap();
        let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
        let section_name = module.intern(".text").unwrap();
        let section = module
            .add_section(Section {
                name: section_name,
                kind: SectionKind::Text,
                address: 0,
                align: 1,
                flags: SectionFlags::code(),
                data: Vec::new(),
                size: 0,
            })
            .unwrap();
        let symbol_name = module.intern("sym").unwrap();
        let symbol = module
            .add_symbol(SymbolEntry {
                name: symbol_name,
                value: 0,
                size: 0,
                section: Some(section),
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                flags: SymbolFlags::none(),
            })
            .unwrap();
        let section_ids = [(1, section)];
        let symbol_ids = [(7, 0, symbol)];

        let mut missing_table = file.clone();
        missing_table.relocations = vec![relocation(999, 0)];
        assert!(
            add_projected_relocations(&mut module, &missing_table, &section_ids, &symbol_ids)
                .is_err()
        );

        let mut huge_symbol = file;
        let mut table = section_header(999, ElfSectionType::Rela);
        table.info = 1;
        table.link = 7;
        huge_symbol.section_headers.push(table);
        huge_symbol.relocations = vec![relocation(999, u64::from(u32::MAX) + 1)];
        assert!(
            add_projected_relocations(&mut module, &huge_symbol, &section_ids, &symbol_ids)
                .is_err()
        );
        assert!(find_section_header(&[], 1).is_none());
    }

    #[test]
    fn parses_extended_counts() {
        let mut bytes = hello_bytes();
        let (shoff, program_header_count, section_header_count, section_name_table_index) = {
            let file = ElfFile::parse(&bytes).unwrap();
            (
                file.header.section_header_offset,
                file.header.program_header_count,
                file.header.section_header_count,
                file.header.section_name_table_index,
            )
        };
        patch(&mut bytes, 56, &PN_XNUM.to_le_bytes());
        patch(&mut bytes, 60, &0_u16.to_le_bytes());
        patch(&mut bytes, 62, &u16::MAX.to_le_bytes());
        patch_u32_at_shdr64(&mut bytes, shoff, 0, 44, program_header_count);
        patch_u64_at_shdr64(&mut bytes, shoff, 0, 32, u64::from(section_header_count));
        patch_u32_at_shdr64(&mut bytes, shoff, 0, 40, section_name_table_index.unwrap());
        let reparsed = ElfFile::parse(&bytes).unwrap();
        assert_eq!(reparsed.header.program_header_count, program_header_count);
        assert_eq!(reparsed.header.section_header_count, section_header_count);
        assert_eq!(
            reparsed.header.section_name_table_index,
            section_name_table_index
        );

        let mut bad_count = bytes.clone();
        patch(&mut bad_count, 60, &0_u16.to_le_bytes());
        patch_u64_at_shdr64(&mut bad_count, shoff, 0, 32, u64::MAX);
        assert!(ElfFile::parse(&bad_count).is_err());
    }

    fn patch(bytes: &mut [u8], offset: usize, replacement: &[u8]) {
        let end = offset.checked_add(replacement.len()).unwrap();
        bytes
            .get_mut(offset..end)
            .unwrap()
            .copy_from_slice(replacement);
    }

    fn assert_all_truncated_prefixes_fail(bytes: &[u8]) {
        for len in 0..bytes.len() {
            let prefix = bytes.get(..len).unwrap();
            assert!(ElfFile::parse(prefix).is_err(), "prefix length {len}");
        }
    }

    fn section_header(index: u32, section_type: ElfSectionType) -> ElfSectionHeader {
        ElfSectionHeader {
            index,
            name_offset: 0,
            name: Some(Vec::new()),
            section_type,
            flags: ElfSectionFlags::from_raw(0),
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            address_align: 1,
            entry_size: 0,
        }
    }

    fn program_header(index: u32, segment_type: ElfSegmentType) -> ElfProgramHeader {
        ElfProgramHeader {
            index,
            segment_type,
            flags: ElfSegmentFlags::from_raw(0),
            offset: 0,
            virtual_address: 0,
            physical_address: 0,
            file_size: 0,
            memory_size: 0,
            align: 1,
        }
    }

    fn relocation(table_section: u32, symbol: u64) -> ElfRelocation {
        ElfRelocation {
            table_section,
            index: 0,
            offset: 0,
            symbol,
            relocation_type: ElfRelocationType::from_raw(0),
            info: 0,
            addend: None,
        }
    }

    fn minimal_elf32(machine: ElfMachine) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(ElfClass::Class32.raw());
        bytes.push(ElfDataEncoding::Little.raw());
        bytes.push(ElfVersion::Current.raw());
        bytes.extend_from_slice(&[0; 9]);
        push_u16(&mut bytes, 1);
        push_u16(&mut bytes, machine.raw());
        push_u32(&mut bytes, u32::from(ElfVersion::Current.raw()));
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u16(&mut bytes, u16::try_from(elf32::EHDR_SIZE).unwrap());
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        bytes
    }

    fn program_dynamic_and_note_elf64() -> Vec<u8> {
        let phoff = elf64::EHDR_SIZE;
        let dyn_offset = elf64::EHDR_SIZE + (elf64::PHDR_SIZE * 2);
        let note_offset = dyn_offset + 16;
        let note = note_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.push(ElfClass::Class64.raw());
        bytes.push(ElfDataEncoding::Little.raw());
        bytes.push(ElfVersion::Current.raw());
        bytes.extend_from_slice(&[0; 9]);
        push_u16(&mut bytes, 2);
        push_u16(&mut bytes, ElfMachine::X86_64.raw());
        push_u32(&mut bytes, u32::from(ElfVersion::Current.raw()));
        push_u64(&mut bytes, 0);
        push_u64(&mut bytes, phoff);
        push_u64(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        push_u16(&mut bytes, u16::try_from(elf64::EHDR_SIZE).unwrap());
        push_u16(&mut bytes, u16::try_from(elf64::PHDR_SIZE).unwrap());
        push_u16(&mut bytes, 2);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_phdr64(&mut bytes, ElfSegmentType::Dynamic.raw(), dyn_offset, 16, 8);
        push_phdr64(
            &mut bytes,
            ElfSegmentType::Note.raw(),
            note_offset,
            u64::try_from(note.len()).unwrap(),
            4,
        );
        push_u64(&mut bytes, 0);
        push_u64(&mut bytes, 0);
        bytes.extend_from_slice(&note);
        bytes
    }

    fn push_phdr64(bytes: &mut Vec<u8>, typ: u32, offset: u64, filesz: u64, align: u64) {
        push_u32(bytes, typ);
        push_u32(bytes, 0);
        push_u64(bytes, offset);
        push_u64(bytes, 0);
        push_u64(bytes, 0);
        push_u64(bytes, filesz);
        push_u64(bytes, filesz);
        push_u64(bytes, align);
    }

    fn note_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 4);
        push_u32(&mut bytes, 7);
        bytes.extend_from_slice(b"GNU\0");
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        bytes
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn patch_u32_at_shdr64(bytes: &mut [u8], shoff: u64, index: u32, field: u64, value: u32) {
        let base = shoff
            .checked_add(u64::from(index) * elf64::SHDR_SIZE)
            .and_then(|offset| offset.checked_add(field))
            .and_then(|offset| usize::try_from(offset).ok())
            .unwrap();
        patch(bytes, base, &value.to_le_bytes());
    }

    fn patch_u64_at_shdr64(bytes: &mut [u8], shoff: u64, index: u32, field: u64, value: u64) {
        let base = shoff
            .checked_add(u64::from(index) * elf64::SHDR_SIZE)
            .and_then(|offset| offset.checked_add(field))
            .and_then(|offset| usize::try_from(offset).ok())
            .unwrap();
        patch(bytes, base, &value.to_le_bytes());
    }
}
