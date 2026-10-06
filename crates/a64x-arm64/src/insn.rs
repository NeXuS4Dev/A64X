//! Instruction representation shared by the decoder, translator and
//! disassembler.

use core::fmt;

/// ARM condition codes (the `cond` field of B.cond / CSEL / CCMP).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    /// Z == 1
    Eq = 0,
    /// Z == 0
    Ne = 1,
    /// C == 1 (unsigned higher or same)
    Cs = 2,
    /// C == 0 (unsigned lower)
    Cc = 3,
    /// N == 1 (minus)
    Mi = 4,
    /// N == 0 (plus)
    Pl = 5,
    /// V == 1
    Vs = 6,
    /// V == 0
    Vc = 7,
    /// C == 1 && Z == 0 (unsigned higher)
    Hi = 8,
    /// !(C == 1 && Z == 0)
    Ls = 9,
    /// N == V
    Ge = 10,
    /// N != V
    Lt = 11,
    /// Z == 0 && N == V
    Gt = 12,
    /// Z == 1 || N != V
    Le = 13,
    /// always
    Al = 14,
    /// always (alias; 0b1111)
    Nv = 15,
}

impl Cond {
    /// Decode from the 4-bit field.
    pub fn from_bits(v: u8) -> Cond {
        use Cond::*;
        match v & 0xF {
            0 => Eq,
            1 => Ne,
            2 => Cs,
            3 => Cc,
            4 => Mi,
            5 => Pl,
            6 => Vs,
            7 => Vc,
            8 => Hi,
            9 => Ls,
            10 => Ge,
            11 => Lt,
            12 => Gt,
            13 => Le,
            14 => Al,
            _ => Nv,
        }
    }

    /// The inverse condition.
    pub fn invert(self) -> Cond {
        use Cond::*;
        match self {
            Eq => Ne,
            Ne => Eq,
            Cs => Cc,
            Cc => Cs,
            Mi => Pl,
            Pl => Mi,
            Vs => Vc,
            Vc => Vs,
            Hi => Ls,
            Ls => Hi,
            Ge => Lt,
            Lt => Ge,
            Gt => Le,
            Le => Gt,
            Al => Nv,
            Nv => Al,
        }
    }

    /// True if this is the "always" condition.
    pub fn is_always(self) -> bool {
        matches!(self, Cond::Al)
    }

    /// Evaluate against NZCV bytes.
    pub fn eval(self, n: bool, z: bool, c: bool, v: bool) -> bool {
        use Cond::*;
        match self {
            Eq => z,
            Ne => !z,
            Cs => c,
            Cc => !c,
            Mi => n,
            Pl => !n,
            Vs => v,
            Vc => !v,
            Hi => c && !z,
            Ls => !(c && !z),
            Ge => n == v,
            Lt => n != v,
            Gt => !z && n == v,
            Le => z || n != v,
            Al => true,
            // 0b1111 (NV): inverted unconditional => never
            Nv => false,
        }
    }
}

impl fmt::Display for Cond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Cond::*;
        f.write_str(match self {
            Eq => "eq",
            Ne => "ne",
            Cs => "hs",
            Cc => "lo",
            Mi => "mi",
            Pl => "pl",
            Vs => "vs",
            Vc => "vc",
            Hi => "hi",
            Ls => "ls",
            Ge => "ge",
            Lt => "lt",
            Gt => "gt",
            Le => "le",
            Al => "al",
            Nv => "nv",
        })
    }
}

/// Shift operations used by register-shifted operands.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftType {
    /// Logical shift left.
    Lsl = 0,
    /// Logical shift right.
    Lsr = 1,
    /// Arithmetic shift right.
    Asr = 2,
    /// Rotate right (only valid for logical register forms).
    Ror = 3,
}

impl fmt::Display for ShiftType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ShiftType::Lsl => "lsl",
            ShiftType::Lsr => "lsr",
            ShiftType::Asr => "asr",
            ShiftType::Ror => "ror",
        })
    }
}

/// Extend operations for the extended-register addressing forms.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendType {
    /// unsigned extend byte
    Uxtb = 0,
    /// unsigned extend halfword
    Uxth = 1,
    /// unsigned extend word
    Uxtw = 2,
    /// unsigned extend doubleword (identity)
    Uxtx = 3,
    /// signed extend byte
    Sxtb = 4,
    /// signed extend halfword
    Sxth = 5,
    /// signed extend word
    Sxtw = 6,
    /// signed extend doubleword (identity)
    Sxtx = 7,
}

impl ExtendType {
    /// Decode the 3-bit option field.
    pub fn from_bits(v: u8) -> ExtendType {
        use ExtendType::*;
        match v & 7 {
            0 => Uxtb,
            1 => Uxth,
            2 => Uxtw,
            3 => Uxtx,
            4 => Sxtb,
            5 => Sxth,
            6 => Sxtw,
            _ => Sxtx,
        }
    }

    /// Number of bytes the source value occupies before extension.
    pub fn src_size(self) -> u8 {
        use ExtendType::*;
        match self {
            Uxtb | Sxtb => 1,
            Uxth | Sxth => 2,
            Uxtw | Sxtw => 4,
            Uxtx | Sxtx => 8,
        }
    }

    /// Whether the extension is signed.
    pub fn is_signed(self) -> bool {
        (self as u8) >= 4
    }
}

impl fmt::Display for ExtendType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtendType::*;
        f.write_str(match self {
            Uxtb => "uxtb",
            Uxth => "uxth",
            Uxtw => "uxtw",
            Uxtx => "uxtx",
            Sxtb => "sxtb",
            Sxth => "sxth",
            Sxtw => "sxtw",
            Sxtx => "sxtx",
        })
    }
}

/// Logical operations for immediate/shifted-register forms.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicOp {
    /// AND
    And = 0,
    /// ORR
    Orr = 1,
    /// EOR
    Eor = 2,
    /// ANDS (sets flags)
    Ands = 3,
}

/// Memory access kind for single register loads/stores.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdStOp {
    /// STRx — store `size` bytes.
    Store = 0,
    /// LDRx — load `size` bytes, zero extend.
    LoadZ = 1,
    /// LDRSx — load `size` bytes (1,2,4), sign extend to 64 bits.
    LoadS64 = 2,
    /// LDRSx to W — load `size` bytes (1,2), sign extend to 32 bits.
    LoadS32 = 3,
}

/// Addressing modes for single register loads/stores.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    /// `[Xn, #imm]` (LDUR/STUR family, unscaled 9-bit signed offset).
    UnscaledImm { offset: i32 },
    /// `[Xn, #imm]` (unsigned 12-bit, scaled by access size).
    UnsignedImm { offset: u32 },
    /// `[Xn, #imm]!` — write-back before access.
    PreIndex { offset: i32 },
    /// `[Xn], #imm` — write-back after access.
    PostIndex { offset: i32 },
    /// `[Xn, Rm, extend {#shift}]`.
    RegOffset { rm: u8, extend: ExtendType, shift: u8 },
}

/// Write-back mode for load/store pair.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairMode {
    /// `stnp/ldnp [Xn, #imm]` — signed offset, no write-back.
    SignedOffset = 0,
    /// `[Xn], #imm` — post-index.
    PostIndex = 1,
    /// `[Xn, #imm]` — signed offset (normal stp/ldp).
    Offset = 2,
    /// `[Xn, #imm]!` — pre-index.
    PreIndex = 3,
}

/// Move-wide operations.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MovOp {
    /// MOVN — write inverted immediate.
    Movn = 0,
    /// MOVZ — write immediate.
    Movz = 2,
    /// MOVK — keep other bits.
    Movk = 3,
}

/// Bitfield move operations.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfOp {
    /// SBFM (sign-extending aliases: asr imm, sxtb/h/w, sbfx, sbfiz).
    Sbfm = 0,
    /// BFM (insert: bfi, bfxil).
    Bfm = 1,
    /// UBFM (zero-extending aliases: lsr/lsl imm, uxtb/h, ubfx, ubfiz).
    Ubfm = 2,
}

/// Conditional select variants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSelOp {
    /// `rd = cond ? rn : rm`
    Csel = 0,
    /// `rd = cond ? rn : rm + 1`
    Csinc = 1,
    /// `rd = cond ? rn : !rm`
    Csinv = 2,
    /// `rd = cond ? rn : -rm`
    Csneg = 3,
}

/// Register-reverse/clear-count variants (Data processing 1-source).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevOp {
    /// Reverse all bytes (32-bit: bswap32; 64-bit: bswap64).
    Rev = 0,
    /// Reverse bytes within each 16-bit element.
    Rev16 = 1,
    /// Reverse bytes within each 32-bit element (64-bit regs only here).
    Rev32 = 2,
    /// Count leading zeros.
    Clz = 4,
}

/// A decoded A64 instruction (integer subset; FP/SIMD are rejected by the
/// decoder and reported as unsupported by the translator).
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq)]
pub enum Insn {
    /// ADD/SUB (immediate). `rn`/`rd` use index 31 for SP
    /// (or ZR when `setflags && rd == 31`, i.e. CMP/CMN).
    AddImm { w64: bool, sub: bool, setflags: bool, imm: u32, rn: u8, rd: u8 },
    /// Logical (immediate), decoded bitmask.
    LogicImm { w64: bool, op: LogicOp, mask: u64, rn: u8, rd: u8 },
    /// MOVN/MOVZ/MOVK.
    MovImm { w64: bool, op: MovOp, imm16: u16, shift: u8, rd: u8 },
    /// Bitfield move (SBFM/BFM/UBFM and their aliases).
    Bitfield { w64: bool, op: BfOp, immr: u8, imms: u8, rn: u8, rd: u8 },
    /// EXTR (extract; ROR immediate alias when rn == rm).
    Extract { w64: bool, lsb: u8, rm: u8, rn: u8, rd: u8 },
    /// ADR / ADRP — target address resolved at decode time.
    PcRel { page: bool, addr: u64, rd: u8 },
    /// B / BL — resolved absolute target.
    Branch { link: bool, target: u64 },
    /// B.<cond>.
    BranchCond { cond: Cond, target: u64 },
    /// CBZ / CBNZ.
    Cbz { w64: bool, nonzero: bool, rt: u8, target: u64 },
    /// TBZ / TBNZ.
    Tbz { nonzero: bool, bit: u8, rt: u8, target: u64 },
    /// BR / BLR / RET.
    BranchReg { link: bool, ret: bool, rn: u8 },
    /// Single register load/store.
    LdSt { size: u8, op: LdStOp, rt: u8, rn: u8, mode: AddrMode },
    /// Load/store register pair.
    LdStPair { w64: bool, load: bool, rt: u8, rt2: u8, rn: u8, offset: i32, mode: PairMode },
    /// PC-relative literal load.
    LdrLiteral { size: u8, op: LdStOp, rt: u8, target: u64 },
    /// Logical (shifted register).
    LogicReg { w64: bool, op: LogicOp, negate: bool, shift: ShiftType, shift_amt: u8, rm: u8, rn: u8, rd: u8 },
    /// ADD/SUB (shifted register). Index 31 = ZR on all operands.
    AddReg { w64: bool, sub: bool, setflags: bool, shift: ShiftType, shift_amt: u8, rm: u8, rn: u8, rd: u8 },
    /// ADD/SUB (extended register). Index 31 = SP for `rn`, and for `rd`
    /// when flags are not written.
    AddExt { w64: bool, sub: bool, setflags: bool, extend: ExtendType, amount: u8, rm: u8, rn: u8, rd: u8 },
    /// MADD/MSUB (multiply-add; MUL/MNEG aliases via ra == 31).
    Mul { w64: bool, sub: bool, rm: u8, rn: u8, ra: u8, rd: u8 },
    /// UMADDL/SMADDL/UMSUBL/SMSUBL — 32x32 -> 64 multiply-add.
    MulLong { signed: bool, sub: bool, rm: u8, rn: u8, ra: u8, rd: u8 },
    /// UMULH/SMULH — high half of 64x64 -> 128 product.
    MulHigh { signed: bool, rm: u8, rn: u8, rd: u8 },
    /// UDIV/SDIV. Division by zero yields 0 (per ARM semantics).
    Div { w64: bool, signed: bool, rm: u8, rn: u8, rd: u8 },
    /// LSLV/LSRV/ASRV/RORV — variable shifts.
    ShiftVar { w64: bool, shift: ShiftType, rm: u8, rn: u8, rd: u8 },
    /// REV/REV16/REV32/CLZ.
    Rev { w64: bool, op: RevOp, rn: u8, rd: u8 },
    /// CSEL/CSINC/CSINV/CSNEG.
    CSel { w64: bool, op: CSelOp, cond: Cond, rm: u8, rn: u8, rd: u8 },
    /// NOP and hint/barrier instructions treated as NOPs under A64X's
    /// single-threadedv1 memory model.
    Nop,
    /// SVC #imm — raw syscall (see `Error::UnsupportedSyscall`).
    Svc { imm: u16 },
    /// BRK #imm — breakpoint.
    Brk { imm: u16 },
}

/// Register 31 renders as SP/WSP in stack-capable contexts.
pub fn reg_sp(r: u8, w64: bool) -> String {
    if r == 31 {
        if w64 { "sp".into() } else { "wsp".into() }
    } else if w64 {
        format!("x{r}")
    } else {
        format!("w{r}")
    }
}

/// Register 31 renders as XZR/WZR in zero-register contexts.
pub fn reg_zr(r: u8, w64: bool) -> String {
    if r == 31 {
        if w64 { "xzr".into() } else { "wzr".into() }
    } else if w64 {
        format!("x{r}")
    } else {
        format!("w{r}")
    }
}

impl fmt::Display for Insn {
    /// Light-weight disassembly with the usual alias names resolved
    /// (cmp/mov/tst/mul/neg/lsl/lsr/asr/sxt/uxt/cset).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Insn::*;
        match self {
            AddImm { w64, sub, setflags, imm, rn, rd } => {
                if *setflags && *rd == 31 {
                    return write!(f, "{} {}, #{imm}", if *sub { "cmp" } else { "cmn" }, reg_sp(*rn, *w64));
                }
                let op = if *setflags {
                    if *sub { "subs" } else { "adds" }
                } else if *sub {
                    "sub"
                } else {
                    "add"
                };
                if *imm == 0 && !setflags && (*rd == 31 || *rn == 31) {
                    return write!(f, "mov {}, {}", reg_sp(*rd, *w64), reg_sp(*rn, *w64));
                }
                write!(f, "{op} {}, {}, #{imm}", reg_sp(*rd, *w64), reg_sp(*rn, *w64))
            }
            LogicImm { w64, op, mask, rn, rd } => {
                let name = match op {
                    LogicOp::And => "and",
                    LogicOp::Orr => "orr",
                    LogicOp::Eor => "eor",
                    LogicOp::Ands => "ands",
                };
                if *op == LogicOp::Ands && *rd == 31 {
                    return write!(f, "tst {}, #0x{mask:x}", reg_zr(*rn, *w64));
                }
                write!(f, "{name} {}, {}, #0x{mask:x}", reg_zr(*rd, *w64), reg_zr(*rn, *w64))
            }
            MovImm { w64, op, imm16, shift, rd } => {
                let name = match op {
                    MovOp::Movn => "movn",
                    MovOp::Movz => "movz",
                    MovOp::Movk => "movk",
                };
                if *shift == 0 {
                    write!(f, "{name} {}, #0x{imm16:x}", reg_zr(*rd, *w64))
                } else {
                    write!(f, "{name} {}, #0x{imm16:x}, lsl #{shift}", reg_zr(*rd, *w64))
                }
            }
            Bitfield { w64, op, immr, imms, rn, rd } => {
                let name = match op {
                    BfOp::Sbfm => "sbfm",
                    BfOp::Bfm => "bfm",
                    BfOp::Ubfm => "ubfm",
                };
                let width: u8 = if *w64 { 64 } else { 32 };
                // pretty aliases
                if matches!(op, BfOp::Ubfm) {
                    if *imms == width - 1 {
                        return write!(f, "lsr {}, {}, #{immr}", reg_zr(*rd, *w64), reg_zr(*rn, *w64));
                    }
                    if *imms + 1 == *immr {
                        return write!(f, "lsl {}, {}, #{}", reg_zr(*rd, *w64), reg_zr(*rn, *w64), width - *immr);
                    }
                    if *immr == 0 && (*imms == 7 || *imms == 15) {
                        let n = if *imms == 7 { "uxtb" } else { "uxth" };
                        return write!(f, "{n} {}, {}", reg_zr(*rd, *w64), reg_zr(*rn, false));
                    }
                }
                if matches!(op, BfOp::Sbfm) {
                    if *immr == 0 && (*imms == 7 || *imms == 15 || *imms == 31) {
                        let n = match *imms {
                            7 => "sxtb",
                            15 => "sxth",
                            _ => "sxtw",
                        };
                        return write!(f, "{n} {}, {}", reg_zr(*rd, *w64), reg_zr(*rn, false));
                    }
                    if *imms == width - 1 {
                        return write!(f, "asr {}, {}, #{immr}", reg_zr(*rd, *w64), reg_zr(*rn, *w64));
                    }
                }
                write!(f, "{name} {}, {}, #{immr}, #{imms}", reg_zr(*rd, *w64), reg_zr(*rn, *w64))
            }
            Extract { w64, lsb, rm, rn, rd } => {
                if rn == rm {
                    write!(f, "ror {}, {}, #{lsb}", reg_zr(*rd, *w64), reg_zr(*rn, *w64))
                } else {
                    write!(
                        f,
                        "extr {}, {}, {}, #{lsb}",
                        reg_zr(*rd, *w64),
                        reg_zr(*rn, *w64),
                        reg_zr(*rm, *w64)
                    )
                }
            }
            PcRel { page, addr, rd } => {
                if *page {
                    write!(f, "adrp x{}, #0x{addr:x}", rd)
                } else {
                    write!(f, "adr x{}, #0x{addr:x}", rd)
                }
            }
            Branch { link, target } => {
                write!(f, "{} #0x{target:x}", if *link { "bl" } else { "b" })
            }
            BranchCond { cond, target } => write!(f, "b.{cond} #0x{target:x}"),
            Cbz { w64, nonzero, rt, target } => write!(
                f,
                "{} {}, #0x{target:x}",
                if *nonzero { "cbnz" } else { "cbz" },
                reg_zr(*rt, *w64)
            ),
            Tbz { nonzero, bit, rt, target } => {
                write!(f, "{} x{rt}, #{bit}, #0x{target:x}", if *nonzero { "tbnz" } else { "tbz" })
            }
            BranchReg { link, ret, rn } => {
                if *ret && *rn == 30 {
                    f.write_str("ret")
                } else if *ret {
                    write!(f, "ret x{rn}")
                } else if *link {
                    write!(f, "blr x{rn}")
                } else {
                    write!(f, "br x{rn}")
                }
            }
            LdSt { size, op, rt, rn, mode } => {
                let name = memop_name(*size, *op);
                let rt_s = reg_zr(*rt, *size == 8 || matches!(op, LdStOp::LoadS64));
                match mode {
                    AddrMode::UnscaledImm { offset } => {
                        write!(f, "{name} {rt_s}, [{}, #{offset}]", reg_sp(*rn, true))
                    }
                    AddrMode::UnsignedImm { offset } => {
                        write!(f, "{name} {rt_s}, [{}, #{offset}]", reg_sp(*rn, true))
                    }
                    AddrMode::PreIndex { offset } => {
                        write!(f, "{name} {rt_s}, [{}, #{offset}]!", reg_sp(*rn, true))
                    }
                    AddrMode::PostIndex { offset } => {
                        write!(f, "{name} {rt_s}, [{}], #{offset}", reg_sp(*rn, true))
                    }
                    AddrMode::RegOffset { rm, extend, shift } => write!(
                        f,
                        "{name} {rt_s}, [{}, {}, {extend} #{shift}]",
                        reg_sp(*rn, true),
                        reg_zr(*rm, *extend == ExtendType::Uxtx)
                    ),
                }
            }
            LdStPair { w64, load, rt, rt2, rn, offset, mode } => {
                let name = match (load, mode) {
                    (false, PairMode::SignedOffset) => "stnp",
                    (true, PairMode::SignedOffset) => "ldnp",
                    (false, _) => "stp",
                    (true, _) => "ldp",
                };
                let a = reg_zr(*rt, *w64);
                let b = reg_zr(*rt2, *w64);
                let base = reg_sp(*rn, true);
                match mode {
                    PairMode::PreIndex => write!(f, "{name} {a}, {b}, [{base}, #{offset}]!"),
                    PairMode::PostIndex => write!(f, "{name} {a}, {b}, [{base}], #{offset}"),
                    _ => write!(f, "{name} {a}, {b}, [{base}, #{offset}]"),
                }
            }
            LdrLiteral { size, op, rt, target } => {
                let name = memop_name(*size, *op);
                let wide = *size == 8 || matches!(op, LdStOp::LoadS64);
                write!(f, "{name} {}, #0x{target:x} (literal)", reg_zr(*rt, wide))
            }
            LogicReg { w64, op, negate, shift, shift_amt, rm, rn, rd } => {
                // MOV alias: ORR/ORX rd, xzr, rm, LSL #0
                if *op == LogicOp::Orr && !*negate && *rn == 31 && *shift_amt == 0 && *shift == ShiftType::Lsl {
                    return write!(f, "mov {}, {}", reg_zr(*rd, *w64), reg_zr(*rm, *w64));
                }
                if *op == LogicOp::Orr && *negate && *rn == 31 {
                    return write!(
                        f,
                        "mvn {}, {}{}",
                        reg_zr(*rd, *w64),
                        reg_zr(*rm, *w64),
                        shift_suffix(*shift, *shift_amt)
                    );
                }
                if *op == LogicOp::Ands && *rd == 31 {
                    return write!(
                        f,
                        "tst {}, {}{}",
                        reg_zr(*rn, *w64),
                        reg_zr(*rm, *w64),
                        shift_suffix(*shift, *shift_amt)
                    );
                }
                let name = match (op, negate) {
                    (LogicOp::And, false) => "and",
                    (LogicOp::And, true) => "bic",
                    (LogicOp::Orr, false) => "orr",
                    (LogicOp::Orr, true) => "orn",
                    (LogicOp::Eor, false) => "eor",
                    (LogicOp::Eor, true) => "eon",
                    (LogicOp::Ands, false) => "ands",
                    (LogicOp::Ands, true) => "bics",
                };
                write!(
                    f,
                    "{name} {}, {}, {}{}",
                    reg_zr(*rd, *w64),
                    reg_zr(*rn, *w64),
                    reg_zr(*rm, *w64),
                    shift_suffix(*shift, *shift_amt)
                )
            }
            AddReg { w64, sub, setflags, shift, shift_amt, rm, rn, rd } => {
                if *setflags && *rd == 31 {
                    return write!(
                        f,
                        "{} {}, {}{}",
                        if *sub { "cmp" } else { "cmn" },
                        reg_zr(*rn, *w64),
                        reg_zr(*rm, *w64),
                        shift_suffix(*shift, *shift_amt)
                    );
                }
                if *sub && !*setflags && *rn == 31 {
                    return write!(
                        f,
                        "neg {}, {}{}",
                        reg_zr(*rd, *w64),
                        reg_zr(*rm, *w64),
                        shift_suffix(*shift, *shift_amt)
                    );
                }
                let name = match (sub, setflags) {
                    (false, false) => "add",
                    (true, false) => "sub",
                    (false, true) => "adds",
                    (true, true) => "subs",
                };
                write!(
                    f,
                    "{name} {}, {}, {}{}",
                    reg_zr(*rd, *w64),
                    reg_zr(*rn, *w64),
                    reg_zr(*rm, *w64),
                    shift_suffix(*shift, *shift_amt)
                )
            }
            AddExt { w64, sub, setflags, extend, amount, rm, rn, rd } => {
                let name = match (sub, setflags) {
                    (false, false) => "add",
                    (true, false) => "sub",
                    (false, true) => "adds",
                    (true, true) => "subs",
                };
                write!(
                    f,
                    "{name} {}, {}, {}, {extend} #{amount}",
                    reg_sp(*rd, *w64),
                    reg_sp(*rn, *w64),
                    reg_zr(*rm, false)
                )
            }
            Mul { w64, sub, rm, rn, ra, rd } => {
                if *ra == 31 && !*sub {
                    return write!(f, "mul {}, {}, {}", reg_zr(*rd, *w64), reg_zr(*rn, *w64), reg_zr(*rm, *w64));
                }
                if *ra == 31 && *sub {
                    return write!(f, "mneg {}, {}, {}", reg_zr(*rd, *w64), reg_zr(*rn, *w64), reg_zr(*rm, *w64));
                }
                write!(
                    f,
                    "{} {}, {}, {}, {}",
                    if *sub { "msub" } else { "madd" },
                    reg_zr(*rd, *w64),
                    reg_zr(*rn, *w64),
                    reg_zr(*rm, *w64),
                    reg_zr(*ra, *w64)
                )
            }
            MulLong { signed, sub, rm, rn, ra, rd } => {
                let name = match (signed, sub, *ra == 31) {
                    (true, false, true) => "smull",
                    (false, false, true) => "umull",
                    (true, false, false) => "smaddl",
                    (false, false, false) => "umaddl",
                    (true, true, _) => "smsubl",
                    (false, true, _) => "umsubl",
                };
                write!(f, "{name} x{rd}, w{rn}, w{rm}, x{ra}")
            }
            MulHigh { signed, rm, rn, rd } => {
                write!(f, "{} x{rd}, x{rn}, x{rm}", if *signed { "smulh" } else { "umulh" })
            }
            Div { w64, signed, rm, rn, rd } => write!(
                f,
                "{} {}, {}, {}",
                if *signed { "sdiv" } else { "udiv" },
                reg_zr(*rd, *w64),
                reg_zr(*rn, *w64),
                reg_zr(*rm, *w64)
            ),
            ShiftVar { w64, shift, rm, rn, rd } => write!(
                f,
                "{}v {}, {}, {}",
                match shift {
                    ShiftType::Lsl => "lsl",
                    ShiftType::Lsr => "lsr",
                    ShiftType::Asr => "asr",
                    ShiftType::Ror => "ror",
                },
                reg_zr(*rd, *w64),
                reg_zr(*rn, *w64),
                reg_zr(*rm, *w64)
            ),
            Rev { w64, op, rn, rd } => {
                let name = match op {
                    RevOp::Rev => "rev",
                    RevOp::Rev16 => "rev16",
                    RevOp::Rev32 => "rev32",
                    RevOp::Clz => "clz",
                };
                write!(f, "{name} {}, {}", reg_zr(*rd, *w64), reg_zr(*rn, *w64))
            }
            CSel { w64, op, cond, rm, rn, rd } => {
                let name = match op {
                    CSelOp::Csel => "csel",
                    CSelOp::Csinc => "csinc",
                    CSelOp::Csinv => "csinv",
                    CSelOp::Csneg => "csneg",
                };
                // CSET/CSETM aliases
                if *rn == 31 && *rm == 31 {
                    if matches!(op, CSelOp::Csinc) {
                        return write!(f, "cset {}, {}", reg_zr(*rd, *w64), cond.invert());
                    }
                    if matches!(op, CSelOp::Csinv) {
                        return write!(f, "csetm {}, {}", reg_zr(*rd, *w64), cond.invert());
                    }
                }
                write!(
                    f,
                    "{name} {}, {}, {}, {cond}",
                    reg_zr(*rd, *w64),
                    reg_zr(*rn, *w64),
                    reg_zr(*rm, *w64)
                )
            }
            Nop => f.write_str("nop"),
            Svc { imm } => write!(f, "svc #0x{imm:x}"),
            Brk { imm } => write!(f, "brk #0x{imm:x}"),
        }
    }
}

fn shift_suffix(shift: ShiftType, amt: u8) -> String {
    if amt == 0 && shift == ShiftType::Lsl {
        String::new()
    } else {
        format!(", {shift} #{amt}")
    }
}

fn memop_name(size: u8, op: LdStOp) -> &'static str {
    match (op, size) {
        (LdStOp::Store, 1) => "strb",
        (LdStOp::Store, 2) => "strh",
        (LdStOp::Store, 4) => "str",
        (LdStOp::Store, 8) => "str",
        (LdStOp::LoadZ, 1) => "ldrb",
        (LdStOp::LoadZ, 2) => "ldrh",
        (LdStOp::LoadZ, 4) => "ldr",
        (LdStOp::LoadZ, 8) => "ldr",
        (LdStOp::LoadS64, 1) => "ldrsb",
        (LdStOp::LoadS64, 2) => "ldrsh",
        (LdStOp::LoadS64, 4) => "ldrsw",
        (LdStOp::LoadS32, 1) => "ldrsb",
        (LdStOp::LoadS32, 2) => "ldrsh",
        _ => "ldr?",
    }
}
