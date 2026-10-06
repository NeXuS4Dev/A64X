//! A small A64 *assembler* — instruction encoders plus a minimal label-
//! resolving code builder. It serves two purposes:
//!
//! 1. unit tests: `decode(encode(x)) == x` round-trips pin the decoder and
//!    the encoders to each other, while golden constants pin both to the
//!    real architecture;
//! 2. test/demo guests: the runtime integration tests and `a64x demo`
//!    assemble real guest programs without any external toolchain.

use crate::insn::{CSelOp, Cond, ExtendType, LdStOp, PairMode, ShiftType};

#[inline]
fn sf(w64: bool) -> u32 {
    (w64 as u32) << 31
}

// ---------------------------------------------------------------------------
// Data processing — immediate
// ---------------------------------------------------------------------------

/// ADD/SUB (immediate). `imm12` is the *unshifted* 12-bit value, `shift12`
/// selects LSL #12.
pub fn add_imm(w64: bool, sub: bool, setflags: bool, rd: u8, rn: u8, imm12: u16, shift12: bool) -> u32 {
    sf(w64)
        | (sub as u32) << 30
        | (setflags as u32) << 29
        | 0x1100_0000
        | (shift12 as u32) << 22
        | (imm12 as u32 & 0xFFF) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// `add rd, rn, #imm`
pub fn add(w64: bool, rd: u8, rn: u8, imm12: u16) -> u32 {
    add_imm(w64, false, false, rd, rn, imm12, false)
}

/// `sub rd, rn, #imm`
pub fn sub(w64: bool, rd: u8, rn: u8, imm12: u16) -> u32 {
    add_imm(w64, true, false, rd, rn, imm12, false)
}

/// `cmp rn, #imm`
/// `subs rd, rn, #1` with flags set.
pub fn subs_imm1(reg: u8) -> u32 {
    add_imm(true, true, true, reg, reg, 1, false)
}

/// `cmp rn, #imm12` (\`subs xzr, rn, #imm\`).
pub fn cmp_imm(w64: bool, rn: u8, imm12: u16) -> u32 {
    add_imm(w64, true, true, 31, rn, imm12, false)
}

/// MOVN/MOVZ/MOVK raw encoder (`shift` in bits, multiple of 16).
pub fn mov_imm(w64: bool, op: u8, rd: u8, imm16: u16, shift: u8) -> u32 {
    sf(w64)
        | (op as u32) << 29
        | 0x1280_0000
        | ((shift as u32 / 16) & 3) << 21
        | (imm16 as u32) << 5
        | (rd as u32 & 0x1F)
}

/// `movz`
pub fn movz(w64: bool, rd: u8, imm16: u16, shift: u8) -> u32 {
    mov_imm(w64, 2, rd, imm16, shift)
}
/// `movn`
pub fn movn(w64: bool, rd: u8, imm16: u16, shift: u8) -> u32 {
    mov_imm(w64, 0, rd, imm16, shift)
}
/// `movk`
pub fn movk(w64: bool, rd: u8, imm16: u16, shift: u8) -> u32 {
    mov_imm(w64, 3, rd, imm16, shift)
}

/// Materialise a 64-bit constant in EXACTLY four instructions
/// (movz + 3 movk), regardless of the value. Code generators that build
/// two passes with identical layout need this predictable length.
pub fn mov_imm64_fixed(rd: u8, val: u64) -> Vec<u32> {
    vec![
        movz(true, rd, (val & 0xFFFF) as u16, 0),
        movk(true, rd, ((val >> 16) & 0xFFFF) as u16, 16),
        movk(true, rd, ((val >> 32) & 0xFFFF) as u16, 32),
        movk(true, rd, ((val >> 48) & 0xFFFF) as u16, 48),
    ]
}

/// Materialise a 64-bit constant (MOVZ + MOVK chain; at most 4 insns).
pub fn mov_imm64(rd: u8, val: u64) -> Vec<u32> {
    if val == 0 {
        return vec![movz(true, rd, 0, 0)];
    }
    let mut out = Vec::new();
    let mut started = false;
    for i in 0..4 {
        let chunk = (val >> (16 * i)) as u16;
        if chunk != 0 {
            if !started {
                out.push(movz(true, rd, chunk, 16 * i as u8));
                started = true;
            } else {
                out.push(movk(true, rd, chunk, 16 * i as u8));
            }
        }
    }
    out
}

/// Materialise a 32-bit constant into a W register.
pub fn mov_imm32(rd: u8, val: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let lo = val as u16;
    let hi = (val >> 16) as u16;
    out.push(movz(false, rd, lo, 0));
    if hi != 0 {
        out.push(movk(false, rd, hi, 16));
    }
    out
}

/// ORR/AND/EOR/ANDS (immediate) with pre-encoded bitmask fields.
pub fn logic_imm(w64: bool, opc: u8, n: bool, immr: u8, imms: u8, rd: u8, rn: u8) -> u32 {
    sf(w64)
        | (opc as u32) << 29
        | 0x1200_0000
        | (n as u32) << 22
        | (immr as u32 & 0x3F) << 16
        | (imms as u32 & 0x3F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// ADR (page = false) / ADRP (page = true) to absolute `addr` from `pc`.
pub fn pc_rel(page: bool, rd: u8, pc: u64, addr: u64) -> u32 {
    let base = if page { pc & !0xFFF } else { pc };
    let imm = if page { (addr as i64 - base as i64) >> 12 } else { addr as i64 - base as i64 };
    let imm = imm & 0x1F_FFFF;
    (page as u32) << 31 | (((imm as u32 >> 0) & 3) << 29) | 0x1000_0000 | (((imm as u32 >> 2) & 0x7FFFF) << 5) | (rd as u32 & 0x1F)
}

/// SBFM/BFM/UBFM raw encoder.
pub fn bitfield(w64: bool, opc: u8, rd: u8, rn: u8, immr: u8, imms: u8) -> u32 {
    sf(w64)
        | (opc as u32) << 29
        | 0x1300_0000
        | (w64 as u32) << 22
        | (immr as u32 & 0x3F) << 16
        | (imms as u32 & 0x3F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// `lsl rd, rn, #n` (UBFM alias).
pub fn lsl_imm(w64: bool, rd: u8, rn: u8, n: u8) -> u32 {
    let width = if w64 { 64u8 } else { 32 };
    bitfield(w64, 2, rd, rn, width - n, width - 1 - n)
}
/// `lsr rd, rn, #n` (UBFM alias).
pub fn lsr_imm(w64: bool, rd: u8, rn: u8, n: u8) -> u32 {
    let width = if w64 { 64u8 } else { 32 };
    bitfield(w64, 2, rd, rn, n, width - 1)
}
/// `asr rd, rn, #n` (SBFM alias).
pub fn asr_imm(w64: bool, rd: u8, rn: u8, n: u8) -> u32 {
    let width = if w64 { 64u8 } else { 32 };
    bitfield(w64, 0, rd, rn, n, width - 1)
}
/// `sxtb xd, wn` (or 32-bit form when !w64).
pub fn sxtb(w64: bool, rd: u8, rn: u8) -> u32 {
    bitfield(w64, 0, rd, rn, 0, 7)
}
/// `sxth`.
pub fn sxth(w64: bool, rd: u8, rn: u8) -> u32 {
    bitfield(w64, 0, rd, rn, 0, 15)
}
/// `sxtw xd, wn` (64-bit only).
pub fn sxtw(rd: u8, rn: u8) -> u32 {
    bitfield(true, 0, rd, rn, 0, 31)
}
/// `uxtb wd, wn` (32-bit only).
pub fn uxtb(rd: u8, rn: u8) -> u32 {
    bitfield(false, 2, rd, rn, 0, 7)
}
/// `uxth wd, wn` (32-bit only).
pub fn uxth(rd: u8, rn: u8) -> u32 {
    bitfield(false, 2, rd, rn, 0, 15)
}
/// `ror rd, rn, #n` (EXTR alias).
pub fn ror_imm(w64: bool, rd: u8, rn: u8, n: u8) -> u32 {
    extr(w64, rd, rn, rn, n)
}
/// EXTR raw.
pub fn extr(w64: bool, rd: u8, rn: u8, rm: u8, lsb: u8) -> u32 {
    sf(w64)
        | 0x1380_0000
        | (w64 as u32) << 22
        | (rm as u32 & 0x1F) << 16
        | (lsb as u32 & 0x3F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

// ---------------------------------------------------------------------------
// Data processing — register
// ---------------------------------------------------------------------------

/// Logical (shifted register).
pub fn logic_reg(w64: bool, opc: u8, negate: bool, rd: u8, rn: u8, rm: u8, shift: ShiftType, amt: u8) -> u32 {
    sf(w64)
        | (opc as u32) << 29
        | 0x0A00_0000
        | (shift as u32) << 22
        | (negate as u32) << 21
        | (rm as u32 & 0x1F) << 16
        | (amt as u32 & 0x3F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// `orr rd, xzr, rm` — the canonical register MOV.
pub fn mov_reg(w64: bool, rd: u8, rm: u8) -> u32 {
    logic_reg(w64, 1, false, rd, 31, rm, ShiftType::Lsl, 0)
}
/// `and rd, rn, rm`.
pub fn and_reg(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    logic_reg(w64, 0, false, rd, rn, rm, ShiftType::Lsl, 0)
}
/// `orr rd, rn, rm`.
pub fn orr_reg(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    logic_reg(w64, 1, false, rd, rn, rm, ShiftType::Lsl, 0)
}
/// `eor rd, rn, rm`.
pub fn eor_reg(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    logic_reg(w64, 2, false, rd, rn, rm, ShiftType::Lsl, 0)
}
/// `mvn rd, rm` (ORN with XZR).
pub fn mvn(w64: bool, rd: u8, rm: u8) -> u32 {
    logic_reg(w64, 1, true, rd, 31, rm, ShiftType::Lsl, 0)
}
/// `tst rn, rm`.
pub fn tst_reg(w64: bool, rn: u8, rm: u8) -> u32 {
    logic_reg(w64, 3, false, 31, rn, rm, ShiftType::Lsl, 0)
}

/// ADD/SUB (shifted register).
pub fn add_reg(w64: bool, sub: bool, setflags: bool, rd: u8, rn: u8, rm: u8, shift: ShiftType, amt: u8) -> u32 {
    sf(w64)
        | (sub as u32) << 30
        | (setflags as u32) << 29
        | 0x0B00_0000
        | (shift as u32) << 22
        | (rm as u32 & 0x1F) << 16
        | (amt as u32 & 0x3F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// `add rd, rn, rm`.
pub fn add_r(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    add_reg(w64, false, false, rd, rn, rm, ShiftType::Lsl, 0)
}
/// `sub rd, rn, rm`.
pub fn sub_r(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    add_reg(w64, true, false, rd, rn, rm, ShiftType::Lsl, 0)
}
/// `cmp rn, rm`.
pub fn cmp_reg(w64: bool, rn: u8, rm: u8) -> u32 {
    add_reg(w64, true, true, 31, rn, rm, ShiftType::Lsl, 0)
}
/// `neg rd, rm`.
pub fn neg(w64: bool, rd: u8, rm: u8) -> u32 {
    add_reg(w64, true, false, rd, 31, rm, ShiftType::Lsl, 0)
}

/// ADD/SUB (extended register).
pub fn add_ext(w64: bool, sub: bool, setflags: bool, rd: u8, rn: u8, rm: u8, ext: ExtendType, amount: u8) -> u32 {
    sf(w64)
        | (sub as u32) << 30
        | (setflags as u32) << 29
        | 0x0B20_0000
        | (rm as u32 & 0x1F) << 16
        | (ext as u32 & 7) << 13
        | (amount as u32 & 7) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}

/// MADD raw; `mul` is `madd(rd, rn, rm, xzr)`.
pub fn madd(w64: bool, rd: u8, rn: u8, rm: u8, ra: u8) -> u32 {
    sf(w64)
        | 0x1B00_0000
        | (rm as u32 & 0x1F) << 16
        | (ra as u32 & 0x1F) << 10
        | (rn as u32 & 0x1F) << 5
        | (rd as u32 & 0x1F)
}
/// MSUB raw.
pub fn msub(w64: bool, rd: u8, rn: u8, rm: u8, ra: u8) -> u32 {
    madd(w64, rd, rn, rm, ra) | 1 << 15
}
/// `mul rd, rn, rm`.
pub fn mul(w64: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    madd(w64, rd, rn, rm, 31)
}
/// SMADDL (32x32 -> 64 signed multiply-add).
pub fn smaddl(rd: u8, rn: u8, rm: u8, ra: u8) -> u32 {
    0x9B20_0000 | (rm as u32) << 16 | (ra as u32) << 10 | (rn as u32) << 5 | rd as u32
}
/// UMADDL.
pub fn umaddl(rd: u8, rn: u8, rm: u8, ra: u8) -> u32 {
    0x9BA0_0000 | (rm as u32) << 16 | (ra as u32) << 10 | (rn as u32) << 5 | rd as u32
}
/// SMULH.
pub fn smulh(rd: u8, rn: u8, rm: u8) -> u32 {
    0x9B40_7C00 | (rm as u32) << 16 | (rn as u32) << 5 | rd as u32
}
/// UMULH.
pub fn umulh(rd: u8, rn: u8, rm: u8) -> u32 {
    0x9BC0_7C00 | (rm as u32) << 16 | (rn as u32) << 5 | rd as u32
}
/// UDIV/SDIV.
pub fn div(w64: bool, signed: bool, rd: u8, rn: u8, rm: u8) -> u32 {
    sf(w64)
        | 0x1AC0_0000
        | (rm as u32) << 16
        | (if signed { 3u32 } else { 2u32 }) << 10
        | (rn as u32) << 5
        | rd as u32
}
/// LSLV/LSRV/ASRV/RORV — variable shifts.
pub fn shift_var(w64: bool, shift: ShiftType, rd: u8, rn: u8, rm: u8) -> u32 {
    let opc = match shift {
        ShiftType::Lsl => 8,
        ShiftType::Lsr => 9,
        ShiftType::Asr => 10,
        ShiftType::Ror => 11,
    };
    sf(w64) | 0x1AC0_0000 | (rm as u32) << 16 | (opc as u32) << 10 | (rn as u32) << 5 | rd as u32
}
/// Data-processing 1-source raw encoder (`opc6` field).
pub fn rev_op(w64: bool, opc6: u8, rd: u8, rn: u8) -> u32 {
    sf(w64) | 0x5AC0_0000 | (opc6 as u32 & 0x3F) << 10 | (rn as u32) << 5 | rd as u32
}
/// `rev wd/ xd` — byte reverse of the whole register.
pub fn rev(w64: bool, rd: u8, rn: u8) -> u32 {
    rev_op(w64, if w64 { 3 } else { 2 }, rd, rn)
}
/// `rev16` — byte reverse within 16-bit elements.
pub fn rev16(w64: bool, rd: u8, rn: u8) -> u32 {
    rev_op(w64, 1, rd, rn)
}
/// `rev32 xd, xn` — byte reverse within 32-bit elements (64-bit regs).
pub fn rev32(rd: u8, rn: u8) -> u32 {
    rev_op(true, 2, rd, rn)
}
/// `clz`.
pub fn clz(w64: bool, rd: u8, rn: u8) -> u32 {
    rev_op(w64, 4, rd, rn)
}
/// CSINC/CSEL family.
pub fn csel(w64: bool, op: CSelOp, rd: u8, rn: u8, rm: u8, cond: Cond) -> u32 {
    let (op_bit, o2) = match op {
        CSelOp::Csel => (0u32, 0u32),
        CSelOp::Csinc => (0, 1),
        CSelOp::Csinv => (1, 0),
        CSelOp::Csneg => (1, 1),
    };
    sf(w64)
        | (op_bit as u32) << 30
        | 0x1A80_0000
        | (rm as u32) << 16
        | (cond as u32) << 12
        | (o2 as u32) << 10
        | (rn as u32) << 5
        | rd as u32
}
/// `cset rd, cond` (CSINC with XZR/XZR, inverted condition).
pub fn cset(w64: bool, rd: u8, cond: Cond) -> u32 {
    csel(w64, CSelOp::Csinc, rd, 31, 31, cond.invert())
}

// ---------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------

fn size_bits(size: u8) -> u32 {
    match size {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => panic!("bad size"),
    }
}

fn opc_bits(op: LdStOp) -> u32 {
    match op {
        LdStOp::Store => 0,
        LdStOp::LoadZ => 1,
        LdStOp::LoadS64 => 2,
        LdStOp::LoadS32 => 3,
    }
}

/// Unsigned scaled immediate: `ldr/str{,b,h} rt, [rn, #imm]`.
pub fn ld_st_unsigned(size: u8, op: LdStOp, rt: u8, rn: u8, offset: u32) -> u32 {
    (size_bits(size) << 30)
        | 0x3900_0000
        | (opc_bits(op) << 22)
        | ((offset / size as u32) & 0xFFF) << 10
        | (rn as u32) << 5
        | rt as u32
}

/// Unscaled immediate (LDUR/STUR).
pub fn ld_st_unscaled(size: u8, op: LdStOp, rt: u8, rn: u8, offset: i16) -> u32 {
    (size_bits(size) << 30)
        | 0x3800_0000
        | (opc_bits(op) << 22)
        | (((offset as i32) as u32 & 0x1FF) << 12)
        | (rn as u32) << 5
        | rt as u32
}

/// Pre-index: `[rn, #offset]!`.
pub fn ld_st_pre(size: u8, op: LdStOp, rt: u8, rn: u8, offset: i16) -> u32 {
    ld_st_unscaled(size, op, rt, rn, offset) | 0b11 << 10
}

/// Post-index: `[rn], #offset`.
pub fn ld_st_post(size: u8, op: LdStOp, rt: u8, rn: u8, offset: i16) -> u32 {
    ld_st_unscaled(size, op, rt, rn, offset) | 0b01 << 10
}

/// Register offset: `[rn, rm, extend #shift]`.
pub fn ld_st_reg(size: u8, op: LdStOp, rt: u8, rn: u8, rm: u8, ext: ExtendType, shift_scaled: bool) -> u32 {
    (size_bits(size) << 30)
        | 0x3820_0800
        | (opc_bits(op) << 22)
        | (rm as u32) << 16
        | (ext as u32 & 7) << 13
        | (shift_scaled as u32) << 12
        | (rn as u32) << 5
        | rt as u32
}

/// LDR literal with signed byte offset (already scaled, multiple of 4).
pub fn ldr_literal(opc: u8, rt: u8, offset: i32) -> u32 {
    (opc as u32) << 30 | 0x1800_0000 | (((offset >> 2) as u32 & 0x7FFFF) << 5) | rt as u32
}

/// LDP/STP with signed offset, pre or post index.
pub fn pair(w64: bool, load: bool, mode: PairMode, rt: u8, rt2: u8, rn: u8, offset: i32) -> u32 {
    let scale = if w64 { 3 } else { 2 };
    let imm7 = ((offset >> scale) as u32 & 0x7F) << 15;
    (if w64 { 0b10u32 } else { 0 }) << 30
        | 0x2800_0000
        | (mode as u32) << 23
        | (load as u32) << 22
        | imm7
        | (rt2 as u32) << 10
        | (rn as u32) << 5
        | rt as u32
}

/// Convenience: `stp rt, rt2, [rn, #offset]!`.
pub fn stp_pre(w64: bool, rt: u8, rt2: u8, rn: u8, offset: i32) -> u32 {
    pair(w64, false, PairMode::PreIndex, rt, rt2, rn, offset)
}
/// Convenience: `ldp rt, rt2, [rn], #offset`.
pub fn ldp_post(w64: bool, rt: u8, rt2: u8, rn: u8, offset: i32) -> u32 {
    pair(w64, true, PairMode::PostIndex, rt, rt2, rn, offset)
}
/// Convenience: `stp rt, rt2, [rn, #offset]`.
pub fn stp_off(w64: bool, rt: u8, rt2: u8, rn: u8, offset: i32) -> u32 {
    pair(w64, false, PairMode::Offset, rt, rt2, rn, offset)
}
/// Convenience: `ldp rt, rt2, [rn, #offset]`.
pub fn ldp_off(w64: bool, rt: u8, rt2: u8, rn: u8, offset: i32) -> u32 {
    pair(w64, true, PairMode::Offset, rt, rt2, rn, offset)
}

// ---------------------------------------------------------------------------
// Branches & system
// ---------------------------------------------------------------------------

/// `b #offset` / `bl #offset` (byte offset from the instruction).
pub fn branch(link: bool, offset: i32) -> u32 {
    ((link as u32) << 31) | 0x1400_0000 | ((offset >> 2) as u32 & 0x3FF_FFFF)
}
/// `b.cond #offset`.
pub fn branch_cond(cond: Cond, offset: i32) -> u32 {
    0x5400_0000 | (((offset >> 2) as u32 & 0x7FFFF) << 5) | cond as u32
}
/// `cbz` / `cbnz`.
pub fn cbz(w64: bool, nonzero: bool, rt: u8, offset: i32) -> u32 {
    sf(w64) | 0x3400_0000 | (nonzero as u32) << 24 | (((offset >> 2) as u32 & 0x7FFFF) << 5) | rt as u32
}
/// `tbz` / `tbnz`.
pub fn tbz(nonzero: bool, bit: u8, rt: u8, offset: i32) -> u32 {
    (((bit as u32) >> 5) << 31)
        | 0x3600_0000
        | ((nonzero as u32) << 24)
        | (((bit as u32) & 0x1F) << 19)
        | (((offset >> 2) as u32 & 0x3FFF) << 5)
        | rt as u32
}
/// `br rn` / `blr rn` / `ret rn`.
pub fn branch_reg(op: u8, rn: u8) -> u32 {
    match op {
        0 => 0xD61F_0000 | (rn as u32) << 5,   // br
        1 => 0xD63F_0000 | (rn as u32) << 5,   // blr
        _ => 0xD65F_0000 | (rn as u32) << 5,   // ret
    }
}
/// `ret`.
pub fn ret() -> u32 {
    0xD65F_03C0
}
/// `nop`.
pub fn nop() -> u32 {
    0xD503_201F
}
/// `svc #imm`.
pub fn svc(imm: u16) -> u32 {
    0xD400_0001 | (imm as u32) << 5
}
/// `brk #imm`.
pub fn brk(imm: u16) -> u32 {
    0xD420_0000 | (imm as u32) << 5
}

// ---------------------------------------------------------------------------
// Mini assembler with labels
// ---------------------------------------------------------------------------

/// A fixup to a label within the code being built.
enum Fix {
    B { at: usize, link: bool, target: String },
    BCond { at: usize, cond: Cond, target: String },
    Cbz { at: usize, rt: u8, w64: bool, nonzero: bool, target: String },
    Tbz { at: usize, rt: u8, bit: u8, nonzero: bool, target: String },
}

/// A tiny assembler for constructing guest test programs.
#[derive(Default)]
pub struct Assembler {
    words: Vec<u32>,
    labels: Vec<(String, usize)>,
    fixes: Vec<Fix>,
}

impl Assembler {
    /// Create an empty assembler.
    pub fn new() -> Assembler {
        Assembler::default()
    }

    /// Emit one raw instruction word.
    pub fn w(&mut self, word: u32) -> &mut Self {
        self.words.push(word);
        self
    }

    /// Emit a sequence of words (e.g. from [`mov_imm64`]).
    pub fn ws(&mut self, words: &[u32]) -> &mut Self {
        self.words.extend_from_slice(words);
        self
    }

    /// Current position in instructions (words).
    pub fn pos(&self) -> usize {
        self.words.len()
    }

    /// Place a label at the current position.
    pub fn label(&mut self, name: &str) -> &mut Self {
        self.labels.push((name.to_string(), self.words.len()));
        self
    }

    /// `bl label`.
    pub fn bl(&mut self, target: &str) -> &mut Self {
        self.fixes.push(Fix::B { at: self.words.len(), link: true, target: target.into() });
        self.words.push(0);
        self
    }

    /// `b label`.
    pub fn b(&mut self, target: &str) -> &mut Self {
        self.fixes.push(Fix::B { at: self.words.len(), link: false, target: target.into() });
        self.words.push(0);
        self
    }

    /// `b.cond label`.
    pub fn b_cond(&mut self, cond: Cond, target: &str) -> &mut Self {
        self.fixes.push(Fix::BCond { at: self.words.len(), cond, target: target.into() });
        self.words.push(0);
        self
    }

    /// `cbz`/`cbnz label`.
    pub fn cbz_to(&mut self, w64: bool, nonzero: bool, rt: u8, target: &str) -> &mut Self {
        self.fixes.push(Fix::Cbz { at: self.words.len(), rt, w64, nonzero, target: target.into() });
        self.words.push(0);
        self
    }

    /// `tbz`/`tbnz label`.
    pub fn tbz_to(&mut self, nonzero: bool, bit: u8, rt: u8, target: &str) -> &mut Self {
        self.fixes.push(Fix::Tbz { at: self.words.len(), rt, bit, nonzero, target: target.into() });
        self.words.push(0);
        self
    }

    /// Resolve labels and return little-endian machine code.
    pub fn finish(mut self) -> Vec<u8> {
        let mut words = std::mem::take(&mut self.words);
        for fix in std::mem::take(&mut self.fixes) {
            let (at, target_name) = match &fix {
                Fix::B { at, target, .. } => (*at, target),
                Fix::BCond { at, target, .. } => (*at, target),
                Fix::Cbz { at, target, .. } => (*at, target),
                Fix::Tbz { at, target, .. } => (*at, target),
            };
            let to = self
                .labels
                .iter()
                .find(|(name, _)| name == target_name)
                .unwrap_or_else(|| panic!("undefined label {target_name}"))
                .1;
            let off = (to as i32 - at as i32) * 4;
            words[at] = match fix {
                Fix::B { link, .. } => branch(link, off),
                Fix::BCond { cond, .. } => branch_cond(cond, off),
                Fix::Cbz { rt, w64, nonzero, .. } => cbz(w64, nonzero, rt, off),
                Fix::Tbz { rt, bit, nonzero, .. } => tbz(nonzero, bit, rt, off),
            };
        }
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}
