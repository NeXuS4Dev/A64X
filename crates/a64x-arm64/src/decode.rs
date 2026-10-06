//! The A64 instruction decoder (integer / control-flow subset).
//!
//! `decode()` is a pure function from a 32-bit instruction word and its
//! address (needed to resolve PC-relative targets at translation time).
//! Encodings follow ARM DDI 0487; group masks are annotated per class.

use crate::bitmask::{decode_bitfield_masks, decode_logical_imm};
use crate::insn::*;

/// Why a 32-bit word could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The encoding is architecturally unallocated.
    Unallocated,
    /// Valid encoding that A64X does not translate yet
    /// (FP/SIMD, atomics, system registers, ...).
    Unsupported,
}

/// Sign-extend `bits`-wide `x` to 64 bits.
#[inline]
fn sext(x: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((x << shift) as i64) >> shift
}

#[inline]
fn rd(w: u32) -> u8 {
    (w & 0x1F) as u8
}
#[inline]
fn rn(w: u32) -> u8 {
    ((w >> 5) & 0x1F) as u8
}
#[inline]
fn rm(w: u32) -> u8 {
    ((w >> 16) & 0x1F) as u8
}

/// Decode one instruction at address `pc`.
pub fn decode(word: u32, pc: u64) -> Result<Insn, DecodeError> {
    // Top-level map on bits [28:25].
    let op1 = (word >> 25) & 0xF;
    match op1 {
        0b1000 | 0b1001 => decode_dp_imm(word, pc),
        0b1010 | 0b1011 => decode_branch_system(word, pc),
        o if (o & 0b0111) == 0b0100 => decode_ldst(word, pc),
        o if (o & 0b0111) == 0b0101 => decode_dp_reg(word),
        // 0bx111: scalar FP/SIMD — out of translator scope (v1).
        o if (o & 0b0111) == 0b0111 => Err(DecodeError::Unsupported),
        _ => Err(DecodeError::Unallocated),
    }
}

// --------------------------------------------------------------------------
// Data processing — immediate
// --------------------------------------------------------------------------
fn decode_dp_imm(w: u32, pc: u64) -> Result<Insn, DecodeError> {
    // PC-relative addressing: op(31) immlo(30:29) 10000 immhi(23:5) rd
    if (w & 0x1F00_0000) == 0x1000_0000 {
        let page = w >> 31 != 0;
        let immlo = ((w >> 29) & 3) as u64;
        let immhi = ((w >> 5) & 0x7FFFF) as u64;
        let imm = sext((immhi << 2) | immlo, 21);
        return Ok(Insn::PcRel { page, addr: 0, rd: rd(w) }.with_pc(imm, pc, page));
    }

    // ADD/SUB (immediate): sf op S 100010 sh imm12 rn rd
    // (mask includes bit23 so ADDG/SUBG — MTE — are rejected)
    if (w & 0x1F80_0000) == 0x1100_0000 {
        let sf = w >> 31 != 0;
        let sub = (w >> 30) & 1 != 0;
        let setflags = (w >> 29) & 1 != 0;
        let sh = (w >> 22) & 1;
        let imm12 = ((w >> 10) & 0xFFF) as u32;
        let imm = if sh == 1 { imm12 << 12 } else { imm12 };
        return Ok(Insn::AddImm { w64: sf, sub, setflags, imm, rn: rn(w), rd: rd(w) });
    }

    // Logical (immediate): sf opc 100100 N immr imms rn rd
    if (w & 0x1F80_0000) == 0x1200_0000 {
        let sf = w >> 31 != 0;
        let opc = ((w >> 29) & 3) as u8;
        let n = (w >> 22) & 1 != 0;
        let immr = ((w >> 16) & 0x3F) as u8;
        let imms = ((w >> 10) & 0x3F) as u8;
        let width = if sf { 64 } else { 32 };
        if !sf && n {
            return Err(DecodeError::Unallocated);
        }
        let mask = decode_logical_imm(n, immr, imms, width).ok_or(DecodeError::Unallocated)?;
        let op = match opc {
            0 => LogicOp::And,
            1 => LogicOp::Orr,
            2 => LogicOp::Eor,
            _ => LogicOp::Ands,
        };
        return Ok(Insn::LogicImm { w64: sf, op, mask, rn: rn(w), rd: rd(w) });
    }

    // Move wide: sf opc 100101 hw imm16 rd
    if (w & 0x1F80_0000) == 0x1280_0000 {
        let sf = w >> 31 != 0;
        let opc = ((w >> 29) & 3) as u8;
        let hw = ((w >> 21) & 3) as u8;
        let imm16 = ((w >> 5) & 0xFFFF) as u16;
        let (op, ok) = match opc {
            0 => (MovOp::Movn, true),
            2 => (MovOp::Movz, true),
            3 => (MovOp::Movk, true),
            _ => (MovOp::Movz, false),
        };
        if !ok || (!sf && hw > 1) {
            return Err(DecodeError::Unallocated);
        }
        return Ok(Insn::MovImm { w64: sf, op, imm16, shift: hw * 16, rd: rd(w) });
    }

    // Bitfield: sf opc 100110 N immr imms rn rd
    if (w & 0x1F80_0000) == 0x1300_0000 {
        let sf = w >> 31 != 0;
        let opc = ((w >> 29) & 3) as u8;
        let n = (w >> 22) & 1 != 0;
        let immr = ((w >> 16) & 0x3F) as u8;
        let imms = ((w >> 10) & 0x3F) as u8;
        let width = if sf { 64 } else { 32 };
        if n != sf || opc == 3 {
            return Err(DecodeError::Unallocated);
        }
        if decode_bitfield_masks(n, immr, imms, width).is_none() {
            return Err(DecodeError::Unallocated);
        }
        let op = match opc {
            0 => BfOp::Sbfm,
            1 => BfOp::Bfm,
            _ => BfOp::Ubfm,
        };
        return Ok(Insn::Bitfield { w64: sf, op, immr, imms, rn: rn(w), rd: rd(w) });
    }

    // Extract: sf 00 100111 N o0 rm imms rn rd  (bit30 = 0, bit21 = 0)
    if (w & 0x1F80_0000) == 0x1380_0000 {
        let sf = w >> 31 != 0;
        let n = (w >> 22) & 1 != 0;
        let o0 = (w >> 21) & 1 != 0;
        let imms = ((w >> 10) & 0x3F) as u8;
        if n != sf || o0 {
            return Err(DecodeError::Unallocated);
        }
        if !sf && imms >= 32 {
            return Err(DecodeError::Unallocated);
        }
        return Ok(Insn::Extract { w64: sf, lsb: imms, rm: rm(w), rn: rn(w), rd: rd(w) });
    }

    Err(DecodeError::Unallocated)
}

// --------------------------------------------------------------------------
// Branches, exception generation, system
// --------------------------------------------------------------------------
fn decode_branch_system(w: u32, pc: u64) -> Result<Insn, DecodeError> {
    // Unconditional branch (register): BR/BLR/RET — exact patterns with rn.
    if (w & 0xFFFF_FC1F) == 0xD61F_0000 {
        return Ok(Insn::BranchReg { link: false, ret: false, rn: rn(w) });
    }
    if (w & 0xFFFF_FC1F) == 0xD63F_0000 {
        return Ok(Insn::BranchReg { link: true, ret: false, rn: rn(w) });
    }
    if (w & 0xFFFF_FC1F) == 0xD65F_0000 {
        return Ok(Insn::BranchReg { link: false, ret: true, rn: rn(w) });
    }

    // Exception generation.
    match w & 0xFFE0_001F {
        0xD400_0001 => return Ok(Insn::Svc { imm: ((w >> 5) & 0xFFFF) as u16 }),
        0xD420_0000 => return Ok(Insn::Brk { imm: ((w >> 5) & 0xFFFF) as u16 }),
        _ => {}
    }

    // Hints and barriers — treated as NOP under A64X's memory model.
    if (w & 0xFFFF_F01F) == 0xD503_201F {
        // NOP / YIELD / WFE / WFI / SEV / SEVL (rd == 31, CRm any).
        return Ok(Insn::Nop);
    }
    if (w & 0xFFFF_F0FF) == 0xD503_305F
        || (w & 0xFFFF_F0FF) == 0xD503_309F
        || (w & 0xFFFF_F0FF) == 0xD503_30BF
        || (w & 0xFFFF_F0FF) == 0xD503_30DF
    {
        // CLREX / DSB / DMB / ISB — no-op for the translator (v1: no
        // multi-threaded weakly-ordered guest interaction).
        return Ok(Insn::Nop);
    }

    // Conditional branch (immediate): 0101010 0 imm19 0 cond
    if (w & 0xFF00_0010) == 0x5400_0000 {
        let imm19 = ((w >> 5) & 0x7FFFF) as u64;
        let target = (pc as i64).wrapping_add(sext(imm19, 19) << 2) as u64;
        let cond = Cond::from_bits((w & 0xF) as u8);
        return Ok(Insn::BranchCond { cond, target });
    }

    // Unconditional branch (immediate): op 000101 imm26
    if (w & 0x7C00_0000) == 0x1400_0000 {
        let link = w >> 31 != 0;
        let imm26 = (w & 0x3FF_FFFF) as u64;
        let target = (pc as i64).wrapping_add(sext(imm26, 26) << 2) as u64;
        return Ok(Insn::Branch { link, target });
    }

    // Compare & branch: sf 011010 op imm19 rt
    if (w & 0x7E00_0000) == 0x3400_0000 {
        let sf = w >> 31 != 0;
        let nonzero = (w >> 24) & 1 != 0;
        let imm19 = ((w >> 5) & 0x7FFFF) as u64;
        let target = (pc as i64).wrapping_add(sext(imm19, 19) << 2) as u64;
        return Ok(Insn::Cbz { w64: sf, nonzero, rt: rd(w), target });
    }

    // Test & branch: b5 011011 op b40 imm14 rt
    if (w & 0x7E00_0000) == 0x3600_0000 {
        let b5 = ((w >> 31) & 1) as u8;
        let nonzero = (w >> 24) & 1 != 0;
        let b40 = ((w >> 19) & 0x1F) as u8;
        let bit = b5 << 5 | b40;
        let imm14 = ((w >> 5) & 0x3FFF) as u64;
        let target = (pc as i64).wrapping_add(sext(imm14, 14) << 2) as u64;
        return Ok(Insn::Tbz { nonzero, bit, rt: rd(w), target });
    }

    // MRS/MSR/SYS hints land here — not supported in v1.
    Err(DecodeError::Unsupported)
}

// --------------------------------------------------------------------------
// Loads and stores
// --------------------------------------------------------------------------
fn decode_ldst(w: u32, pc: u64) -> Result<Insn, DecodeError> {
    // LDR (literal) / PRFM (literal): opc 011 V 00 imm19 rt
    if (w & 0x3F00_0000) == 0x1800_0000 {
        let opc = ((w >> 30) & 3) as u8;
        let imm19 = ((w >> 5) & 0x7FFFF) as u64;
        let target = (pc as i64).wrapping_add(sext(imm19, 19) << 2) as u64;
        return match opc {
            0 => Ok(Insn::LdrLiteral { size: 4, op: LdStOp::LoadZ, rt: rd(w), target }),
            1 => Ok(Insn::LdrLiteral { size: 8, op: LdStOp::LoadZ, rt: rd(w), target }),
            2 => Ok(Insn::LdrLiteral { size: 4, op: LdStOp::LoadS64, rt: rd(w), target }),
            _ => Ok(Insn::Nop), // PRFM — prefetch is a NOP for us
        };
    }

    // Load/store register pair: opc 101 V 0 L imm7 rt2 rn rt
    if (w & 0x3E00_0000) == 0x2800_0000 {
        let opc = ((w >> 30) & 3) as u8;
        let load = (w >> 22) & 1 != 0;
        let mode = match (w >> 23) & 3 {
            0 => PairMode::SignedOffset,
            1 => PairMode::PostIndex,
            2 => PairMode::Offset,
            _ => PairMode::PreIndex,
        };
        let imm7 = sext(((w >> 15) & 0x7F) as u64, 7);
        let (w64, scale) = match opc {
            0 => (false, 2),
            2 => (true, 3),
            // opc 01/03 with V=0 are not valid integer forms (01=SIMD? no —
            // 01 is 128-bit SIMD when V=1; with V=0 it is unallocated).
            _ => return Err(DecodeError::Unallocated),
        };
        let offset = (imm7 << scale) as i32;
        let rt2 = ((w >> 10) & 0x1F) as u8;
        return Ok(Insn::LdStPair { w64, load, rt: rd(w), rt2, rn: rn(w), offset, mode });
    }

    // Load/store register (register offset):
    // size 111 V 0 opc 1 Rm option S 10 Rn Rt
    if (w & 0x3F20_0C00) == 0x3820_0800 {
        let size_bits = ((w >> 30) & 3) as u8;
        let opc = ((w >> 22) & 3) as u8;
        let option = ((w >> 13) & 7) as u8;
        let s = (w >> 12) & 1;
        let size = 1u8 << size_bits;
        let op = ldst_op(size_bits, opc)?;
        let extend = ExtendType::from_bits(option);
        let shift = if s == 1 { size_bits } else { 0 };
        return Ok(Insn::LdSt {
            size,
            op,
            rt: rd(w),
            rn: rn(w),
            mode: AddrMode::RegOffset { rm: rm(w), extend, shift },
        });
    }

    // Load/store register (unscaled/post/pre/unprivileged immediate):
    // size 111 V 0 opc 0 imm9 mode 2 Rn Rt
    if (w & 0x3F00_0000) == 0x3800_0000 {
        let size_bits = ((w >> 30) & 3) as u8;
        let opc = ((w >> 22) & 3) as u8;
        let imm9 = sext(((w >> 12) & 0x1FF) as u64, 9) as i32;
        let mode_bits = (w >> 10) & 3;
        let size = 1u8 << size_bits;
        let op = ldst_op(size_bits, opc)?;
        let mode = match mode_bits {
            0 => AddrMode::UnscaledImm { offset: imm9 },
            1 => AddrMode::PostIndex { offset: imm9 },
            2 => return Err(DecodeError::Unsupported), // LDTR/STTR
            _ => AddrMode::PreIndex { offset: imm9 },
        };
        return Ok(Insn::LdSt { size, op, rt: rd(w), rn: rn(w), mode });
    }

    // Load/store register (unsigned immediate):
    // size 111 V 0 opc 1 imm12 Rn Rt
    if (w & 0x3F00_0000) == 0x3900_0000 {
        let size_bits = ((w >> 30) & 3) as u8;
        let opc = ((w >> 22) & 3) as u8;
        let imm12 = ((w >> 10) & 0xFFF) as u32;
        let size = 1u8 << size_bits;
        let op = ldst_op(size_bits, opc)?;
        let offset = imm12 << size_bits;
        return Ok(Insn::LdSt { size, op, rt: rd(w), rn: rn(w), mode: AddrMode::UnsignedImm { offset } });
    }

    // Atomics / load-exclusive / load-acquire — multi-threaded v1 skips them
    // with an explicit diagnostic.
    Err(DecodeError::Unsupported)
}

/// Map (size, opc) to the scalar operation; rejects unallocated combos.
fn ldst_op(size_bits: u8, opc: u8) -> Result<LdStOp, DecodeError> {
    match opc {
        0 => Ok(LdStOp::Store),
        1 => Ok(LdStOp::LoadZ),
        2 => {
            if size_bits == 3 {
                Err(DecodeError::Unallocated)
            } else {
                Ok(LdStOp::LoadS64)
            }
        }
        _ => {
            if size_bits >= 2 {
                Err(DecodeError::Unallocated)
            } else {
                Ok(LdStOp::LoadS32)
            }
        }
    }
}

// --------------------------------------------------------------------------
// Data processing — register
// --------------------------------------------------------------------------
fn decode_dp_reg(w: u32) -> Result<Insn, DecodeError> {
    // Logical (shifted register): sf opc 01010 shift N rm imm6 rn rd
    if (w & 0x1F00_0000) == 0x0A00_0000 {
        let sf = w >> 31 != 0;
        let opc = ((w >> 29) & 3) as u8;
        let shift = ShiftType::from_u2(((w >> 22) & 3) as u8);
        let negate = (w >> 21) & 1 != 0;
        let imm6 = ((w >> 10) & 0x3F) as u8;
        if !sf && imm6 >= 32 {
            return Err(DecodeError::Unallocated);
        }
        let op = match opc {
            0 => LogicOp::And,
            1 => LogicOp::Orr,
            2 => LogicOp::Eor,
            _ => LogicOp::Ands,
        };
        return Ok(Insn::LogicReg {
            w64: sf,
            op,
            negate,
            shift,
            shift_amt: imm6,
            rm: rm(w),
            rn: rn(w),
            rd: rd(w),
        });
    }

    // Add/subtract (shifted register): sf op S 01011 shift 0 rm imm6 rn rd
    if (w & 0x1F20_0000) == 0x0B00_0000 {
        let sf = w >> 31 != 0;
        let sub = (w >> 30) & 1 != 0;
        let setflags = (w >> 29) & 1 != 0;
        let shift_bits = ((w >> 22) & 3) as u8;
        if shift_bits == 3 {
            return Err(DecodeError::Unallocated); // no ROR here
        }
        let imm6 = ((w >> 10) & 0x3F) as u8;
        if !sf && imm6 >= 32 {
            return Err(DecodeError::Unallocated);
        }
        return Ok(Insn::AddReg {
            w64: sf,
            sub,
            setflags,
            shift: ShiftType::from_u2(shift_bits),
            shift_amt: imm6,
            rm: rm(w),
            rn: rn(w),
            rd: rd(w),
        });
    }

    // Add/subtract (extended register): sf op S 01011 00 1 rm option imm3 rn rd
    if (w & 0x1FE0_0000) == 0x0B20_0000 {
        let sf = w >> 31 != 0;
        let sub = (w >> 30) & 1 != 0;
        let setflags = (w >> 29) & 1 != 0;
        let option = ((w >> 13) & 7) as u8;
        let amount = ((w >> 10) & 7) as u8;
        if amount > 4 {
            return Err(DecodeError::Unallocated);
        }
        return Ok(Insn::AddExt {
            w64: sf,
            sub,
            setflags,
            extend: ExtendType::from_bits(option),
            amount,
            rm: rm(w),
            rn: rn(w),
            rd: rd(w),
        });
    }

    // Conditional select: sf op S 11010100 rm cond 00 op2 rn rd
    if (w & 0x1FE0_0000) == 0x1A80_0000 {
        let sf = w >> 31 != 0;
        let op_bit = (w >> 30) & 1 != 0;
        let s_bit = (w >> 29) & 1 != 0;
        let o2 = (w >> 10) & 1 != 0;
        if s_bit {
            return Err(DecodeError::Unallocated);
        }
        let op = match (op_bit, o2) {
            (false, false) => CSelOp::Csel,
            (false, true) => CSelOp::Csinc,
            (true, false) => CSelOp::Csinv,
            (true, true) => CSelOp::Csneg,
        };
        let cond = Cond::from_bits(((w >> 12) & 0xF) as u8);
        return Ok(Insn::CSel { w64: sf, op, cond, rm: rm(w), rn: rn(w), rd: rd(w) });
    }

    // Data-processing (1 source): sf 1 S 11010110 opcode(2)0000 opcode(6) rn rd
    if (w & 0x5FE0_0000) == 0x5AC0_0000 {
        let sf = w >> 31 != 0;
        if (w >> 29) & 1 != 0 {
            return Err(DecodeError::Unallocated);
        }
        let opc2 = ((w >> 16) & 0x1F) as u8;
        let opc6 = ((w >> 10) & 0x3F) as u8;
        if opc2 != 0 {
            return Err(DecodeError::Unsupported);
        }
        return match opc6 {
            // RBIT — rarely used, but cheap to support via software sequence
            // is not: emit a clear "unsupported" diagnostic.
            0 => Err(DecodeError::Unsupported),
            1 => Ok(Insn::Rev { w64: sf, op: RevOp::Rev16, rn: rn(w), rd: rd(w) }),
            2 => Ok(Insn::Rev {
                w64: sf,
                op: if sf { RevOp::Rev32 } else { RevOp::Rev },
                rn: rn(w),
                rd: rd(w),
            }),
            3 if sf => Ok(Insn::Rev { w64: true, op: RevOp::Rev, rn: rn(w), rd: rd(w) }),
            3 => Err(DecodeError::Unallocated),
            4 => Ok(Insn::Rev { w64: sf, op: RevOp::Clz, rn: rn(w), rd: rd(w) }),
            // CLS and everything else: not yet supported.
            _ => Err(DecodeError::Unsupported),
        };
    }

    // Data-processing (2 source): sf 0 S 11010110 rm opcode rn rd
    if (w & 0x5FE0_0000) == 0x1AC0_0000 {
        let sf = w >> 31 != 0;
        if (w >> 29) & 1 != 0 {
            // S=1: CRC32 etc. — unsupported.
            return Err(DecodeError::Unsupported);
        }
        let opc6 = ((w >> 10) & 0x3F) as u8;
        let (rn_, rm_, rd_) = (rn(w), rm(w), rd(w));
        return match opc6 {
            2 => Ok(Insn::Div { w64: sf, signed: false, rm: rm_, rn: rn_, rd: rd_ }),
            3 => Ok(Insn::Div { w64: sf, signed: true, rm: rm_, rn: rn_, rd: rd_ }),
            8 => Ok(Insn::ShiftVar { w64: sf, shift: ShiftType::Lsl, rm: rm_, rn: rn_, rd: rd_ }),
            9 => Ok(Insn::ShiftVar { w64: sf, shift: ShiftType::Lsr, rm: rm_, rn: rn_, rd: rd_ }),
            10 => Ok(Insn::ShiftVar { w64: sf, shift: ShiftType::Asr, rm: rm_, rn: rn_, rd: rd_ }),
            11 => Ok(Insn::ShiftVar { w64: sf, shift: ShiftType::Ror, rm: rm_, rn: rn_, rd: rd_ }),
            _ => Err(DecodeError::Unsupported),
        };
    }

    // Data-processing (3 source): sf op54 11011 op31 rm o0 ra rn rd
    if (w & 0x1F00_0000) == 0x1B00_0000 {
        let sf = w >> 31 != 0;
        let op54 = (w >> 29) & 3;
        if op54 != 0 {
            return Err(DecodeError::Unallocated);
        }
        let op31 = ((w >> 21) & 7) as u8;
        let o0 = (w >> 15) & 1 != 0;
        let (rm_, ra_, rn_, rd_) = (rm(w), ((w >> 10) & 0x1F) as u8, rn(w), rd(w));
        return match op31 {
            0 => Ok(Insn::Mul { w64: sf, sub: o0, rm: rm_, rn: rn_, ra: ra_, rd: rd_ }),
            1 if sf => Ok(Insn::MulLong { signed: true, sub: o0, rm: rm_, rn: rn_, ra: ra_, rd: rd_ }),
            2 if sf && !o0 && ra_ == 31 => Ok(Insn::MulHigh { signed: true, rm: rm_, rn: rn_, rd: rd_ }),
            5 if sf => Ok(Insn::MulLong { signed: false, sub: o0, rm: rm_, rn: rn_, ra: ra_, rd: rd_ }),
            6 if sf && !o0 && ra_ == 31 => Ok(Insn::MulHigh { signed: false, rm: rm_, rn: rn_, rd: rd_ }),
            _ => Err(DecodeError::Unallocated),
        };
    }

    Err(DecodeError::Unsupported)
}

impl ShiftType {
    fn from_u2(v: u8) -> ShiftType {
        match v & 3 {
            0 => ShiftType::Lsl,
            1 => ShiftType::Lsr,
            2 => ShiftType::Asr,
            _ => ShiftType::Ror,
        }
    }
}

impl Insn {
    /// Resolve the absolute target of ADR/ADRP.
    fn with_pc(self, imm: i64, pc: u64, page: bool) -> Insn {
        if let Insn::PcRel { rd, .. } = self {
            let base = if page { pc & !0xFFF } else { pc };
            let addr = (base as i64).wrapping_add(if page { imm << 12 } else { imm }) as u64;
            Insn::PcRel { page, addr, rd }
        } else {
            self
        }
    }
}
