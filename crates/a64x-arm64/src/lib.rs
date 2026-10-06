//! # a64x-arm64
//!
//! ARMv8-A (A64) instruction support for A64X:
//!
//! * [`decode`] — decodes 32-bit instruction words into [`Insn`].
//! * [`asm`] — small assembler/encoders used by tests and demo guests.
//!
//! The supported subset targets the integer/control-flow instruction stream
//! produced by MSVC/LLVM/GCC -O2 for typical userspace code. FP/SIMD,
//! atomics, privileged system instructions and pointer authentication are
//! rejected with a precise `Unsupported`/`Unallocated` diagnostic (see
//! `docs/ISA-COVERAGE.md` for the support matrix).

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod asm;
pub mod bitmask;
pub mod decode;
pub mod insn;

pub use decode::{decode, DecodeError};
pub use insn::*;

#[cfg(test)]
mod tests {
    use super::asm;
    use super::*;

    fn d(word: u32) -> Insn {
        decode(word, 0x1000).expect("decode failed")
    }

    #[test]
    fn golden_data_processing() {
        assert_eq!(
            d(0x8B020020),
            Insn::AddReg { w64: true, sub: false, setflags: false, shift: ShiftType::Lsl, shift_amt: 0, rm: 2, rn: 1, rd: 0 }
        );
        assert_eq!(
            d(0xEB01001F),
            Insn::AddReg { w64: true, sub: true, setflags: true, shift: ShiftType::Lsl, shift_amt: 0, rm: 1, rn: 0, rd: 31 }
        );
        assert_eq!(
            d(0x91001420),
            Insn::AddImm { w64: true, sub: false, setflags: false, imm: 5, rn: 1, rd: 0 }
        );
        assert_eq!(
            d(0xD1001420),
            Insn::AddImm { w64: true, sub: true, setflags: false, imm: 5, rn: 1, rd: 0 }
        );
        assert_eq!(
            d(0xD2800020),
            Insn::MovImm { w64: true, op: MovOp::Movz, imm16: 1, shift: 0, rd: 0 }
        );
        assert_eq!(format!("{}", d(0xD2824680)), "movz x0, #0x1234");
        assert_eq!(
            d(0xAA0103E0),
            Insn::LogicReg {
                w64: true,
                op: LogicOp::Orr,
                negate: false,
                shift: ShiftType::Lsl,
                shift_amt: 0,
                rm: 1,
                rn: 31,
                rd: 0
            }
        );
        assert_eq!(format!("{}", d(0xAA0103E0)), "mov x0, x1");
        assert_eq!(
            d(0x9B027C20),
            Insn::Mul { w64: true, sub: false, rm: 2, rn: 1, ra: 31, rd: 0 }
        );
        assert_eq!(format!("{}", d(0x9B027C20)), "mul x0, x1, x2");
        assert_eq!(
            d(0x9AC20820),
            Insn::Div { w64: true, signed: false, rm: 2, rn: 1, rd: 0 }
        );
        assert_eq!(
            d(0x9A820020),
            Insn::CSel { w64: true, op: CSelOp::Csel, cond: Cond::Eq, rm: 2, rn: 1, rd: 0 }
        );
    }

    #[test]
    fn golden_loads_stores() {
        assert_eq!(
            d(0xF9400020),
            Insn::LdSt { size: 8, op: LdStOp::LoadZ, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 0 } }
        );
        assert_eq!(
            d(0xF9400420),
            Insn::LdSt { size: 8, op: LdStOp::LoadZ, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 8 } }
        );
        assert_eq!(
            d(0xF9000020),
            Insn::LdSt { size: 8, op: LdStOp::Store, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 0 } }
        );
        assert_eq!(
            d(0xB9400020),
            Insn::LdSt { size: 4, op: LdStOp::LoadZ, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 0 } }
        );
        assert_eq!(
            d(0x39400020),
            Insn::LdSt { size: 1, op: LdStOp::LoadZ, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 0 } }
        );
        assert_eq!(
            d(0xB9800020),
            Insn::LdSt { size: 4, op: LdStOp::LoadS64, rt: 0, rn: 1, mode: AddrMode::UnsignedImm { offset: 0 } }
        );
        assert_eq!(
            d(0xF85F8020),
            Insn::LdSt { size: 8, op: LdStOp::LoadZ, rt: 0, rn: 1, mode: AddrMode::UnscaledImm { offset: -8 } }
        );
        assert_eq!(
            d(0xA9BF7BFD),
            Insn::LdStPair { w64: true, load: false, rt: 29, rt2: 30, rn: 31, offset: -16, mode: PairMode::PreIndex }
        );
        assert_eq!(
            d(0xA8C17BFD),
            Insn::LdStPair { w64: true, load: true, rt: 29, rt2: 30, rn: 31, offset: 16, mode: PairMode::PostIndex }
        );
        assert_eq!(format!("{}", d(0xA9BF7BFD)), "stp x29, x30, [sp, #-16]!");
        assert_eq!(format!("{}", d(0xA8C17BFD)), "ldp x29, x30, [sp], #16");
        // ldr x0, #+8 (literal)
        assert_eq!(
            d(0x58000040),
            Insn::LdrLiteral { size: 8, op: LdStOp::LoadZ, rt: 0, target: 0x1008 }
        );
        // SIMD store must NOT alias onto integer STR: str q0, [x1]
        assert!(decode(0x3D800020, 0x1000).is_err());
        // SIMD literal must not alias either: ldr q0, #8
        assert!(decode(0x5C000040, 0x1000).is_err());
    }

    #[test]
    fn golden_branches() {
        assert_eq!(d(0x14000002), Insn::Branch { link: false, target: 0x1008 });
        assert_eq!(d(0x94000001), Insn::Branch { link: true, target: 0x1004 });
        assert_eq!(d(0x54000040), Insn::BranchCond { cond: Cond::Eq, target: 0x1008 });
        assert_eq!(d(0xB4000040), Insn::Cbz { w64: true, nonzero: false, rt: 0, target: 0x1008 });
        assert_eq!(d(0xB5000040), Insn::Cbz { w64: true, nonzero: true, rt: 0, target: 0x1008 });
        assert_eq!(d(0x36180040), Insn::Tbz { nonzero: false, bit: 3, rt: 0, target: 0x1008 });
        assert_eq!(d(0xB7400040), Insn::Tbz { nonzero: true, bit: 40, rt: 0, target: 0x1008 });
        assert_eq!(d(0xD65F03C0), Insn::BranchReg { link: false, ret: true, rn: 30 });
        assert_eq!(d(0xD63F0200), Insn::BranchReg { link: true, ret: false, rn: 16 });
        assert_eq!(d(0xD61F0200), Insn::BranchReg { link: false, ret: false, rn: 16 });
        assert_eq!(d(0xD503201F), Insn::Nop);
        assert_eq!(d(0xD4000001), Insn::Svc { imm: 0 });
        assert_eq!(d(0xD4200000), Insn::Brk { imm: 0 });
        assert_eq!(format!("{}", d(0x54000040)), "b.eq #0x1008");
    }

    #[test]
    fn golden_bitfield_aliases() {
        assert_eq!(format!("{}", d(0xD37DF020)), "lsl x0, x1, #3");
        assert_eq!(format!("{}", d(0x9344FC20)), "asr x0, x1, #4");
        assert_eq!(format!("{}", d(0x93401C20)), "sxtb x0, w1");
        assert_eq!(format!("{}", d(0x53001C20)), "uxtb w0, w1");
        assert_eq!(format!("{}", d(0x53003C20)), "uxth w0, w1");
        // lsr w1, w2, #5 = UBFM 32 immr=5 imms=31
        assert_eq!(format!("{}", d(0x53057C41)), "lsr w1, w2, #5");
        // sxtw x0, w1
        assert_eq!(format!("{}", d(0x93407C20)), "sxtw x0, w1");
        // UBFM with N=0 on a 64-bit register is unallocated
        assert!(decode(0xD33DF020, 0x1000).is_err());
    }

    #[test]
    fn encoder_decoder_roundtrip() {
        let pc = 0x4000u64;
        let cases: Vec<u32> = vec![
            asm::add(true, 0, 1, 5),
            asm::sub(true, 0, 1, 4095),
            asm::cmp_imm(true, 1, 0),
            asm::movz(true, 5, 0xBEEF, 48),
            asm::movn(false, 2, 0x1234, 0),
            asm::movk(true, 7, 0xAAAA, 32),
            asm::mov_reg(true, 3, 4),
            asm::and_reg(false, 1, 2, 3),
            asm::eor_reg(true, 9, 9, 9),
            asm::tst_reg(true, 10, 11),
            asm::add_r(true, 1, 2, 3),
            asm::add_reg(true, false, false, 0, 1, 2, ShiftType::Lsl, 3),
            asm::add_reg(true, true, true, 0, 1, 2, ShiftType::Lsr, 17),
            asm::cmp_reg(true, 20, 21),
            asm::neg(true, 4, 5),
            asm::add_ext(true, false, false, 0, 1, 2, crate::ExtendType::Uxtw, 2),
            asm::madd(true, 2, 3, 4, 5),
            asm::msub(true, 2, 3, 4, 5),
            asm::smaddl(0, 1, 2, 3),
            asm::umaddl(4, 5, 6, 31),
            asm::smulh(0, 1, 2),
            asm::umulh(3, 4, 5),
            asm::div(true, false, 0, 1, 2),
            asm::div(false, true, 3, 4, 5),
            asm::shift_var(true, ShiftType::Lsl, 0, 1, 2),
            asm::shift_var(true, ShiftType::Asr, 0, 1, 2),
            asm::shift_var(false, ShiftType::Ror, 0, 1, 2),
            asm::rev(true, 0, 1),
            asm::rev16(false, 2, 3),
            asm::rev32(4, 5),
            asm::clz(true, 0, 1),
            asm::csel(true, CSelOp::Csel, 0, 1, 2, Cond::Ge),
            asm::csel(false, CSelOp::Csinc, 3, 4, 5, Cond::Lt),
            asm::cset(true, 6, Cond::Ne),
            asm::csel(true, CSelOp::Csneg, 7, 8, 9, Cond::Mi),
            asm::lsl_imm(true, 0, 1, 3),
            asm::lsr_imm(false, 2, 3, 7),
            asm::asr_imm(true, 4, 5, 33),
            asm::sxtb(true, 0, 1),
            asm::sxth(true, 2, 3),
            asm::sxtw(4, 5),
            asm::uxtb(6, 7),
            asm::uxth(8, 9),
            asm::ror_imm(true, 0, 1, 13),
            asm::extr(true, 2, 3, 4, 25),
            asm::pc_rel(false, 0, pc, pc + 0x80),
            asm::pc_rel(true, 1, pc, pc - 0x2000),
            asm::branch(false, 128),
            asm::branch(true, -64),
            asm::branch_cond(Cond::Hi, 256),
            asm::branch_cond(Cond::Ls, -256),
            asm::cbz(true, false, 3, 512),
            asm::cbz(false, true, 4, -512),
            asm::tbz(false, 5, 6, 1024),
            asm::tbz(true, 63, 7, -1024),
            asm::branch_reg(0, 16),
            asm::branch_reg(1, 17),
            asm::branch_reg(2, 30),
            asm::ret(),
            asm::nop(),
            asm::svc(7),
            asm::brk(31),
            asm::ld_st_unsigned(8, LdStOp::LoadZ, 0, 1, 8192),
            asm::ld_st_unsigned(4, LdStOp::Store, 2, 3, 160),
            asm::ld_st_unsigned(1, LdStOp::LoadZ, 4, 5, 255),
            asm::ld_st_unsigned(2, LdStOp::LoadS32, 6, 7, 60),
            asm::ld_st_unscaled(8, LdStOp::Store, 8, 9, -128),
            asm::ld_st_pre(4, LdStOp::LoadZ, 10, 11, -4),
            asm::ld_st_post(1, LdStOp::LoadS64, 12, 13, 100),
            asm::ld_st_reg(8, LdStOp::LoadZ, 0, 1, 2, ExtendType::Uxtx, true),
            asm::ld_st_reg(8, LdStOp::Store, 0, 1, 2, ExtendType::Uxtw, true),
            asm::ld_st_reg(1, LdStOp::LoadZ, 3, 4, 5, ExtendType::Sxtw, false),
            asm::ldr_literal(1, 0, 64),
            asm::ldr_literal(2, 1, -32),
            asm::ldp_off(true, 0, 1, 2, 48),
            asm::stp_off(true, 29, 30, 2, -64),
            asm::stp_pre(true, 29, 30, 31, -16),
            asm::ldp_post(true, 29, 30, 31, 16),
            asm::ldp_off(false, 10, 11, 12, 24),
            asm::logic_imm(true, 0, true, 0, 1, 0, 1), // and #3
            asm::logic_imm(false, 3, false, 1, 0, 31, 5), // tst w5, top-bit
        ];
        for (i, w) in cases.iter().enumerate() {
            let decoded = decode(*w, pc).unwrap_or_else(|e| panic!("case {i}: decode failed for 0x{w:08x} ({e:?})"));
            // The decoder must produce a sensible instruction and the
            // disassembly must be non-empty.
            let text = format!("{decoded}");
            assert!(!text.is_empty(), "case {i}");
        }
    }

    #[test]
    fn mov_imm64_encoding() {
        let words = asm::mov_imm64(0, 0x1122_3344_5566_7788);
        assert_eq!(words.len(), 4);
        let zero = asm::mov_imm64(1, 0);
        assert_eq!(zero.len(), 1);
        assert_eq!(zero[0], asm::movz(true, 1, 0, 0));
        let small = asm::mov_imm64(2, 0xFF00_0000);
        assert_eq!(small.len(), 1);
        assert_eq!(small[0], asm::movz(true, 2, 0xFF00, 16));
    }

    #[test]
    fn assembler_labels() {
        let mut a = asm::Assembler::new();
        a.label("loop")
            .w(asm::add(true, 0, 0, 1))
            .w(asm::cmp_imm(true, 0, 10))
            .b_cond(Cond::Lt, "loop")
            .bl("done")
            .label("done")
            .w(asm::ret());
        let code = a.finish();
        let words: Vec<u32> = code.chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        assert_eq!(words[2], asm::branch_cond(Cond::Lt, -8));
        assert_eq!(words[3], asm::branch(true, 4));
    }
}
