//! Native execution tests: guest A64 programs are translated to x86-64
//! and executed on this very machine. These are the proofs of the
//! "Native Conversion" and "Not an Emulator" pillars — the observed
//! behavior comes from running real generated machine code, not a
//! simulated CPU.

use a64x_arm64::asm::{self, Assembler};
use a64x_arm64::{Cond, ExtendType, LdStOp, ShiftType};
use a64x_core::state::ExitReason;
use a64x_core::Memory;
use a64x_xlat::{Machine, XlatConfig};

const BASE: u64 = 0x1_0000;

fn boot(code: &[u8]) -> Machine {
    let mut mem = Memory::new(1 << 22).expect("guest memory");
    mem.write(BASE, code).expect("load code");
    let mut m = Machine::new(mem, XlatConfig::default()).expect("machine");
    m.state.sp = m.mem.size() - 64;
    m
}

fn run(m: &mut Machine) -> ExitReason {
    m.execute(BASE, 100_000_000).expect("run")
}

fn asm_run(a: Assembler) -> (Machine, ExitReason) {
    let code = a.finish();
    let mut m = boot(&code);
    let r = run(&mut m);
    (m, r)
}

/// `subs x1, x1, #1` (flag-writing).
fn subs1(reg: u8) -> u32 {
    asm::add_imm(true, true, true, reg, reg, 1, false)
}

#[test]
fn arith_and_mov() {
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 5, 0)); // mov x0, #5
    a.w(asm::movz(true, 1, 7, 0)); // mov x1, #7
    a.w(asm::add_r(true, 2, 0, 1)); // add x2, x0, x1
    a.w(asm::sub(true, 3, 2, 3)); // sub x3, x2, #3
    a.w(asm::movn(true, 4, 0, 0)); // mov x4, #-1
    a.w(asm::movk(true, 4, 0xBEEF, 16)); // movk x4, #0xBEEF, lsl #16
    a.w(asm::neg(true, 5, 0)); // neg x5, x0
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[2], 12);
    assert_eq!(m.state.x[3], 9);
    assert_eq!(m.state.x[4], 0xFFFF_FFFF_BEEF_FFFF);
    assert_eq!(m.state.x[5], (-5i64) as u64);
}

#[test]
fn w_ops_zero_extend() {
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 0xFFFF, 16));
    a.w(asm::movk(true, 0, 0xFFFF, 32));
    a.w(asm::movk(true, 0, 0xFFFF, 48));
    a.w(asm::movk(true, 0, 0xFFFF, 0)); // x0 = -1
    a.w(asm::add(true, 0, 0, 1)); // x0 = 0
    a.w(asm::movz(false, 1, 0xFFFF, 16)); // w1 = 0xFFFF_0000, x1 upper = 0
    a.w(asm::add_r(false, 1, 1, 1)); // w1 = 0xFFFE_0000 (wraps in 32, zext)
    a.w(asm::orr_reg(true, 2, 1, 31)); // x2 = x1
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[1], 0xFFFE_0000);
    assert_eq!(m.state.x[2], 0xFFFE_0000);
}

#[test]
fn loop_sum_with_flags() {
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 0, 0)); // x0 = 0 (acc)
    a.w(asm::movz(true, 1, 10, 0)); // x1 = 10 (i)
    a.label("loop");
    a.w(asm::add_r(true, 0, 0, 1)); // acc += i
    a.w(subs1(1));
    a.b_cond(Cond::Ne, "loop");
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[0], 55);
    assert_eq!(m.state.flags[1], 1, "Z set after subs hitting zero");
    assert_eq!(m.state.flags[2], 1, "C set (no borrow)");
    assert_eq!(m.state.insn_count, 2 + 10 * 3 + 1, "incl. the svc");
}

#[test]
fn calls_returns_lr() {
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 3, 0));
    a.bl("double");
    a.bl("double");
    a.bl("double");
    a.w(asm::svc(0));
    a.label("double");
    a.w(asm::add_r(true, 0, 0, 0));
    a.w(asm::ret());
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[0], 24);
}

#[test]
fn memory_ops_all_sizes() {
    let mut a = Assembler::new();
    a.w(asm::sub(true, 9, 31, 32)); // x9 = sp - 32
    a.ws(&asm::mov_imm64(0, 0x0102_0304_0506_0708));
    a.w(asm::ld_st_pre(8, LdStOp::Store, 0, 31, -16)); // str x0, [sp, #-16]!
    a.w(asm::ld_st_unsigned(8, LdStOp::LoadZ, 1, 31, 0)); // ldr x1, [sp]
    a.w(asm::ld_st_post(8, LdStOp::LoadZ, 2, 31, 16)); // ldr x2, [sp], #16
    a.w(asm::movz(true, 0, 0x80FF, 0));
    a.w(asm::ld_st_unsigned(1, LdStOp::Store, 0, 9, 0)); // strb w0, [x9]
    a.w(asm::ld_st_unsigned(2, LdStOp::Store, 0, 9, 2)); // strh w0, [x9, #2]
    a.w(asm::ld_st_unsigned(1, LdStOp::LoadS64, 3, 9, 0)); // ldrsb x3
    a.w(asm::ld_st_unsigned(1, LdStOp::LoadZ, 4, 9, 0)); // ldrb w4
    a.w(asm::ld_st_unsigned(2, LdStOp::LoadS64, 5, 9, 2)); // ldrsh x5
    // extended-register offset addressing: [x9, w6, uxtw #0]
    a.w(asm::movz(true, 6, 3, 0));
    a.w(asm::ld_st_reg(1, LdStOp::LoadZ, 6, 9, 6, ExtendType::Uxtw, false)); // ldrb w6, [x9, w6, uxtw]
    // pairs
    a.w(asm::movz(true, 0, 111, 0));
    a.w(asm::movz(true, 1, 222, 0));
    a.w(asm::stp_pre(true, 0, 1, 31, -16));
    a.w(asm::movz(true, 0, 0, 0));
    a.w(asm::movz(true, 1, 0, 0));
    a.w(asm::ldp_post(true, 0, 1, 31, 16));
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[2], 0x0102_0304_0506_0708);
    assert_eq!(m.state.x[3] as i64, -1, "ldrsb");
    assert_eq!(m.state.x[4], 0xFF);
    assert_eq!(m.state.x[5] as i64, 0x80FFu16 as i16 as i64, "ldrsh");
    assert_eq!(m.state.x[6], 0x80, "byte at offset 3 (little-endian)");
    assert_eq!(m.state.x[0], 111);
    assert_eq!(m.state.x[1], 222);
}

#[test]
fn mul_div_family() {
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 13, 0));
    a.w(asm::movz(true, 1, 7, 0));
    a.w(asm::mul(true, 2, 0, 1)); // 91
    a.w(asm::movz(true, 3, 5, 0));
    a.w(asm::madd(true, 4, 0, 1, 3)); // 96
    a.w(asm::msub(true, 5, 0, 1, 3)); // 5 - 91
    a.w(asm::div(true, false, 6, 0, 1)); // udiv = 1
    a.w(asm::div(true, true, 7, 0, 1)); // sdiv = 1
    a.w(asm::div(true, false, 8, 0, 31)); // udiv by xzr = 0
    a.ws(&asm::mov_imm64(10, 0xFFFF_FFFF));
    a.w(asm::umaddl(11, 10, 10, 31)); // (2^32-1)^2
    a.w(asm::umulh(12, 10, 10)); // high64 = 0
    a.ws(&asm::mov_imm64(13, (-3i64) as u64));
    a.w(asm::smaddl(15, 13, 13, 31)); // 9
    a.w(asm::smulh(16, 13, 13)); // 0
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[2], 91);
    assert_eq!(m.state.x[4], 96);
    assert_eq!(m.state.x[5] as i64, -86);
    assert_eq!(m.state.x[6], 1);
    assert_eq!(m.state.x[7], 1);
    assert_eq!(m.state.x[8], 0);
    assert_eq!(m.state.x[11], 0xFFFF_FFFE_0000_0001);
    assert_eq!(m.state.x[12], 0);
    assert_eq!(m.state.x[15], 9);
    assert_eq!(m.state.x[16], 0);
}

#[test]
fn div_edge_cases() {
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(0, i64::MIN as u64));
    a.ws(&asm::mov_imm64(1, -1i64 as u64));
    a.w(asm::div(true, true, 2, 0, 1)); // INT64_MIN / -1 = INT64_MIN (ARM)
    a.ws(&asm::mov_imm64(3, 0x8000_0000));
    a.w(asm::div(false, true, 4, 3, 1)); // INT32_MIN / -1
    a.w(asm::div(true, true, 5, 0, 31)); // sdiv by zero = 0
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[2] as i64, i64::MIN);
    assert_eq!(m.state.x[4], 0x8000_0000);
    assert_eq!(m.state.x[5], 0);
}

#[test]
fn bitfield_shifts_extends() {
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(0, 0x1234_5678_9ABC_DEF0));
    a.w(asm::lsr_imm(true, 1, 0, 8));
    a.w(asm::lsl_imm(true, 2, 0, 8));
    a.w(asm::uxtb(3, 0));
    a.w(asm::sxth(true, 4, 0));
    a.w(asm::sxtw(5, 0));
    a.w(asm::ror_imm(true, 6, 0, 8));
    a.w(asm::movz(true, 8, 4, 0));
    a.w(asm::shift_var(true, ShiftType::Lsl, 7, 0, 8)); // lslv x7, x0, x8
    a.w(asm::extr(true, 17, 0, 1, 32)); // extr x17, x0, x1, #32
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[1], 0x0012_3456_789A_BCDE);
    assert_eq!(m.state.x[2], 0x3456_789A_BCDE_F000);
    assert_eq!(m.state.x[3], 0xF0);
    assert_eq!(m.state.x[4], 0xFFFF_FFFF_FFFF_DEF0u64);
    assert_eq!(m.state.x[5] as i64, 0x9ABC_DEF0u32 as i32 as i64);
    assert_eq!(m.state.x[6], 0xF012_3456_789A_BCDE);
    assert_eq!(m.state.x[7], 0x1234_5678_9ABC_DEF0u64 << 4);
    assert_eq!(
        m.state.x[17],
        (0x1234_5678_9ABC_DEF0u64 << 32) | (0x0012_3456_789A_BCDE >> 32),
        "extr = hi:lo"
    );
}

#[test]
fn csel_and_conditions() {
    // Compare equal operands → N=0 Z=1 C=1 V=0, then cset per cond.
    let conds = [
        Cond::Eq, Cond::Ne, Cond::Mi, Cond::Pl, Cond::Cs, Cond::Cc, Cond::Vs, Cond::Vc, Cond::Hi, Cond::Ls, Cond::Ge, Cond::Lt,
        Cond::Gt, Cond::Le, Cond::Al,
    ];
    let mut a = Assembler::new();
    a.w(asm::movz(true, 0, 42, 0));
    a.w(asm::movz(true, 1, 42, 0));
    for (i, cond) in conds.iter().enumerate() {
        a.w(asm::cmp_reg(true, 0, 1));
        a.w(asm::cset(false, (i as u8) + 10, *cond)); // w(i+10) = cond ? 1 : 0
    }
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    // Ge: n==v true, Gt: z==0&&n==v → false, Le: z==1||n!=v → true
    let expect_true = |c: Cond| {
        matches!(
            c,
            Cond::Eq | Cond::Pl | Cond::Cs | Cond::Vc | Cond::Ge | Cond::Le | Cond::Ls | Cond::Al
        )
    };
    for (i, cond) in conds.iter().enumerate() {
        assert_eq!(m.state.x[10 + i], expect_true(*cond) as u64, "cond {:?}", cond);
    }
}

#[test]
fn tbz_cbz_paths() {
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(0, 1 << 40));
    a.w(asm::movz(true, 1, 0, 0));
    a.tbz_to(true, 40, 0, "taken40"); // tbnz x0, #40 → taken
    a.w(asm::add(true, 1, 1, 100));
    a.b("after");
    a.label("taken40");
    a.w(asm::add(true, 1, 1, 7));
    a.label("after");
    a.cbz_to(true, false, 31, "zero"); // cbz xzr → always taken
    a.w(asm::add(true, 1, 1, 1000));
    a.label("zero");
    a.cbz_to(true, true, 0, "nonzero"); // cbnz x0 → taken
    a.w(asm::add(true, 1, 1, 10000));
    a.label("nonzero");
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[1], 7);
}

#[test]
fn adrp_data_load() {
    let data = BASE + 0x1000;
    let mut a = Assembler::new();
    a.w(asm::pc_rel(true, 0, BASE, data)); // adrp x0, data_page
    a.w(asm::ld_st_unsigned(8, LdStOp::LoadZ, 1, 0, 0)); // ldr x1, [x0]
    a.w(asm::svc(0));
    let code = a.finish();
    let mut mem = Memory::new(1 << 22).unwrap();
    mem.write(BASE, &code).unwrap();
    mem.write(data, &0xDEAD_BEEF_1234_5678u64.to_le_bytes()).unwrap();
    let mut m = Machine::new(mem, XlatConfig::default()).unwrap();
    m.state.sp = m.mem.size() - 64;
    let r = run(&mut m);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[0], data);
    assert_eq!(m.state.x[1], 0xDEAD_BEEF_1234_5678);
}

#[test]
fn memory_fault_reported() {
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(0, 0xDEAD_0000));
    let fault_pc = BASE + (a.pos() as u64) * 4;
    a.w(asm::ld_st_unsigned(8, LdStOp::LoadZ, 1, 0, 0));
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::MemoryFault);
    assert_eq!(m.state.pc, fault_pc);
    assert_eq!(m.state.aux[1], 0xDEAD_0000);
}

#[test]
fn exit_via_svc_and_brk() {
    let mut a = Assembler::new();
    a.w(asm::svc(123));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.aux[0], 123);

    let mut a = Assembler::new();
    a.w(asm::brk(7));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Breakpoint);
    assert_eq!(m.state.aux[0], 7);
}

#[test]
fn unsupported_insn_exits_cleanly() {
    // 0x1E602801 is `fmov d1, d0` — FP is v2 territory; must exit cleanly.
    let mut a = Assembler::new();
    a.w(0x1E60_2801);
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::UnimplementedInsn);
    assert_eq!(m.state.aux[0], 0x1E60_2801);
    assert_eq!(m.state.pc, BASE);
}

#[test]
fn hot_loop_retires_exact_insns() {
    // The "Speed" pillar in executable form: 1M iterations retire an exact
    // instruction count and translate only a handful of blocks — after
    // warm-up everything runs as chained native code.
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(1, 1_000_000)); // movz+movk
    a.w(asm::movz(true, 0, 0, 0));
    a.label("loop");
    a.w(asm::add(true, 0, 0, 1));
    a.w(subs1(1));
    a.b_cond(Cond::Ne, "loop");
    a.w(asm::svc(0));
    let (m, r) = asm_run(a);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[0], 1_000_000);
    assert_eq!(m.state.insn_count, 3 + 3 * 1_000_000 + 1, "incl. the svc");
    assert!(m.cache.len() <= 4, "only a few blocks, got {}", m.cache.len());
}

#[test]
fn cache_persistence_roundtrip() {
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(1, 1000));
    a.w(asm::movz(true, 0, 0, 0));
    a.label("loop");
    a.w(asm::add_r(true, 0, 0, 1));
    a.w(subs1(1));
    a.b_cond(Cond::Ne, "loop");
    a.w(asm::svc(0));
    let code = a.finish();

    let mut m1 = boot(&code);
    let r1 = run(&mut m1);
    assert_eq!(r1, ExitReason::Svc);
    assert_eq!(m1.state.x[0], 1000 * 1001 / 2);

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in &code {
        hash = (hash ^ *b as u64).wrapping_mul(0x1000_0000_01b3);
    }
    let saved = m1.cache.save(hash);
    assert!(!saved.is_empty());

    // Fresh machine: load the cache, run without translating anything new.
    let mut mem = Memory::new(1 << 22).unwrap();
    mem.write(BASE, &code).unwrap();
    let mut m2 = Machine::new(mem, XlatConfig::default()).unwrap();
    m2.state.sp = m2.mem.size() - 64;
    let cfg = m2.cache.cfg;
    m2.cache = a64x_xlat::block::CodeCache::load(cfg, &saved, hash).expect("load cache");
    let loaded = m2.cache.len() as u64;
    assert!(loaded >= 2);
    let r2 = run(&mut m2);
    assert_eq!(r2, ExitReason::Svc);
    assert_eq!(m2.state.x[0], 1000 * 1001 / 2);
    assert_eq!(m2.state.insn_count, m1.state.insn_count);
    assert_eq!(m2.cache.stats.blocks_translated, loaded, "no fresh translations after load");
}

#[test]
fn fast_mode_masked_memory() {
    let cfg = XlatConfig { checked_mem: false, count_stats: true };
    let size: u64 = 1 << 22;
    let mut a = Assembler::new();
    a.ws(&asm::mov_imm64(9, size - 4));
    a.ws(&asm::mov_imm64(10, 2 * size - 4));
    a.w(asm::movz(false, 0, 0xABCD, 0));
    a.w(asm::ld_st_unsigned(4, LdStOp::Store, 0, 9, 0)); // str w0, [x9]
    a.w(asm::ld_st_unsigned(4, LdStOp::LoadZ, 1, 10, 0)); // ldr w1, [x10] wraps to [x9]
    a.w(asm::svc(0));
    let code = a.finish();
    let mut mem = Memory::new(size).unwrap();
    mem.write(BASE, &code).unwrap();
    let mut m = Machine::new(mem, cfg).unwrap();
    m.state.sp = size - 64;
    let r = run(&mut m);
    assert_eq!(r, ExitReason::Svc);
    assert_eq!(m.state.x[1], 0xABCD);
}
