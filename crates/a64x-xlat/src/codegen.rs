//! ARM64 → x86-64 binary translation, one basic block at a time.
//!
//! Register conventions inside translated code (installed by the
//! trampoline in [`crate::Trampoline`]):
//!
//! * `r15` — pointer to the guest [`CpuState`]
//! * `r14` — guest memory base (`mem_base`)
//! * `rax`, `rcx`, `rdx`, `r8`–`r11` — scratch
//!
//! Guest registers live in the CpuState struct; 32-bit ("W") results are
//! produced by 32-bit host operations, whose zero-extension into 64-bit
//! registers exactly matches ARM's W-register semantics — so register
//! slots are always stored 64-bit wide and stay canonical.
//!
//! Condition flags (NZCV) are *forwarded* from the host EFLAGS: ADD/SUB
//! produce identical carry/overflow on both ISAs (with ARM's subtraction
//! carry being `!CF` — i.e. "no borrow"), and ARM shifter-carry equals the
//! host CF after the same shift. Flag capture is 4 `setcc`+store pairs
//! per flag-writing instruction — no software flag model anywhere.

use a64x_arm64::bitmask::decode_bitfield_masks;
use a64x_arm64::{decode, DecodeError, Insn};
use a64x_arm64::{AddrMode, BfOp, CSelOp, Cond, ExtendType, LdStOp, LogicOp, MovOp, PairMode, RevOp, ShiftType};
use a64x_core::state::{CpuState, ExitReason};
use a64x_core::{Error, Memory, Result};
use a64x_x64::{Alu, Cc, Code, Label, Mem, Reg, Shift};
use core::mem::offset_of;

use crate::block::{write_chain_slot, write_ret_slot, CodeCache, Link, TranslatedBlock, SLOT_LEN};

/// Hard cap on instructions per block (keeps code-cache entries small and
/// bounding).
const MAX_BLOCK_INSNS: usize = 64;

// ---------------------------------------------------------------------------
// CpuState field offsets
// ---------------------------------------------------------------------------

#[inline]
fn so_x(i: u8) -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, x) as i32 + 8 * i as i32)
}
#[inline]
fn so_sp() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, sp) as i32)
}
#[inline]
fn so_pc() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, pc) as i32)
}
#[inline]
fn so_flag(i: usize) -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, flags) as i32 + i as i32)
}
#[inline]
fn so_budget() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, budget) as i32)
}
#[inline]
fn so_memsize() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, mem_size) as i32)
}
#[inline]
fn so_insns() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, insn_count) as i32)
}
#[inline]
fn so_blocks() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, block_count) as i32)
}
#[inline]
fn so_reason() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, exit_reason) as i32)
}
#[inline]
fn so_running() -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, running) as i32)
}
#[inline]
fn so_aux(i: usize) -> Mem {
    Mem::bd(Reg::R15, offset_of!(CpuState, aux) as i32 + 8 * i as i32)
}

/// Translate one basic block starting at guest `pc`.
pub fn translate_block(cache: &CodeCache, mem: &Memory, pc: u64) -> Result<TranslatedBlock> {
    let mut t = T::new(cache);

    // -- prologue: per-block budget + statistics --------------------------
    // sub budget, 1 ; jz -> return-to-dispatcher (budget exhausted)
    let l_ok = t.c.label();
    t.c.alu_mi(Alu::Sub, so_budget(), 1, true);
    t.c.jcc(Cc::Ne, l_ok);
    t.c.ret();
    t.c.bind(l_ok);
    t.c.alu_mi(Alu::Add, so_blocks(), 1, true);

    let mut addr = pc;
    loop {
        let word = mem.fetch_insn(addr).map_err(|_| Error::OutOfBounds { addr, len: 4 })?;
        match decode(word, addr) {
            Ok(insn) => {
                t.n += 1;
                let done = t.emit(addr, &insn)?;
                addr += 4;
                if done {
                    break;
                }
                if t.n as usize >= MAX_BLOCK_INSNS {
                    t.emit_exit_to(addr);
                    break;
                }
            }
            Err(DecodeError::Unsupported) | Err(DecodeError::Unallocated) => {
                t.emit_exit_unsupported(addr, word);
                break;
            }
        }
    }

    let guest_len = (addr - pc) as u32;
    let n_insns = t.n;
    let code = t.c.finish();
    let links = t.links;
    let exec = a64x_core::ExecBuffer::from_bytes(&code)?;
    Ok(TranslatedBlock { guest_pc: pc, guest_len, n_insns, links, exec })
}

struct T<'a> {
    c: Code,
    cfg: crate::block::XlatConfig,
    cache: &'a CodeCache,
    links: Vec<Link>,
    n: u32,
}

impl<'a> T<'a> {
    fn new(cache: &'a CodeCache) -> T<'a> {
        T { c: Code::new(), cfg: cache.cfg, cache, links: Vec::new(), n: 0 }
    }

    // -------------------------------------------------------------------
    // register access helpers
    // -------------------------------------------------------------------

    /// Load guest register `i` (index 31 = XZR when `!sp_ok`, SP when
    /// `sp_ok`) into host register `dst`.
    fn ld(&mut self, dst: Reg, i: u8, sp_ok: bool) {
        if i == 31 {
            if sp_ok {
                self.c.mov_rm(dst, so_sp());
            } else {
                self.c.mov_ri(dst, 0);
            }
        } else {
            self.c.mov_rm(dst, so_x(i));
        }
    }

    /// Store host `src` into guest register `i` (dropping stores to XZR).
    fn st(&mut self, i: u8, src: Reg, sp_ok: bool) {
        if i == 31 {
            if sp_ok {
                self.c.mov_mr(so_sp(), src);
            }
        } else {
            self.c.mov_mr(so_x(i), src);
        }
    }

    // -------------------------------------------------------------------
    // exits
    // -------------------------------------------------------------------

    /// Bump the retired-instruction count for this block into the state
    /// (emitted on every exit path exactly once).
    fn emit_stats(&mut self) {
        self.c.alu_mi(Alu::Add, so_insns(), self.n as i32, true);
    }

    /// Exit to a constant guest address: store the target pc, then either
    /// chain into the target block (when already translated) or return.
    fn emit_exit_to(&mut self, target: u64) {
        self.emit_stats();
        self.c.mov_ri(Reg::Rax, target);
        self.c.mov_mr(so_pc(), Reg::Rax);
        let off = self.c.pos();
        let mut slot = [0u8; SLOT_LEN];
        match self.cache.lookup(target) {
            Some(entry) => write_chain_slot(&mut slot, 0, entry as u64),
            None => write_ret_slot(&mut slot, 0),
        }
        self.c.raw_bytes(&slot);
        self.links.push(Link { code_off: off as u32, target });
    }

    /// Exit with pc already in RAX (BR/BLR/RET).
    fn emit_exit_pc_rax(&mut self) {
        self.emit_stats();
        self.c.mov_mr(so_pc(), Reg::Rax);
        self.c.ret();
    }

    /// Exit with a stop reason and an informational aux value.
    fn emit_exit_reason(&mut self, pc: u64, reason: ExitReason, aux0: u64) {
        self.emit_stats();
        self.c.mov_ri(Reg::Rax, pc);
        self.c.mov_mr(so_pc(), Reg::Rax);
        self.c.mov_ri(Reg::Rax, aux0);
        self.c.mov_mr(so_aux(0), Reg::Rax);
        self.c.mov_mi8(so_reason(), reason as u8);
        self.c.mov_mi8(so_running(), 0);
        self.c.ret();
    }

    fn emit_exit_unsupported(&mut self, pc: u64, word: u32) {
        self.n += 1;
        self.emit_stats();
        self.c.mov_ri(Reg::Rax, pc);
        self.c.mov_mr(so_pc(), Reg::Rax);
        self.c.mov_ri(Reg::Rax, word as u64);
        self.c.mov_mr(so_aux(0), Reg::Rax);
        self.c.mov_mi8(so_reason(), ExitReason::UnimplementedInsn as u8);
        self.c.mov_mi8(so_running(), 0);
        self.c.ret();
    }

    // -------------------------------------------------------------------
    // flags
    // -------------------------------------------------------------------

    /// Capture NZCV from the host EFLAGS after an add/sub (`sub` selects
    /// ARM's inverted carry convention).
    fn flags_alu(&mut self, is_add: bool) {
        self.c.setcc(Cc::S, Reg::R8);
        self.c.setcc(Cc::E, Reg::R9);
        self.c.setcc(if is_add { Cc::B } else { Cc::Ae }, Reg::R10);
        self.c.setcc(Cc::O, Reg::R11);
        for (i, r) in [Reg::R8, Reg::R9, Reg::R10, Reg::R11].iter().enumerate() {
            self.c.mov_mr_size(so_flag(i), *r, 1);
        }
    }

    /// Capture NZCV after a logical op: N/Z from host flags, V = 0. The C
    /// source is selected by `shifter_carry`; the caller exposes it in r10
    /// either by pre-capture (shift case: host CF *is* ARM's shifter carry
    /// and must be grabbed before the logical op clears CF) or here.
    fn flags_logic(&mut self, shifter_carry: ShifterCarry) {
        // SF/ZF/CF all still live from the logical op: capture N/Z first.
        self.c.setcc(Cc::S, Reg::R8);
        self.c.setcc(Cc::E, Reg::R9);
        match shifter_carry {
            ShifterCarry::PreCaptured => { /* r10 already holds shifter carry */ }
            ShifterCarry::Zero => {
                self.c.mov_ri(Reg::R10, 0);
            }
            ShifterCarry::Keep => {
                self.c.movzx_rm(Reg::R10, so_flag(2), 1);
            }
        }
        self.c.mov_ri(Reg::R11, 0);
        for (i, r) in [Reg::R8, Reg::R9, Reg::R10, Reg::R11].iter().enumerate() {
            self.c.mov_mr_size(so_flag(i), *r, 1);
        }
    }

    // -------------------------------------------------------------------
    // condition evaluation
    // -------------------------------------------------------------------

    /// Emit a jump to `lt` iff the ARM condition holds. Scratch: rax/rcx.
    /// All flag reads come from the guest flag bytes.
    fn emit_jcc_arm(&mut self, cond: Cond, lt: Label) {
        match cond {
            Cond::Al => {
                self.c.jmp(lt);
            }
            Cond::Nv => { /* never */ }
            Cond::Eq | Cond::Ne | Cond::Mi | Cond::Pl | Cond::Cs | Cond::Cc | Cond::Vs | Cond::Vc => {
                let (idx, one) = match cond {
                    Cond::Eq => (1, true),
                    Cond::Ne => (1, false),
                    Cond::Mi => (0, true),
                    Cond::Pl => (0, false),
                    Cond::Cs => (2, true),
                    Cond::Cc => (2, false),
                    Cond::Vs => (3, true),
                    Cond::Vc => (3, false),
                    _ => unreachable!(),
                };
                self.c.movzx_rm(Reg::Rax, so_flag(idx), 1);
                self.c.alu_ri(Alu::Cmp, Reg::Rax, 0, false);
                self.c.jcc(if one { Cc::Ne } else { Cc::E }, lt);
            }
            Cond::Ge | Cond::Lt => {
                self.c.movzx_rm(Reg::Rax, so_flag(0), 1); // N
                self.c.movzx_rm(Reg::Rcx, so_flag(3), 1); // V
                self.c.alu_rr(Alu::Cmp, Reg::Rax, Reg::Rcx, false);
                self.c.jcc(if matches!(cond, Cond::Ge) { Cc::E } else { Cc::Ne }, lt);
            }
            Cond::Hi | Cond::Ls => {
                // bool = C & (Z==0); Hi jumps when bool!=0, Ls when ==0
                self.c.movzx_rm(Reg::Rax, so_flag(2), 1);
                self.c.movzx_rm(Reg::Rcx, so_flag(1), 1);
                self.c.alu_ri(Alu::Cmp, Reg::Rcx, 0, false);
                self.c.setcc(Cc::E, Reg::Rcx);
                self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, false);
                self.c.jcc(if matches!(cond, Cond::Hi) { Cc::Ne } else { Cc::E }, lt);
            }
            Cond::Gt | Cond::Le => {
                // bool = (Z==0) & (N==V)
                self.c.movzx_rm(Reg::Rax, so_flag(1), 1);
                self.c.alu_ri(Alu::Cmp, Reg::Rax, 0, false);
                self.c.setcc(Cc::E, Reg::Rax);
                self.c.movzx_rm(Reg::Rcx, so_flag(0), 1);
                self.c.movzx_rm(Reg::Rdx, so_flag(3), 1);
                self.c.alu_rr(Alu::Cmp, Reg::Rcx, Reg::Rdx, false);
                self.c.setcc(Cc::E, Reg::Rcx);
                self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, false);
                self.c.jcc(if matches!(cond, Cond::Gt) { Cc::Ne } else { Cc::E }, lt);
            }
        }
    }

    // -------------------------------------------------------------------
    // memory access
    // -------------------------------------------------------------------

    /// Guest-EA (r8) → host pointer (r8), with the configured check.
    /// `size` = access bytes; on fault the exit stub reports insn `pc`.
    fn emit_mem_gate(&mut self, size: u8, pc: u64) {
        if self.cfg.checked_mem {
            self.c.mov_rm(Reg::Rdx, so_memsize());
            self.c.alu_ri(Alu::Sub, Reg::Rdx, size as i32, true);
            let l_ok = self.c.label();
            self.c.alu_rr(Alu::Cmp, Reg::R8, Reg::Rdx, true);
            self.c.jcc(Cc::Be, l_ok);
            // inline fault stub
            self.c.mov_mi8(so_reason(), ExitReason::MemoryFault as u8);
            self.c.mov_mr(so_aux(1), Reg::R8);
            self.c.mov_ri(Reg::Rax, pc);
            self.c.mov_mr(so_pc(), Reg::Rax);
            self.c.mov_mi8(so_running(), 0);
            self.c.ret();
            self.c.bind(l_ok);
        } else {
            // fast mode: wrap into the address space
            self.c.mov_rm(Reg::Rdx, so_memsize());
            self.c.alu_ri(Alu::Sub, Reg::Rdx, 1, true);
            self.c.alu_rr(Alu::And, Reg::R8, Reg::Rdx, true);
        }
        self.c.lea(Reg::R8, Mem::bi(Reg::R14, Reg::R8));
    }

    /// Load from [r8] into rax, per load semantics.
    fn emit_load_rax(&mut self, size: u8, op: LdStOp) {
        let m = Mem::bd(Reg::R8, 0);
        match op {
            LdStOp::LoadZ => match size {
                1 => self.c.movzx_rm(Reg::Rax, m, 1),
                2 => self.c.movzx_rm(Reg::Rax, m, 2),
                4 => self.c.mov32_rm(Reg::Rax, m),
                _ => self.c.mov_rm(Reg::Rax, m),
            },
            LdStOp::LoadS64 => match size {
                1 => self.c.movsx_rm(Reg::Rax, m, 1, true),
                2 => self.c.movsx_rm(Reg::Rax, m, 2, true),
                _ => self.c.movsxd_rm(Reg::Rax, m),
            },
            LdStOp::LoadS32 => match size {
                1 => self.c.movsx_rm(Reg::Rax, m, 1, false),
                2 => self.c.movsx_rm(Reg::Rax, m, 2, false),
                _ => self.c.movsxd_rm(Reg::Rax, m),
            },
            LdStOp::Store => unreachable!(),
        };
    }

    /// Extend `r` from 8/16/32 to 64 bits per ARM extend type, in place.
    fn emit_extend(&mut self, r: Reg, ext: ExtendType) {
        match ext {
            ExtendType::Uxtb => { self.c.movzx_rr(r, r, 1); }
            ExtendType::Uxth => { self.c.movzx_rr(r, r, 2); }
            ExtendType::Uxtw => { self.c.mov32_rr(r, r); }
            ExtendType::Uxtx => {}
            ExtendType::Sxtb => { self.c.movsx_rr(r, r, 1, true); }
            ExtendType::Sxth => { self.c.movsx_rr(r, r, 2, true); }
            ExtendType::Sxtw => { self.c.movsxd_rr(r, r); }
            ExtendType::Sxtx => {}
        }
    }

    // -------------------------------------------------------------------
    // the instruction emitter — returns true when the block ends
    // -------------------------------------------------------------------

    fn emit(&mut self, pc: u64, insn: &Insn) -> Result<bool> {
        match insn {
            // ------------------------------------------------ ALU, immediate
            Insn::AddImm { w64, sub, setflags, imm, rn, rd } => {
                self.ld(Reg::Rax, *rn, true);
                if *imm != 0 {
                    self.c.alu_ri(if *sub { Alu::Sub } else { Alu::Add }, Reg::Rax, *imm as i32, *w64);
                }
                if *setflags {
                    self.flags_alu(!*sub);
                }
                self.st(*rd, Reg::Rax, !*setflags);
            }

            Insn::LogicImm { w64, op, mask, rn, rd } => {
                self.ld(Reg::Rax, *rn, false);
                match op {
                    LogicOp::And | LogicOp::Ands => self.logic_with_mask(Alu::And, *mask, *w64),
                    LogicOp::Orr => self.logic_with_mask(Alu::Or, *mask, *w64),
                    LogicOp::Eor => self.logic_with_mask(Alu::Xor, *mask, *w64),
                }
                if *op == LogicOp::Ands {
                    self.flags_logic(ShifterCarry::Zero);
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::MovImm { w64, op, imm16, shift, rd } => {
                let v = (*imm16 as u64) << shift;
                match op {
                    MovOp::Movz => {
                        self.c.mov_ri(Reg::Rax, if *w64 { v } else { v & 0xFFFF_FFFF });
                    }
                    MovOp::Movn => {
                        let nv = if *w64 { !v } else { !v & 0xFFFF_FFFF };
                        self.c.mov_ri(Reg::Rax, nv);
                    }
                    MovOp::Movk => {
                        self.ld(Reg::Rax, *rd, false);
                        let keep = if *w64 { !(0xFFFFu64 << shift) } else { !((0xFFFFu32 << shift) as u64) };
                        self.c.mov_ri(Reg::Rcx, keep);
                        self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, *w64);
                        self.c.mov_ri(Reg::Rcx, v);
                        self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, *w64);
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            // ------------------------------------------------ bitfield ops
            Insn::Bitfield { w64, op, immr, imms, rn, rd } => {
                let width: u8 = if *w64 { 64 } else { 32 };
                let (wmask, tmask) = match decode_bitfield_masks(*w64, *immr, *imms, width) {
                    Some(x) => x,
                    None => return Err(Error::Host("bitfield decode failed".into())),
                };
                let immr_w = immr % width;
                self.ld(Reg::Rax, *rn, false);
                if immr_w != 0 {
                    self.c.shift_ri(Shift::Ror, Reg::Rax, immr_w, *w64);
                }
                if !matches!(op, BfOp::Sbfm | BfOp::Ubfm) {
                    // BFM: merge into rd
                    self.c.mov_ri(Reg::Rcx, wmask);
                    self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, *w64);
                    self.ld(Reg::Rcx, *rd, false);
                    self.c.mov_ri(Reg::Rdx, !wmask);
                    self.c.alu_rr(Alu::And, Reg::Rcx, Reg::Rdx, *w64);
                    self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, *w64);
                } else {
                    self.c.mov_ri(Reg::Rcx, wmask);
                    self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, *w64);
                }
                self.c.mov_ri(Reg::Rcx, tmask);
                self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rcx, *w64);
                if matches!(op, BfOp::Sbfm) {
                    // sign-extend at the top bit of tmask. The two 32-bit
                    // forms run in 32-bit lanes (and zero the top half of
                    // the host register for free — matching W semantics).
                    if *w64 {
                        let top: u32 = 63 - tmask.leading_zeros();
                        let sh: u8 = (63 - top) as u8;
                        if sh != 0 {
                            self.c.shift_ri(Shift::Shl, Reg::Rax, sh, true);
                            self.c.shift_ri(Shift::Sar, Reg::Rax, sh, true);
                        }
                    } else {
                        let top: u32 = 31 - (tmask as u32).leading_zeros();
                        let sh: u8 = (31 - top) as u8;
                        if sh != 0 {
                            self.c.shift_ri(Shift::Shl, Reg::Rax, sh, false);
                            self.c.shift_ri(Shift::Sar, Reg::Rax, sh, false);
                        }
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::Extract { w64, lsb, rm, rn, rd } => {
                if rn == rm {
                    // ROR alias
                    self.ld(Reg::Rax, *rm, false);
                    if *lsb != 0 {
                        self.c.shift_ri(Shift::Ror, Reg::Rax, *lsb, *w64);
                    }
                } else {
                    let width: u8 = if *w64 { 64 } else { 32 };
                    self.ld(Reg::Rax, *rm, false);
                    if *lsb != 0 {
                        self.c.shift_ri(Shift::Shr, Reg::Rax, *lsb, *w64);
                    }
                    self.ld(Reg::Rcx, *rn, false);
                    self.c.shift_ri(Shift::Shl, Reg::Rcx, width - *lsb, *w64);
                    self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, *w64);
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::PcRel { addr, rd, .. } => {
                self.c.mov_ri(Reg::Rax, *addr);
                self.st(*rd, Reg::Rax, false);
            }

            // ------------------------------------------------ ALU, register
            Insn::LogicReg { w64, op, negate, shift, shift_amt, rm, rn, rd } => {
                self.ld(Reg::Rcx, *rm, false);
                let amt = *shift_amt;
                self.emit_shift_imm(Reg::Rcx, *shift, amt, *w64);
                let sets = *op == LogicOp::Ands;
                if sets && amt != 0 {
                    // host CF == ARM shifter carry — grab it before the
                    // logical op below clears CF
                    self.c.setcc(Cc::B, Reg::R10);
                }
                if *negate {
                    self.c.not(Reg::Rcx, *w64);
                }
                self.ld(Reg::Rax, *rn, false);
                let alu = match op {
                    LogicOp::And | LogicOp::Ands => Alu::And,
                    LogicOp::Orr => Alu::Or,
                    LogicOp::Eor => Alu::Xor,
                };
                self.c.alu_rr(alu, Reg::Rax, Reg::Rcx, *w64);
                if sets {
                    if amt == 0 {
                        self.flags_logic(ShifterCarry::Keep);
                    } else {
                        self.flags_logic(ShifterCarry::PreCaptured);
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::AddReg { w64, sub, setflags, shift, shift_amt, rm, rn, rd } => {
                self.ld(Reg::Rcx, *rm, false);
                self.emit_shift_imm(Reg::Rcx, *shift, *shift_amt, *w64);
                self.ld(Reg::Rax, *rn, false);
                self.c.alu_rr(if *sub { Alu::Sub } else { Alu::Add }, Reg::Rax, Reg::Rcx, *w64);
                if *setflags {
                    self.flags_alu(!*sub);
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::AddExt { w64, sub, setflags, extend, amount, rm, rn, rd } => {
                self.ld(Reg::Rax, *rn, true);
                self.ld(Reg::Rcx, *rm, false);
                self.emit_extend(Reg::Rcx, *extend);
                if *amount != 0 {
                    self.c.shift_ri(Shift::Shl, Reg::Rcx, *amount, true);
                }
                self.c.alu_rr(if *sub { Alu::Sub } else { Alu::Add }, Reg::Rax, Reg::Rcx, *w64);
                if *setflags {
                    self.flags_alu(!*sub);
                }
                self.st(*rd, Reg::Rax, true);
            }

            // ------------------------------------------------ multiplies
            Insn::Mul { w64, sub, rm, rn, ra, rd } => {
                self.ld(Reg::Rax, *rn, false);
                self.ld(Reg::Rcx, *rm, false);
                self.c.imul_rr(Reg::Rax, Reg::Rcx, *w64);
                if *ra != 31 {
                    self.ld(Reg::Rcx, *ra, false);
                    if *sub {
                        self.c.alu_rr(Alu::Sub, Reg::Rcx, Reg::Rax, *w64);
                        self.c.mov_rr(Reg::Rax, Reg::Rcx);
                    } else {
                        self.c.alu_rr(Alu::Add, Reg::Rax, Reg::Rcx, *w64);
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::MulLong { signed, sub, rm, rn, ra, rd } => {
                if *signed {
                    self.ld(Reg::Rax, *rn, false);
                    self.c.movsxd_rr(Reg::Rax, Reg::Rax);
                    self.ld(Reg::Rcx, *rm, false);
                    self.c.movsxd_rr(Reg::Rcx, Reg::Rcx);
                } else {
                    self.ld(Reg::Rax, *rn, false);
                    self.ld(Reg::Rcx, *rm, false);
                    // operands are W registers: upper halves already zero
                }
                self.c.imul_rr(Reg::Rax, Reg::Rcx, true);
                if *ra != 31 {
                    self.ld(Reg::Rcx, *ra, false);
                    if *sub {
                        self.c.alu_rr(Alu::Sub, Reg::Rcx, Reg::Rax, true);
                        self.c.mov_rr(Reg::Rax, Reg::Rcx);
                    } else {
                        self.c.alu_rr(Alu::Add, Reg::Rax, Reg::Rcx, true);
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::MulHigh { signed, rm, rn, rd } => {
                self.ld(Reg::Rax, *rn, false);
                self.ld(Reg::Rcx, *rm, false);
                if *signed {
                    self.c.imul_r(Reg::Rcx, true);
                } else {
                    self.c.mul_r(Reg::Rcx, true);
                }
                self.st(*rd, Reg::Rdx, false);
            }

            Insn::Div { w64, signed, rm, rn, rd } => {
                self.ld(Reg::Rax, *rn, false);
                self.ld(Reg::Rcx, *rm, false);
                let l_norm = self.c.label();
                let l_done = self.c.label();
                self.c.test_rr(Reg::Rcx, Reg::Rcx, *w64);
                self.c.jcc(Cc::Ne, l_norm);
                // div by zero → 0
                self.c.alu_rr(Alu::Xor, Reg::Rax, Reg::Rax, false);
                self.c.jmp(l_done);
                self.c.bind(l_norm);
                if *signed {
                    let l_idiv = self.c.label();
                    self.c.alu_ri(Alu::Cmp, Reg::Rcx, -1, *w64);
                    self.c.jcc(Cc::Ne, l_idiv);
                    // INT_MIN / -1 → INT_MIN on ARM (host would #DE)
                    self.c.neg(Reg::Rax, *w64);
                    self.c.jmp(l_done);
                    self.c.bind(l_idiv);
                    self.c.cqo(*w64);
                    self.c.idiv_r(Reg::Rcx, *w64);
                } else {
                    self.c.alu_rr(Alu::Xor, Reg::Rdx, Reg::Rdx, false);
                    self.c.div_r(Reg::Rcx, *w64);
                }
                self.c.bind(l_done);
                self.st(*rd, Reg::Rax, false);
            }

            Insn::ShiftVar { w64, shift, rm, rn, rd } => {
                self.ld(Reg::Rax, *rn, false);
                self.ld(Reg::Rcx, *rm, false);
                let k = match shift {
                    ShiftType::Lsl => Shift::Shl,
                    ShiftType::Lsr => Shift::Shr,
                    ShiftType::Asr => Shift::Sar,
                    ShiftType::Ror => Shift::Ror,
                };
                self.c.shift_cl(k, Reg::Rax, *w64);
                self.st(*rd, Reg::Rax, false);
            }

            // ------------------------------------------------ byte reversals
            Insn::Rev { w64, op, rn, rd } => {
                self.ld(Reg::Rax, *rn, false);
                match op {
                    RevOp::Rev => {
                        self.c.bswap(Reg::Rax, *w64);
                    }
                    RevOp::Rev32 => {
                        self.c.mov_rr(Reg::Rcx, Reg::Rax);
                        self.c.shift_ri(Shift::Shr, Reg::Rcx, 32, true);
                        self.c.bswap(Reg::Rax, false);
                        self.c.bswap(Reg::Rcx, false);
                        self.c.shift_ri(Shift::Shl, Reg::Rcx, 32, true);
                        self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, true);
                    }
                    RevOp::Rev16 => {
                        // per-16-bit-lane byte swap
                        if *w64 {
                            self.c.mov_rr(Reg::Rcx, Reg::Rax);
                            self.c.shift_ri(Shift::Shr, Reg::Rcx, 8, true);
                            self.c.mov_ri(Reg::Rdx, 0x00FF_00FF_00FF_00FF);
                            self.c.alu_rr(Alu::And, Reg::Rcx, Reg::Rdx, true);
                            self.c.alu_rr(Alu::And, Reg::Rax, Reg::Rdx, true);
                            self.c.shift_ri(Shift::Shl, Reg::Rax, 8, true);
                            self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, true);
                        } else {
                            self.c.mov32_rr(Reg::Rcx, Reg::Rax);
                            self.c.shift_ri(Shift::Shr, Reg::Rcx, 8, false);
                            self.c.alu_ri(Alu::And, Reg::Rcx, 0x00FF_00FF, false);
                            self.c.alu_ri(Alu::And, Reg::Rax, 0x00FF_00FF, false);
                            self.c.shift_ri(Shift::Shl, Reg::Rax, 8, false);
                            self.c.alu_rr(Alu::Or, Reg::Rax, Reg::Rcx, false);
                        }
                    }
                    RevOp::Clz => {
                        let width: u8 = if *w64 { 64 } else { 32 };
                        let l_nz = self.c.label();
                        let l_done = self.c.label();
                        self.c.test_rr(Reg::Rax, Reg::Rax, *w64);
                        self.c.jcc(Cc::Ne, l_nz);
                        self.c.mov_ri(Reg::Rax, width as u64);
                        self.c.jmp(l_done);
                        self.c.bind(l_nz);
                        self.c.bsr(Reg::Rcx, Reg::Rax, *w64);
                        self.c.mov_ri(Reg::Rax, (width - 1) as u64);
                        self.c.alu_rr(Alu::Sub, Reg::Rax, Reg::Rcx, false);
                        self.c.bind(l_done);
                    }
                }
                self.st(*rd, Reg::Rax, false);
            }

            Insn::CSel { w64, op, cond, rm, rn, rd } => {
                // Operands live in r8/r9: condition evaluation only ever
                // scratches rax/rcx/rdx.
                self.ld(Reg::R8, *rn, false);
                self.ld(Reg::R9, *rm, false);
                match op {
                    CSelOp::Csel => {}
                    CSelOp::Csinc => { self.c.alu_ri(Alu::Add, Reg::R9, 1, *w64); }
                    CSelOp::Csinv => { self.c.not(Reg::R9, *w64); }
                    CSelOp::Csneg => { self.c.neg(Reg::R9, *w64); }
                }
                let l_have = self.c.label();
                self.emit_jcc_arm(*cond, l_have);
                if *w64 { self.c.mov_rr(Reg::R8, Reg::R9); } else { self.c.mov32_rr(Reg::R8, Reg::R9); }
                self.c.bind(l_have);
                self.st(*rd, Reg::R8, false);
            }

            Insn::Nop => {}

            // ------------------------------------------------ memory ops
            Insn::LdSt { size, op, rt, rn, mode } => {
                self.emit_ldst(pc, *size, *op, *rt, *rn, mode)?;
            }

            Insn::LdStPair { w64, load, rt, rt2, rn, offset, mode } => {
                let size: u8 = if *w64 { 8 } else { 4 };
                let (ea_off, pre, post) = match mode {
                    PairMode::PreIndex => (*offset, true, false),
                    PairMode::PostIndex => (0, false, true),
                    _ => (*offset, false, false),
                };
                self.ld(Reg::R8, *rn, true);
                if ea_off != 0 || pre {
                    self.c.alu_ri(Alu::Add, Reg::R8, ea_off, true);
                }
                if pre {
                    self.st(*rn, Reg::R8, true);
                }
                self.emit_mem_gate(size * 2, pc);
                if *load {
                    // rt ← [r8], rt2 ← [r8+size]
                    match size {
                        8 => {
                            self.c.mov_rm(Reg::Rax, Mem::bd(Reg::R8, 0));
                            self.c.mov_rm(Reg::Rcx, Mem::bd(Reg::R8, 8));
                        }
                        _ => {
                            self.c.mov32_rm(Reg::Rax, Mem::bd(Reg::R8, 0));
                            self.c.mov32_rm(Reg::Rcx, Mem::bd(Reg::R8, 4));
                        }
                    }
                    self.st(*rt, Reg::Rax, false);
                    self.st(*rt2, Reg::Rcx, false);
                } else {
                    self.ld(Reg::Rax, *rt, false);
                    self.ld(Reg::Rcx, *rt2, false);
                    match size {
                        8 => {
                            self.c.mov_mr_size(Mem::bd(Reg::R8, 0), Reg::Rax, 8);
                            self.c.mov_mr_size(Mem::bd(Reg::R8, 8), Reg::Rcx, 8);
                        }
                        _ => {
                            self.c.mov_mr_size(Mem::bd(Reg::R8, 0), Reg::Rax, 4);
                            self.c.mov_mr_size(Mem::bd(Reg::R8, 4), Reg::Rcx, 4);
                        }
                    }
                }
                if post {
                    // writeback is a guest value; reload the plain base
                    self.c.mov_rm(Reg::Rax, if *rn == 31 { so_sp() } else { so_x(*rn) });
                    if *offset != 0 {
                        self.c.alu_ri(Alu::Add, Reg::Rax, *offset, true);
                    }
                    self.st(*rn, Reg::Rax, true);
                }
            }

            Insn::LdrLiteral { size, op, rt, target } => {
                self.c.mov_ri(Reg::R8, *target);
                self.emit_mem_gate(*size, pc);
                self.emit_load_rax(*size, *op);
                self.st(*rt, Reg::Rax, false);
            }

            // ------------------------------------------------ branches
            Insn::Branch { link, target } => {
                if *link {
                    self.c.mov_ri(Reg::Rax, pc + 4);
                    self.st(30, Reg::Rax, false);
                }
                self.emit_exit_to(*target);
                return Ok(true);
            }

            Insn::BranchCond { cond, target } => {
                if matches!(cond, Cond::Al) {
                    self.emit_exit_to(*target);
                    return Ok(true);
                }
                if matches!(cond, Cond::Nv) {
                    self.emit_exit_to(pc + 4);
                    return Ok(true);
                }
                let l_t = self.c.label();
                self.emit_jcc_arm(*cond, l_t);
                // fallthrough path
                self.emit_exit_to(pc + 4);
                self.c.bind(l_t);
                self.emit_exit_to(*target);
                return Ok(true);
            }

            Insn::Cbz { w64, nonzero, rt, target } => {
                self.ld(Reg::Rax, *rt, false);
                self.c.test_rr(Reg::Rax, Reg::Rax, *w64);
                let l_t = self.c.label();
                self.c.jcc(if *nonzero { Cc::Ne } else { Cc::E }, l_t);
                self.emit_exit_to(pc + 4);
                self.c.bind(l_t);
                self.emit_exit_to(*target);
                return Ok(true);
            }

            Insn::Tbz { nonzero, bit, rt, target } => {
                self.ld(Reg::Rax, *rt, false);
                self.c.bt_ri(Reg::Rax, *bit, true);
                let l_t = self.c.label();
                self.c.jcc(if *nonzero { Cc::B } else { Cc::Ae }, l_t);
                self.emit_exit_to(pc + 4);
                self.c.bind(l_t);
                self.emit_exit_to(*target);
                return Ok(true);
            }

            Insn::BranchReg { link, rn, .. } => {
                if *link {
                    self.c.mov_ri(Reg::Rax, pc + 4);
                    self.st(30, Reg::Rax, false);
                }
                self.ld(Reg::Rax, *rn, false);
                self.emit_exit_pc_rax();
                return Ok(true);
            }

            // ------------------------------------------------ system
            Insn::Svc { imm } => {
                self.emit_exit_reason(pc, ExitReason::Svc, *imm as u64);
                return Ok(true);
            }
            Insn::Brk { imm } => {
                self.emit_exit_reason(pc, ExitReason::Breakpoint, *imm as u64);
                return Ok(true);
            }
        }
        Ok(false)
    }

    // -- load/store body ---------------------------------------------------

    fn emit_ldst(&mut self, pc: u64, size: u8, op: LdStOp, rt: u8, rn: u8, mode: &AddrMode) -> Result<()> {
        match mode {
            AddrMode::UnsignedImm { offset } => {
                self.ld(Reg::R8, rn, true);
                if *offset != 0 {
                    self.c.alu_ri(Alu::Add, Reg::R8, *offset as i32, true);
                }
            }
            AddrMode::UnscaledImm { offset } => {
                self.ld(Reg::R8, rn, true);
                if *offset != 0 {
                    self.c.alu_ri(Alu::Add, Reg::R8, *offset, true);
                }
            }
            AddrMode::PreIndex { offset } => {
                self.ld(Reg::R8, rn, true);
                if *offset != 0 {
                    self.c.alu_ri(Alu::Add, Reg::R8, *offset, true);
                }
                self.st(rn, Reg::R8, true);
            }
            AddrMode::PostIndex { .. } => {
                self.ld(Reg::R8, rn, true);
            }
            AddrMode::RegOffset { rm, extend, shift } => {
                self.ld(Reg::R9, *rm, false);
                self.emit_extend(Reg::R9, *extend);
                if *shift != 0 {
                    self.c.shift_ri(Shift::Shl, Reg::R9, *shift, true);
                }
                self.ld(Reg::R8, rn, true);
                self.c.alu_rr(Alu::Add, Reg::R8, Reg::R9, true);
            }
        }
        self.emit_mem_gate(size, pc);
        if op == LdStOp::Store {
            self.ld(Reg::Rax, rt, false);
            self.c.mov_mr_size(Mem::bd(Reg::R8, 0), Reg::Rax, size);
        } else {
            self.emit_load_rax(size, op);
            self.st(rt, Reg::Rax, false);
        }
        if let AddrMode::PostIndex { offset } = mode {
            // writeback from the *guest* base value (r8 is a host pointer now)
            self.ld(Reg::Rax, rn, true);
            if *offset != 0 {
                self.c.alu_ri(Alu::Add, Reg::Rax, *offset, true);
            }
            self.st(rn, Reg::Rax, true);
        }
        Ok(())
    }

    // -- small emitters ----------------------------------------------------

    /// Apply a logical op between rax and a 64-bit mask (imm32 when it
    /// sign-extends back exactly, else via rcx).
    fn logic_with_mask(&mut self, op: Alu, mask: u64, w64: bool) {
        let short = if w64 { mask as i64 as u64 == mask } else { mask <= u32::MAX as u64 };
        if short {
            self.c.alu_ri(op, Reg::Rax, mask as u32 as i32, w64);
        } else {
            self.c.mov_ri(Reg::Rcx, mask);
            self.c.alu_rr(op, Reg::Rax, Reg::Rcx, w64);
        }
    }

    fn emit_shift_imm(&mut self, r: Reg, shift: ShiftType, amt: u8, w64: bool) {
        if amt == 0 {
            return;
        }
        let k = match shift {
            ShiftType::Lsl => Shift::Shl,
            ShiftType::Lsr => Shift::Shr,
            ShiftType::Asr => Shift::Sar,
            ShiftType::Ror => Shift::Ror,
        };
        self.c.shift_ri(k, r, amt, w64);
    }
}

/// Where the saved C flag comes from for logical-with-flags ops.
enum ShifterCarry {
    /// Keep the guest C (shifter amount was 0).
    Keep,
    /// Zero (logical-immediate forms always write C=0).
    Zero,
    /// r10 already holds the shifter carry (captured pre-logical-op).
    PreCaptured,
}