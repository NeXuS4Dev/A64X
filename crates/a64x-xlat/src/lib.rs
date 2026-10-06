//! # a64x-xlat — the binary translator
//!
//! Translates basic blocks of ARM64 (A64) guest code into native x86-64
//! machine code (never interpreted), keeps them in a code cache with block
//! chaining, and can serialize the cache to disk.
//!
//! * [`block`] — translated block + code cache + persistence
//! * [`codegen`] — the ARM64 → x86-64 code generator
//! * [`Trampoline`] — the tiny host-side stub that preserves host
//!   registers and installs the translated-code register conventions
//!   (r15 = &CpuState, r14 = guest memory base) so dispatcher round trips
//!   cost only a ret/call pair
//! * [`Machine`] — the whole executing universe: CpuState + guest memory +
//!   code cache + trampoline, with the classic "run block → handle exit
//!   reason → run next block" dispatcher loop. There is no instruction
//!   interpretation anywhere on the hot path.

#![warn(missing_docs)]

pub mod block;
pub mod codegen;

pub use block::{CodeCache, Link, TranslatedBlock, XlatConfig};

use a64x_core::state::CpuState;
use a64x_core::{ExecBuffer, ExitReason, Memory, Result};
use a64x_x64::{Code, Mem, Reg};
use core::mem::offset_of;

/// Host-side stub that calls into translated code and back.
///
/// Emitted once at startup; calling convention:
/// `extern "C" fn(state: *mut CpuState, entry: *const u8)`.
pub struct Trampoline {
    exec: ExecBuffer,
}

impl Trampoline {
    /// Build the trampoline (SysV on unix, Win64 on Windows via `cfg!`).
    pub fn new() -> Result<Trampoline> {
        let mut c = Code::new();
        // Preserve host callee-saved registers used by translated code.
        c.push(Reg::Rbx);
        c.push(Reg::Rbp);
        c.push(Reg::R12);
        c.push(Reg::R13);
        c.push(Reg::R14);
        c.push(Reg::R15);
        // 6 pushes + return address = 56 bytes; with one filler push the
        // stack is 16-byte aligned at the call into the block.
        c.push(Reg::Rax);

        // Install translated-code register conventions.
        #[cfg(not(windows))]
        {
            c.mov_rr(Reg::R15, Reg::Rdi); // state
            c.mov_rr(Reg::Rax, Reg::Rsi); // entry
        }
        #[cfg(windows)]
        {
            c.mov_rr(Reg::R15, Reg::Rcx); // state
            c.mov_rr(Reg::Rax, Reg::Rdx); // entry
        }
        c.mov_rm(Reg::R14, Mem::bd(Reg::R15, offset_of!(CpuState, mem_base) as i32));
        c.call_r(Reg::Rax);

        // Restore and return.
        c.pop(Reg::Rax);
        c.pop(Reg::R15);
        c.pop(Reg::R14);
        c.pop(Reg::R13);
        c.pop(Reg::R12);
        c.pop(Reg::Rbp);
        c.pop(Reg::Rbx);
        c.ret();
        Ok(Trampoline { exec: ExecBuffer::from_bytes(&c.finish())? })
    }

    /// Enter translated code. `state.mem_base` must be set. Returns after
    /// the block (or chain) returns to the dispatcher; caller inspects
    /// `state`.
    ///
    /// # Safety
    /// `state` must be a valid, fully-initialized CpuState for the entire
    /// call; `entry` must be machine code honoring the A64X block ABI.
    pub unsafe fn call(&self, state: *mut CpuState, entry: *const u8) {
        let f: extern "C" fn(*mut CpuState, *const u8) = core::mem::transmute(self.exec.entry());
        f(state, entry);
    }
}

/// A complete executing guest: state + memory + code cache + trampoline.
///
/// This is the execution core used by the runtime and by the native
/// execution tests: translated x86-64 runs on this very machine.
pub struct Machine {
    /// CPU state (registers, flags, diagnostics).
    pub state: CpuState,
    /// Guest address space.
    pub mem: Memory,
    /// Code cache.
    pub cache: CodeCache,
    tramp: Trampoline,
}

impl Machine {
    /// New machine over an existing address space.
    pub fn new(mem: Memory, cfg: block::XlatConfig) -> Result<Machine> {
        let mut state = CpuState::default();
        state.mem_base = mem.base() as u64;
        state.mem_size = mem.size();
        Ok(Machine { state, mem, cache: CodeCache::new(cfg), tramp: Trampoline::new()? })
    }

    /// Split borrows over every part of the machine. Runtimes need this
    /// so an API context (state+memory) can be long-lived while the
    /// dispatcher keeps touching the code cache / trampoline.
    pub fn split_parts(&mut self) -> (&mut CpuState, &mut Memory, &mut CodeCache, &Trampoline) {
        (&mut self.state, &mut self.mem, &mut self.cache, &self.tramp)
    }

    /// Give the trampoline handle back (e.g. for tests that drive blocks
    /// directly).
    pub fn trampoline(&self) -> &Trampoline {
        &self.tramp
    }

    /// Set the entry PC and mark the guest running.
    pub fn set_entry(&mut self, pc: u64) {
        self.state.pc = pc;
        self.state.running = 1;
        self.state.exit_reason = ExitReason::Ok as u8;
    }

    /// Run one dispatcher *round*: enter at the current PC, let chained
    /// blocks execute until a block returns (budget or control transfer to
    /// an untranslated target). Returns the current exit reason.
    pub fn step(&mut self, budget: u64) -> Result<ExitReason> {
        let pc = self.state.pc;
        let entry = self.cache.get_or_translate(&self.mem, pc)?;
        self.state.budget = budget;
        unsafe {
            self.tramp.call(&mut self.state as *mut CpuState, entry);
        }
        Ok(ExitReason::from(self.state.exit_reason))
    }

    /// Run until the machine stops for a reason other than `Ok`
    /// (SVC, exit, fault, ...) or the budget policy yields.
    pub fn run(&mut self, budget: u64) -> Result<ExitReason> {
        loop {
            let reason = self.step(budget)?;
            if reason != ExitReason::Ok {
                return Ok(reason);
            }
            if self.state.running == 0 {
                return Ok(ExitReason::from(self.state.exit_reason));
            }
        }
    }

    /// Convenience: run a program loaded at `pc` in a fresh address space.
    pub fn execute(&mut self, pc: u64, budget: u64) -> Result<ExitReason> {
        self.set_entry(pc);
        self.run(budget)
    }
}
