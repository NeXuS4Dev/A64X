//! Guest CPU state.
//!
//! Translated x86-64 code keeps the *entire* architectural state of the
//! ARM64 guest in this structure. Register `r15` always points at it while
//! guest code is running (and `r14` caches `mem_base`).
//!
//! Keeping registers in memory (rather than statically renaming them to
//! host registers) is what makes the translator simple and safe: at any
//! block exit the full guest state is coherent, which is required for API
//! marshaling, exceptions and debugging. Hot blocks amortise the traffic;
//! block chaining removes almost all transitions.

/// Register index of the stack pointer (not stored in `x`).
pub const SP: u8 = 31;
/// Register index meaning the zero register in most instruction forms.
pub const XZR: u8 = 31;

/// Offset of the N flag inside `flags`.
pub const N_OFF: usize = 0;
/// Offset of the Z flag inside `flags`.
pub const Z_OFF: usize = 1;
/// Offset of the C flag inside `flags`.
pub const C_OFF: usize = 2;
/// Offset of the V flag inside `flags`.
pub const V_OFF: usize = 3;

/// Why a translated block returned to the dispatcher.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Nothing special; dispatcher should continue (next block or budget).
    Ok = 0,
    /// Guest called ExitProcess (or returned from the entry point).
    Exited = 1,
    /// Translation/guest hit an unimplemented instruction.
    UnimplementedInsn = 2,
    /// Guest executed SVC #n.
    Svc = 3,
    /// Guest executed BRK #n.
    Breakpoint = 4,
    /// Guest memory access failed the bounds check.
    MemoryFault = 5,
    /// Runtime requested a stop (external interrupt / limit).
    Stopped = 6,
}

impl From<u8> for ExitReason {
    fn from(v: u8) -> Self {
        match v {
            1 => ExitReason::Exited,
            2 => ExitReason::UnimplementedInsn,
            3 => ExitReason::Svc,
            4 => ExitReason::Breakpoint,
            5 => ExitReason::MemoryFault,
            6 => ExitReason::Stopped,
            _ => ExitReason::Ok,
        }
    }
}

/// Complete architectural state of one ARM64 guest vCPU.
///
/// Fields are ordered so hot fields (registers, flags) come first.
/// All offsets are computed with `core::mem::offset_of!` by the translator;
/// there is a static assertions test guarding the layout.
#[repr(C)]
pub struct CpuState {
    /// General purpose registers x0..=x30 (`x[30]` is the link register).
    pub x: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// NZCV condition flags, one byte each: `[N, Z, C, V]`.
    ///
    /// Using one byte per flag lets translated code test a condition with a
    /// single `cmp byte [r15+off], 0` instead of masking a packed register.
    pub flags: [u8; 4],
    /// Set by translated code when it returns to the dispatcher.
    pub exit_reason: u8,
    /// Non-zero while the guest is allowed to keep running.
    pub running: u8,
    /// Padding to keep the following fields 8-byte aligned.
    pub _pad0: [u8; 6],
    /// Chain/exit budget. Decremented at every block entry; when it reaches
    /// zero the block returns to the dispatcher, which reloads it. This
    /// bounds how long the guest can stay inside chained native code, so the
    /// runtime always regains control (API calls, limits, interrupts).
    pub budget: u64,
    /// Base pointer of the guest address space (host address of guest 0x0).
    pub mem_base: u64,
    /// Size of the guest address space in bytes (for checked memory access).
    pub mem_size: u64,
    /// Dynamic count of guest instructions retired (statistic / Speed pillar).
    pub insn_count: u64,
    /// Dynamic count of translated blocks entered.
    pub block_count: u64,
    /// Process exit code once `exit_reason == Exited`.
    pub exit_code: u64,
    /// Win32 "last error" value (GetLastError/SetLastError).
    pub last_error: u64,
    /// Scratch: diagnostic info for the current exit reason
    /// (e.g. instruction word, faulting address, SVC number).
    pub aux: [u64; 4],
    /// SIMD&FP registers v0..=v31 as `[low, high]` 64-bit halves.
    ///
    /// Appended after the translator-visible fields so their offsets stay
    /// stable. Adapters use these for double/float arguments and results
    /// (d0/s0 are the low bits of v0).
    pub v: [[u64; 2]; 32],
    /// Floating-point control register (FPCR).
    pub fpcr: u32,
    /// Floating-point status register (FPSR).
    pub fpsr: u32,
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            flags: [0; 4],
            exit_reason: 0,
            running: 0,
            _pad0: [0; 6],
            budget: 0,
            mem_base: 0,
            mem_size: 0,
            insn_count: 0,
            block_count: 0,
            exit_code: 0,
            last_error: 0,
            aux: [0; 4],
            v: [[0; 2]; 32],
            fpcr: 0,
            fpsr: 0,
        }
    }
}

impl CpuState {
    /// Value of the N flag as bool.
    pub fn n(&self) -> bool {
        self.flags[N_OFF] != 0
    }
    /// Value of the Z flag as bool.
    pub fn z(&self) -> bool {
        self.flags[Z_OFF] != 0
    }
    /// Value of the C flag as bool.
    pub fn c(&self) -> bool {
        self.flags[C_OFF] != 0
    }
    /// Value of the V flag as bool.
    pub fn v(&self) -> bool {
        self.flags[V_OFF] != 0
    }

    /// Read a register, mapping index 31 to the zero register.
    pub fn gpr(&self, i: u8) -> u64 {
        if i == XZR {
            0
        } else {
            self.x[i as usize]
        }
    }

    /// Write a register, ignoring writes to the zero register.
    pub fn set_gpr(&mut self, i: u8, v: u64) {
        if i != XZR {
            self.x[i as usize] = v;
        }
    }

    /// Set the result flags of an add (`a + b = res`), all widths.
    pub fn set_add_flags(&mut self, a: u64, b: u64, res: u64, width: u32) {
        let msb = 1u64 << (width - 1);
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
        let (a, b, res) = (a & mask, b & mask, res & mask);
        self.flags[N_OFF] = ((res & msb) != 0) as u8;
        self.flags[Z_OFF] = (res == 0) as u8;
        self.flags[C_OFF] = (a > mask - b) as u8; // a + b overflowed unsigned
        self.flags[V_OFF] = (((a ^ res) & (b ^ res) & msb) != 0) as u8;
    }

    /// Set the result flags of a subtract (`a - b = res`), all widths.
    pub fn set_sub_flags(&mut self, a: u64, b: u64, res: u64, width: u32) {
        let msb = 1u64 << (width - 1);
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
        let (a, b, res) = (a & mask, b & mask, res & mask);
        self.flags[N_OFF] = ((res & msb) != 0) as u8;
        self.flags[Z_OFF] = (res == 0) as u8;
        self.flags[C_OFF] = (a >= b) as u8; // no borrow
        self.flags[V_OFF] = (((a ^ b) & (a ^ res) & msb) != 0) as u8;
    }

    /// Set N/Z from a logical result and force C=V=0
    /// (immediate forms; `carry` is the shifter carry for register forms).
    pub fn set_logic_flags(&mut self, res: u64, width: u32, carry: bool) {
        let msb = 1u64 << (width - 1);
        let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
        let res = res & mask;
        self.flags[N_OFF] = ((res & msb) != 0) as u8;
        self.flags[Z_OFF] = (res == 0) as u8;
        self.flags[C_OFF] = carry as u8;
        self.flags[V_OFF] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn layout_is_stable() {
        assert_eq!(offset_of!(CpuState, x), 0);
        assert_eq!(offset_of!(CpuState, sp), 31 * 8);
        assert_eq!(offset_of!(CpuState, pc), 32 * 8);
        assert_eq!(offset_of!(CpuState, flags), 33 * 8);
        assert_eq!(offset_of!(CpuState, budget) % 8, 0);
        assert!(offset_of!(CpuState, mem_base) % 8 == 0);
        assert!(core::mem::size_of::<CpuState>() % 8 == 0);
        assert!(offset_of!(CpuState, v) >= offset_of!(CpuState, aux));
    }

    #[test]
    fn flag_math() {
        let mut s = CpuState::default();
        s.set_add_flags(0xFFFF_FFFF_FFFF_FFFF, 1, 0, 64);
        assert!(!s.n() && s.z() && s.c() && !s.v());
        s.set_add_flags(i64::MAX as u64, 1, i64::MIN as u64, 64);
        assert!(s.n() && !s.z() && !s.c() && s.v());
        s.set_sub_flags(0, 1, u64::MAX, 64);
        assert!(s.n() && !s.z() && !s.c() && !s.v());
        s.set_sub_flags(5, 5, 0, 64);
        assert!(!s.n() && s.z() && s.c() && !s.v());
        s.set_logic_flags(0x8000_0000, 32, false);
        assert!(s.n() && !s.z() && !s.c() && !s.v());
    }
}
