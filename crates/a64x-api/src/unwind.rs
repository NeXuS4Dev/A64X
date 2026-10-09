//! ARM64 stack unwinding over `.pdata` and `.xdata`.
//!
//! Implements the Microsoft ARM64 unwind model: a function is described by a
//! `RUNTIME_FUNCTION` entry (begin RVA plus either a packed description or
//! the RVA of an `.xdata` record). Unwind codes are interpreted in *undo*
//! order for the prologue and in forward order for epilogues. For a given
//! pc, the codes that have not executed yet (prologue) or that already
//! executed (epilogue) are skipped, so the register state is exact at every
//! instruction. The result is the caller's register state, the establisher
//! frame (the stack pointer after unwinding) and the language handler, if the
//! function declares one.

use crate::ModuleInfo;
use a64x_core::{Error, Memory, Result};

/// `CONTEXT_ARM64_UNWOUND_TO_CALL`: the pc is a return address.
pub(crate) const CONTEXT_UNWOUND_TO_CALL: u32 = 0x2000_0000;
/// CONTEXT_ARM64 architecture flag.
pub(crate) const CONTEXT_ARM64: u32 = 0x0040_0000;
/// CONTEXT_ARM64_CONTROL | INTEGER | FLOATING_POINT.
pub(crate) const CONTEXT_FULL: u32 = CONTEXT_ARM64 | 0x7;
/// Size in bytes of the ARM64 CONTEXT structure.
pub(crate) const CONTEXT_SIZE: u64 = 0x390;

/// Byte offsets inside the ARM64 CONTEXT structure.
pub(crate) mod off {
    /// ContextFlags.
    pub const FLAGS: u64 = 0x00;
    /// X0 (X1..X28 follow at 8-byte steps).
    pub const X0: u64 = 0x08;
    /// Fp (x29).
    pub const FP: u64 = 0xF0;
    /// Lr (x30).
    pub const LR: u64 = 0xF8;
    /// Sp.
    pub const SP: u64 = 0x100;
    /// Pc.
    pub const PC: u64 = 0x108;
    /// V0 (V1..V31 follow at 16-byte steps).
    pub const V0: u64 = 0x110;
    /// Fpcr.
    pub const FPCR: u64 = 0x310;
    /// Fpsr.
    pub const FPSR: u64 = 0x314;
}

/// Machine register state as the unwinder sees it (CONTEXT layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Regs {
    /// x0..x30 (x29 = Fp, x30 = Lr).
    pub x: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// v0..v31 as [low, high].
    pub v: [[u64; 2]; 32],
    /// Floating-point control register.
    pub fpcr: u32,
    /// Floating-point status register.
    pub fpsr: u32,
    /// ContextFlags.
    pub flags: u32,
}

impl Default for Regs {
    fn default() -> Self {
        Regs {
            x: [0; 31],
            sp: 0,
            pc: 0,
            v: [[0; 2]; 32],
            fpcr: 0,
            fpsr: 0,
            flags: CONTEXT_FULL,
        }
    }
}

impl Regs {
    /// Read a CONTEXT structure from guest memory.
    pub(crate) fn read(mem: &Memory, addr: u64) -> Result<Regs> {
        let mut r = Regs {
            flags: mem.read_int(addr + off::FLAGS, 4)? as u32,
            ..Regs::default()
        };
        for (i, x) in r.x.iter_mut().enumerate() {
            *x = mem.read_int(addr + off::X0 + 8 * i as u64, 8)?;
        }
        r.sp = mem.read_int(addr + off::SP, 8)?;
        r.pc = mem.read_int(addr + off::PC, 8)?;
        for (i, v) in r.v.iter_mut().enumerate() {
            v[0] = mem.read_int(addr + off::V0 + 16 * i as u64, 8)?;
            v[1] = mem.read_int(addr + off::V0 + 16 * i as u64 + 8, 8)?;
        }
        r.fpcr = mem.read_int(addr + off::FPCR, 4)? as u32;
        r.fpsr = mem.read_int(addr + off::FPSR, 4)? as u32;
        Ok(r)
    }

    /// Write this state as a CONTEXT structure at `addr`. Only the parts
    /// selected by `flags` (CONTROL, INTEGER, FLOATING_POINT) are written.
    pub(crate) fn write(&self, mem: &mut Memory, addr: u64) -> Result<()> {
        let f = self.flags;
        mem.write_int(addr + off::FLAGS, 4, f as u64)?;
        if f & 0x2 != 0 {
            for (i, x) in self.x.iter().enumerate() {
                mem.write_int(addr + off::X0 + 8 * i as u64, 8, *x)?;
            }
            mem.write_int(addr + off::FP, 8, self.x[29])?;
            mem.write_int(addr + off::LR, 8, self.x[30])?;
        }
        if f & 0x1 != 0 {
            mem.write_int(addr + off::SP, 8, self.sp)?;
            mem.write_int(addr + off::PC, 8, self.pc)?;
        }
        if f & 0x4 != 0 {
            for (i, v) in self.v.iter().enumerate() {
                mem.write_int(addr + off::V0 + 16 * i as u64, 8, v[0])?;
                mem.write_int(addr + off::V0 + 16 * i as u64 + 8, 8, v[1])?;
            }
            mem.write_int(addr + off::FPCR, 4, self.fpcr as u64)?;
            mem.write_int(addr + off::FPSR, 4, self.fpsr as u64)?;
        }
        Ok(())
    }
}

/// Where each non-volatile register was saved (guest addresses, 0 = not
/// saved). Index layout matches KNONVOLATILE_CONTEXT_POINTERS_ARM64:
/// 0..=9 = X19..X28, 10 = Fp, 11 = Lr, 12..=19 = D8..D15.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NvPtrs {
    /// Saved-at addresses.
    pub a: [u64; 20],
}

impl NvPtrs {
    fn x(&mut self, r: usize, addr: u64) {
        let i = match r {
            19..=28 => r - 19,
            29 => 10,
            30 => 11,
            _ => return,
        };
        self.a[i] = addr;
    }

    fn d(&mut self, r: usize, addr: u64) {
        if (8..=15).contains(&r) {
            self.a[12 + r - 8] = addr;
        }
    }
}

/// A function found in `.pdata`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Function {
    /// Module base (VA).
    pub base: u64,
    /// Begin RVA.
    pub begin: u32,
    /// Guest VA of the RUNTIME_FUNCTION entry.
    pub entry: u64,
    /// Second word of the RUNTIME_FUNCTION entry (packed data or xdata RVA).
    pub data: u32,
}

impl Function {
    /// The entry is packed (Flag != 0).
    pub(crate) fn packed(&self) -> bool {
        self.data & 3 != 0
    }
}

/// Find the `RUNTIME_FUNCTION` covering `pc` in the loaded modules.
pub(crate) fn lookup(mem: &Memory, mods: &[ModuleInfo], pc: u64) -> Result<Option<Function>> {
    for m in mods {
        if pc < m.base || pc >= m.base + m.size {
            continue;
        }
        let Some((pdata, psize)) = m.pdata else {
            return Ok(None);
        };
        let rva = (pc - m.base) as u32;
        let n = psize as u64 / 8;
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let begin = mem.read_int(pdata + mid * 8, 4)? as u32;
            if begin <= rva {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return Ok(None);
        }
        let entry = pdata + (lo - 1) * 8;
        let begin = mem.read_int(entry, 4)? as u32;
        let data = mem.read_int(entry + 4, 4)? as u32;
        let len = if data & 3 != 0 {
            (((data >> 2) & 0x7FF) as u64) * 4
        } else {
            let hdr = mem.read_int(m.base + data as u64, 4)? as u32;
            ((hdr & 0x3_FFFF) as u64) * 4
        };
        if rva >= begin && (rva as u64) < begin as u64 + len {
            return Ok(Some(Function {
                base: m.base,
                begin,
                entry,
                data,
            }));
        }
        return Ok(None);
    }
    Ok(None)
}

/// Length of the unwind-code sequence starting at `codes[0]`, counting
/// instructions (custom stack-frame codes do not count).
fn seq_len(codes: &[u8]) -> u64 {
    let mut n = 0;
    let mut i = 0;
    while i < codes.len() {
        let op = codes[i];
        if op == 0xE4 || op == 0xE5 {
            break;
        }
        if op & 0xF8 != 0xE8 {
            n += 1;
        }
        i += code_len(op);
    }
    n
}

/// Byte length of the unwind code starting with `op`.
fn code_len(op: u8) -> usize {
    match op {
        0x00..=0xBF => 1,
        0xC0..=0xDF => 2,
        0xE0 => 4,
        0xE1 => 1,
        0xE2 => 2,
        0xE3..=0xE6 => 1,
        0xE7 => 3,
        _ => 1,
    }
}

/// Mutable unwinding state threaded through the code interpreter.
struct Work<'a> {
    mem: &'a Memory,
    regs: &'a mut Regs,
    ptrs: &'a mut NvPtrs,
    final_from_lr: bool,
}

impl Work<'_> {
    fn load(&self, addr: u64) -> Result<u64> {
        self.mem.read_int(addr, 8)
    }

    /// Restore `count` 64-bit integer registers from the stack. `pos` is in
    /// 8-byte slots relative to sp; a negative `pos` also moves sp down
    /// (pre-indexed store).
    fn restore_x(&mut self, reg: usize, count: usize, pos: i64) -> Result<()> {
        let offset = pos.max(0) as u64;
        for i in 0..count {
            let r = reg + i;
            let at = self.regs.sp + 8 * (i as u64 + offset);
            if r < 31 {
                self.regs.x[r] = self.load(at)?;
            }
            self.ptrs.x(r, at);
        }
        if pos < 0 {
            self.regs.sp = self.regs.sp.wrapping_add((-8 * pos) as u64);
        }
        Ok(())
    }

    fn restore_d(&mut self, reg: usize, count: usize, pos: i64) -> Result<()> {
        let offset = pos.max(0) as u64;
        for i in 0..count {
            let r = reg + i;
            let at = self.regs.sp + 8 * (i as u64 + offset);
            if r < 32 {
                self.regs.v[r][0] = self.load(at)?;
            }
            self.ptrs.d(r, at);
        }
        if pos < 0 {
            self.regs.sp = self.regs.sp.wrapping_add((-8 * pos) as u64);
        }
        Ok(())
    }

    fn restore_q(&mut self, reg: usize, count: usize, pos: i64) -> Result<()> {
        let offset = pos.max(0) as u64;
        for i in 0..count {
            let r = reg + i;
            let at = self.regs.sp + 16 * (i as u64 + offset);
            if r < 32 {
                self.regs.v[r][0] = self.load(at)?;
                self.regs.v[r][1] = self.load(at + 8)?;
            }
            self.ptrs.d(r, at);
        }
        if pos < 0 {
            self.regs.sp = self.regs.sp.wrapping_add((-16 * pos) as u64);
        }
        Ok(())
    }

    /// save_any_reg: `reg` (5 bits + flags), `kind` 0 = x, 1 = d, 2 = q.
    fn any_reg(&mut self, reg: u8, count: usize, kind: u8, pos: i64) -> Result<()> {
        let mut pos = if reg & 0x20 != 0 { -pos - 1 } else { pos };
        let r = (reg & 0x1F) as usize;
        match kind {
            0 => {
                if count > 1 || pos < 0 {
                    pos *= 2;
                }
                self.restore_x(r, count, pos)
            }
            1 => {
                if count > 1 || pos < 0 {
                    pos *= 2;
                }
                self.restore_d(r, count, pos)
            }
            _ => self.restore_q(r, count, pos),
        }
    }
}

/// Interpret an unwind-code sequence. `skip` codes (instructions) at the
/// start are not executed: they describe work the pc has not reached yet
/// (prologue) or work already done (epilogue).
fn run_codes(
    mem: &Memory,
    codes: &[u8],
    mut skip: u64,
    regs: &mut Regs,
    ptrs: &mut NvPtrs,
) -> Result<bool> {
    let mut w = Work {
        mem,
        regs,
        ptrs,
        final_from_lr: true,
    };
    let mut i = 0usize;
    while i < codes.len() && skip > 0 {
        if codes[i] == 0xE4 {
            break;
        }
        i += code_len(codes[i]);
        skip -= 1;
    }
    let mut save_next: usize = 2;
    while i < codes.len() {
        let op = codes[i];
        let len = code_len(op);
        if i + len > codes.len() {
            break;
        }
        let v = if len > 1 {
            ((op as u32) << 8) | codes[i + 1] as u32
        } else {
            op as u32
        };
        let b1 = if len > 1 { codes[i + 1] } else { 0 };
        let z = (v & 0x3F) as i64;
        match op {
            0x00..=0x1F => w.regs.sp = w.regs.sp.wrapping_add(16 * (v & 0x1F) as u64),
            0x20..=0x3F => w.restore_x(19, save_next, -((v & 0x1F) as i64))?,
            0x40..=0x7F => w.restore_x(29, 2, z)?,
            0x80..=0xBF => w.restore_x(29, 2, -z - 1)?,
            0xC0..=0xC7 => w.regs.sp = w.regs.sp.wrapping_add(16 * (v & 0x7FF) as u64),
            0xC8..=0xCB => w.restore_x(19 + ((v >> 6) & 0xF) as usize, save_next, z)?,
            0xCC..=0xCF => w.restore_x(19 + ((v >> 6) & 0xF) as usize, save_next, -z - 1)?,
            0xD0..=0xD3 => w.restore_x(19 + ((v >> 6) & 0xF) as usize, 1, z)?,
            0xD4..=0xD5 => {
                w.restore_x(19 + ((v >> 5) & 0xF) as usize, 1, -(v as i64 & 0x1F) - 1)?
            }
            0xD6..=0xD7 => {
                let r = 19 + 2 * ((v >> 6) & 0x7) as usize;
                w.restore_x(r, 1, z)?;
                w.restore_x(30, 1, z + 1)?;
            }
            0xD8..=0xD9 => w.restore_d(8 + ((v >> 6) & 0x7) as usize, save_next, z)?,
            0xDA..=0xDB => w.restore_d(8 + ((v >> 6) & 0x7) as usize, save_next, -z - 1)?,
            0xDC..=0xDD => w.restore_d(8 + ((v >> 6) & 0x7) as usize, 1, z)?,
            0xDE => w.restore_d(8 + ((v >> 5) & 0x7) as usize, 1, -(v as i64 & 0x3F) - 1)?,
            0xE0 => {
                let n = ((codes[i + 1] as u64) << 16)
                    | ((codes[i + 2] as u64) << 8)
                    | codes[i + 3] as u64;
                w.regs.sp = w.regs.sp.wrapping_add(16 * n);
            }
            0xE1 => w.regs.sp = w.regs.x[29],
            0xE2 => w.regs.sp = w.regs.x[29].wrapping_sub(8 * b1 as u64),
            0xE3 | 0xE4 | 0xE5 => {}
            0xE6 => {
                save_next += 2;
                i += len;
                continue;
            }
            0xE7 => {
                let reg = codes[i + 1];
                let kind = codes[i + 2] >> 6;
                let pos = (codes[i + 2] & 0x3F) as i64;
                let count = if reg & 0x40 != 0 { save_next } else { 1 };
                w.any_reg(reg, count, kind, pos)?;
            }
            0xE9 => {
                // MSFT_OP_MACHINE_FRAME: pc and sp were pushed by the trap.
                let sp = w.regs.sp;
                w.regs.pc = w.load(sp + 8)?;
                w.regs.sp = w.load(sp)?;
                w.regs.flags &= !CONTEXT_UNWOUND_TO_CALL;
                w.final_from_lr = false;
            }
            0xEA => {
                // MSFT_OP_CONTEXT: a full CONTEXT was pushed at sp.
                let flags = w.regs.flags & !CONTEXT_UNWOUND_TO_CALL;
                let src = Regs::read(w.mem, w.regs.sp)?;
                *w.regs = src;
                w.regs.flags = flags | (src.flags & CONTEXT_UNWOUND_TO_CALL);
                w.final_from_lr = false;
            }
            0xEB => {
                return Err(Error::Host(
                    "unwind: EC_CONTEXT frames are not supported".into(),
                ));
            }
            0xEC => {
                w.regs.pc = w.regs.x[30];
                w.regs.flags &= !CONTEXT_UNWOUND_TO_CALL;
                w.final_from_lr = false;
            }
            0xFC => {
                // pac_sign_lr: pointer authentication is not used by this runtime.
            }
            other => {
                return Err(Error::Host(format!(
                    "unwind: unsupported unwind code {other:#04x}"
                )));
            }
        }
        save_next = if op == 0xE6 { save_next } else { 2 };
        i += len;
    }
    Ok(w.final_from_lr)
}

/// Synthesize the packed prologue (in undo order, terminated by `end`).
/// Mirrors the layout the ARM64 packed-unwind format describes.
fn packed_prologue(data: u32) -> (Vec<u8>, u64) {
    let reg_f = ((data >> 13) & 7) as u64;
    let reg_i = ((data >> 16) & 0xF) as u64;
    let homing = (data >> 20) & 1 == 1;
    let cr = (data >> 21) & 3;
    let frame = ((data >> 23) & 0x1FF) as u64;
    let mut int_size = reg_i * 8;
    if cr == 1 {
        int_size += 8;
    }
    let mut fp_size = reg_f * 8;
    if reg_f != 0 {
        fp_size += 8;
    }
    let regsave = (int_size + fp_size + if homing { 64 } else { 0 } + 15) & !15;
    let mut local = (frame * 16) as i64 - regsave as i64;
    let mut homing = homing;
    if homing && reg_i == 0 && reg_f == 0 && cr != 1 {
        local += regsave as i64;
        homing = false;
    }
    let local = local.max(0) as u64;
    let int_regs = int_size / 8;
    let fp_regs = fp_size / 8;
    let saved_regs = regsave / 8;
    let mut c: Vec<u8> = Vec::new();
    let w1 = |b: u8, c: &mut Vec<u8>| c.push(b);
    let w2 = |v: u16, c: &mut Vec<u8>| {
        c.push((v >> 8) as u8);
        c.push(v as u8);
    };
    if cr == 2 || cr == 3 {
        w1(0xE1, &mut c);
        if local <= 512 {
            w1(0x80 | ((local / 8) as u8).wrapping_sub(1), &mut c);
        } else {
            w1(0x40, &mut c);
        }
    }
    if (cr <= 1 && local > 0) || local > 512 {
        if local <= 512 {
            w1((local / 16) as u8, &mut c);
        } else if local <= 4080 {
            w2(0xC000 | (local / 16) as u16, &mut c);
        } else {
            w1(((local - 4080) / 16) as u8, &mut c);
            w2(0xC000 | (4080 / 16) as u16, &mut c);
        }
    }
    if homing {
        for _ in 0..4 {
            w1(0xE3, &mut c);
        }
    }
    if reg_f > 0 {
        if reg_f % 2 == 0 {
            w2(
                (0xDC00 | (reg_f << 6) | (int_regs + fp_regs - 1)) as u16,
                &mut c,
            );
        }
        let mut i = (reg_f + 1) / 2;
        while i > 0 {
            i -= 1;
            if i == 0 && int_size == 0 {
                w2((0xDA00 | (saved_regs - 1)) as u16, &mut c);
            } else {
                w2(
                    (0xD800 | ((2 * i) << 6) | (int_regs + 2 * i)) as u16,
                    &mut c,
                );
            }
        }
    }
    if cr == 1 && reg_i % 2 == 0 {
        if reg_i == 0 {
            w2(
                (0xD400 | ((30 - 19) << 5) | (saved_regs - 1)) as u16,
                &mut c,
            );
        } else {
            w2((0xD000 | ((30 - 19) << 6) | (int_regs - 1)) as u16, &mut c);
        }
    }
    if reg_i > 0 {
        if reg_i % 2 == 1 {
            if cr == 1 {
                w2(
                    (0xD600 | (((reg_i - 1) / 2) << 6) | (int_regs - 2)) as u16,
                    &mut c,
                );
                if reg_i == 1 {
                    w1((saved_regs / 2) as u8, &mut c);
                }
            } else if reg_i == 1 {
                w2((0xD400 | (saved_regs - 1)) as u16, &mut c);
            } else {
                w2(
                    (0xD000 | ((int_regs - 1) << 6) | (int_regs - 1)) as u16,
                    &mut c,
                );
            }
        }
        let mut i = reg_i / 2;
        while i > 0 {
            i -= 1;
            if i != 0 {
                w2((0xC800 | ((2 * i) << 6) | (2 * i)) as u16, &mut c);
            } else {
                w2((0xCC00 | (saved_regs - 1)) as u16, &mut c);
            }
        }
    }
    if cr == 2 {
        w1(0xFC, &mut c);
    }
    w1(0xE4, &mut c);
    let n = seq_len(&c);
    (c, n)
}

/// Unwind a packed function (Flag 1 or 2). Returns `final_from_lr`.
fn unwind_packed(
    mem: &Memory,
    f: &Function,
    pc: u64,
    regs: &mut Regs,
    ptrs: &mut NvPtrs,
) -> Result<bool> {
    if f.data & 3 == 2 {
        // no prologue: nothing was saved, the return address is still in lr
        return Ok(true);
    }
    let flen = ((f.data >> 2) & 0x7FF) as u64;
    let offset = (pc - f.base - f.begin as u64) / 4;
    let (codes, plen) = packed_prologue(f.data);
    if offset < plen {
        return run_codes(mem, &codes, plen - offset, regs, ptrs);
    }
    let epi_start = flen as i64 - (plen as i64 + 1);
    if (offset as i64) >= epi_start {
        let skip = offset as i64 - epi_start;
        return run_codes(mem, &codes, skip.max(0) as u64, regs, ptrs);
    }
    run_codes(mem, &codes, 0, regs, ptrs)
}

/// Unwind a function described by `.xdata`. Returns
/// `(final_from_lr, handler RVA, handler data VA)`.
fn unwind_full(
    mem: &Memory,
    f: &Function,
    pc: u64,
    regs: &mut Regs,
    ptrs: &mut NvPtrs,
) -> Result<(bool, u32, u64)> {
    let xdata = f.base + f.data as u64;
    let w0 = mem.read_int(xdata, 4)? as u32;
    let flen = (w0 & 0x3_FFFF) as u64;
    let x_present = (w0 >> 20) & 1 == 1;
    let epi_in_hdr = (w0 >> 21) & 1 == 1;
    let mut epilogs = ((w0 >> 22) & 0x1F) as u64;
    let mut codes_words = ((w0 >> 27) & 0x1F) as u64;
    let mut hdr = 4u64;
    if codes_words == 0 && epilogs == 0 {
        let w1 = mem.read_int(xdata + 4, 4)? as u32;
        epilogs = (w1 & 0xFFFF) as u64;
        codes_words = ((w1 >> 16) & 0xFF) as u64;
        hdr = 8;
    }
    let scopes_at = xdata + hdr;
    let scope_bytes = if epi_in_hdr { 0 } else { epilogs * 4 };
    let codes_at = scopes_at + scope_bytes;
    let codes_len = codes_words * 4;
    let codes = mem.slice(codes_at, codes_len)?.to_vec();
    let offset = (pc - f.base - f.begin as u64) / 4;

    let plen = seq_len(&codes);
    if offset < plen {
        let fl = run_codes(mem, &codes, plen - offset, regs, ptrs)?;
        return Ok((fl, 0, 0));
    }
    if !epi_in_hdr {
        for i in 0..epilogs {
            let s = mem.read_int(scopes_at + i * 4, 4)? as u32;
            let start = (s & 0x3_FFFF) as u64;
            let index = ((s >> 22) & 0x3FF) as usize;
            if offset < start {
                break;
            }
            if index > codes.len() {
                continue;
            }
            let ep = &codes[index..];
            let len = seq_len(ep);
            if offset - start < (codes.len() - index) as u64 && offset <= start + len {
                let fl = run_codes(mem, ep, offset - start, regs, ptrs)?;
                return Ok((fl, 0, 0));
            }
        }
    } else {
        let at = epilogs as usize;
        if at <= codes.len() {
            let ep = &codes[at..];
            let len = seq_len(ep) + 1;
            if flen >= len && offset + len >= flen {
                let fl = run_codes(mem, ep, offset - (flen - len), regs, ptrs)?;
                return Ok((fl, 0, 0));
            }
        }
    }
    let fl = run_codes(mem, &codes, 0, regs, ptrs)?;
    if x_present {
        let handler_at = codes_at + codes_len;
        let rva = mem.read_int(handler_at, 4)? as u32;
        return Ok((fl, rva, handler_at + 4));
    }
    Ok((fl, 0, 0))
}

/// Result of unwinding one frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Unwound {
    /// Establisher frame: the stack pointer of the caller after unwinding.
    pub frame: u64,
    /// Language handler VA (0 = none).
    pub handler: u64,
    /// Handler data VA (valid when `handler != 0`).
    pub handler_data: u64,
    /// Image base of the function (0 when there is none).
    pub image_base: u64,
    /// Guest VA of the RUNTIME_FUNCTION entry (0 when there is none).
    pub entry: u64,
}

/// RtlVirtualUnwind: unwind `regs` (the frame whose pc is `regs.pc`) to its
/// caller. `pc` is the address to look up (usually `regs.pc`; `pc - 4` for
/// frames that are already unwound to a call).
pub(crate) fn virtual_unwind(
    mem: &Memory,
    mods: &[ModuleInfo],
    regs: &mut Regs,
    pc: u64,
    ptrs: &mut NvPtrs,
) -> Result<Unwound> {
    regs.flags |= CONTEXT_UNWOUND_TO_CALL;
    let Some(f) = lookup(mem, mods, pc)? else {
        regs.pc = regs.x[30];
        return Ok(Unwound {
            frame: regs.sp,
            handler: 0,
            handler_data: 0,
            image_base: 0,
            entry: 0,
        });
    };
    let (final_lr, handler, hdata) = if f.packed() {
        (unwind_packed(mem, &f, pc, regs, ptrs)?, 0, 0)
    } else {
        unwind_full(mem, &f, pc, regs, ptrs)?
    };
    if final_lr {
        regs.pc = regs.x[30];
    }
    let handler_va = if handler != 0 {
        f.base + handler as u64
    } else {
        0
    };
    Ok(Unwound {
        frame: regs.sp,
        handler: handler_va,
        handler_data: hdata,
        image_base: f.base,
        entry: f.entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Memory {
        Memory::new(0x10000).expect("memory")
    }

    #[test]
    fn code_lengths_match_the_format() {
        assert_eq!(code_len(0x05), 1);
        assert_eq!(code_len(0xC3), 2);
        assert_eq!(code_len(0xE0), 4);
        assert_eq!(code_len(0xE2), 2);
        assert_eq!(code_len(0xE7), 3);
        assert_eq!(code_len(0xE4), 1);
    }

    #[test]
    fn prologue_save_fplr_x_then_set_fp_unwinds() {
        // stp x29, x30, [sp, #-16]! ; mov x29, sp   (pc after both instructions)
        let mut m = mem();
        m.write_int(0x1000, 8, 0x1111).unwrap(); // saved x29 at new sp
        m.write_int(0x1008, 8, 0x2222).unwrap(); // saved x30
        let codes = [0xE1u8, 0x81, 0xE4]; // set_fp ; save_fplr_x of 16 bytes ; end
        let mut r = Regs::default();
        r.sp = 0x1000;
        r.x[29] = 0x1000;
        r.x[30] = 0x9999;
        let mut p = NvPtrs::default();
        // pc is in the body: skip nothing, undo everything
        run_codes(&m, &codes, 0, &mut r, &mut p).unwrap();
        assert_eq!(r.sp, 0x1010);
        assert_eq!(r.x[29], 0x1111);
        assert_eq!(r.x[30], 0x2222);
        assert_eq!(p.a[10], 0x1000);
        assert_eq!(p.a[11], 0x1008);
    }

    #[test]
    fn packed_leaf_without_saves_returns_through_lr() {
        // flag=1, FunctionLength=4 (16 bytes), no saves, frame size 0
        let data = 1u32 | (4 << 2);
        let (codes, plen) = packed_prologue(data);
        assert_eq!(plen, 0);
        assert_eq!(codes, vec![0xE4]);
    }

    #[test]
    fn full_xdata_prologue_unwinds_to_the_caller() {
        // stp x29, x30, [sp, #-48]! ; mov x29, sp ; sub sp, sp, #16 ; <body>
        let mut m = Memory::new(0x100_0000).expect("memory");
        let base = 0x40_0000u64;
        let pdata = 0x20_0000u64;
        // RUNTIME_FUNCTION { begin 0x1000, unwind 0x2000 }
        m.write_int(pdata, 4, 0x1000).unwrap();
        m.write_int(pdata + 4, 4, 0x2000).unwrap();
        // xdata: FunctionLength 10 instructions, one word of unwind codes
        m.write_int(base + 0x2000, 4, 10 | (1 << 27)).unwrap();
        // undo order: alloc_s 16, set_fp, save_fplr_x 48, end
        m.write(base + 0x2004, &[0x01, 0xE1, 0x85, 0xE4]).unwrap();
        let entry_sp = 0x30_0000u64;
        m.write_int(entry_sp - 48, 8, 0xAAA).unwrap(); // caller's x29
        m.write_int(entry_sp - 40, 8, 0xBBB).unwrap(); // return address
        let module = ModuleInfo {
            path: "t.exe".into(),
            base,
            size: 0x10000,
            sections: Vec::new(),
            pdata: Some((pdata, 8)),
            exports: Vec::new(),
        };
        let mut regs = Regs::default();
        regs.sp = entry_sp - 64;
        regs.x[29] = entry_sp - 48;
        regs.x[30] = 0x999;
        let mut ptrs = NvPtrs::default();
        let uw = virtual_unwind(&m, std::slice::from_ref(&module), &mut regs, base + 0x1010, &mut ptrs).unwrap();
        assert_eq!(regs.sp, entry_sp, "stack pointer returns to the caller");
        assert_eq!(regs.pc, 0xBBB, "pc comes from the saved return address");
        assert_eq!(regs.x[29], 0xAAA, "caller's frame pointer is restored");
        assert_eq!(uw.frame, entry_sp);
        assert_eq!(uw.handler, 0);
        assert_eq!(ptrs.a[11], entry_sp - 40, "lr is recorded where it was saved");
    }

    #[test]
    fn regs_round_trip_through_context_layout() {
        let mut m = mem();
        let mut r = Regs::default();
        r.x[5] = 0xDEAD;
        r.sp = 0x2000;
        r.pc = 0x3000;
        r.v[9][0] = 0x55;
        r.flags = CONTEXT_FULL;
        r.write(&mut m, 0x4000).unwrap();
        let back = Regs::read(&m, 0x4000).unwrap();
        assert_eq!(back.x[5], 0xDEAD);
        assert_eq!(back.sp, 0x2000);
        assert_eq!(back.pc, 0x3000);
        assert_eq!(back.v[9][0], 0x55);
    }
}
