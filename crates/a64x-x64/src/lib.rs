//! # a64x-x64
//!
//! Minimal, dependency-free x86-64 machine-code emitter for the A64X
//! translator. Encodes exactly the instruction forms the block translator
//! needs — ALU ops, moves/sign-extends, shifts, mul/div, conditional
//! moves and jumps — with REX/ModRM/SIB/disp handled automatically.
//!
//! ```
//! use a64x_x64::{Code, Reg, Mem, Cc};
//! let mut c = Code::new();
//! c.mov_ri(Reg::Rax, 0x1122_3344_5566_7788);
//! c.mov_mr(Mem::bd(Reg::Rbx, 0x10), Reg::Rax);
//! let l = c.label();
//! c.bind(l);
//! c.jcc(Cc::Ne, l);
//! let bytes = c.finish();
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// General purpose registers, encoded by hardware number (0..=15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    /// rax
    Rax = 0,
    /// rcx
    Rcx = 1,
    /// rdx
    Rdx = 2,
    /// rbx
    Rbx = 3,
    /// rsp (uses SIB as base)
    Rsp = 4,
    /// rbp
    Rbp = 5,
    /// rsi
    Rsi = 6,
    /// rdi
    Rdi = 7,
    /// r8
    R8 = 8,
    /// r9
    R9 = 9,
    /// r10
    R10 = 10,
    /// r11
    R11 = 11,
    /// r12 (uses SIB as base)
    R12 = 12,
    /// r13
    R13 = 13,
    /// r14
    R14 = 14,
    /// r15
    R15 = 15,
}

impl Reg {
    #[inline]
    fn low(self) -> u8 {
        self as u8 & 7
    }
    #[inline]
    fn high(self) -> bool {
        self as u8 >= 8
    }
    /// All 16 registers, for tests.
    pub const ALL: [Reg; 16] = [
        Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx, Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
        Reg::R8, Reg::R9, Reg::R10, Reg::R11, Reg::R12, Reg::R13, Reg::R14, Reg::R15,
    ];
}

/// Condition codes (jcc/setcc/cmovcc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cc {
    /// overflow
    O = 0x0,
    /// not overflow
    No = 0x1,
    /// below (unsigned, CF=1)
    B = 0x2,
    /// above or equal (CF=0); also NotBelow
    Ae = 0x3,
    /// equal / zero
    E = 0x4,
    /// not equal / not zero
    Ne = 0x5,
    /// below or equal (unsigned)
    Be = 0x6,
    /// above (unsigned)
    A = 0x7,
    /// sign
    S = 0x8,
    /// not sign
    Ns = 0x9,
    /// parity even
    Pe = 0xA,
    /// parity odd
    Po = 0xB,
    /// less (signed)
    L = 0xC,
    /// greater or equal (signed)
    Ge = 0xD,
    /// less or equal (signed)
    Le = 0xE,
    /// greater (signed)
    G = 0xF,
}

/// Memory operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    base: Option<Reg>,
    index: Option<(Reg, u8)>, // scale 1,2,4,8
    disp: i32,
}

impl Mem {
    /// `[base + disp]`
    pub fn bd(base: Reg, disp: i32) -> Mem {
        Mem { base: Some(base), index: None, disp }
    }
    /// `[base + index]` (scale 1, disp 0).
    pub fn bi(base: Reg, index: Reg) -> Mem {
        Mem { base: Some(base), index: Some((index, 1)), disp: 0 }
    }
    /// `[base + index*scale + disp]`
    pub fn bid(base: Reg, index: Reg, scale: u8, disp: i32) -> Mem {
        debug_assert!(matches!(scale, 1 | 2 | 4 | 8));
        Mem { base: Some(base), index: Some((index, scale)), disp }
    }
    /// `[rip + disp]` (32-bit displacement).
    pub fn rip(disp: i32) -> Mem {
        Mem { base: None, index: None, disp }
    }
}

/// ALU group opcodes (add/or/adc/sbb/and/sub/xor/cmp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Alu {
    /// add
    Add = 0,
    /// or
    Or = 1,
    /// adc
    Adc = 2,
    /// sbb
    Sbb = 3,
    /// and
    And = 4,
    /// sub
    Sub = 5,
    /// xor
    Xor = 6,
    /// cmp
    Cmp = 7,
}

/// Shift/rotate group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Shift {
    /// rol
    Rol = 0,
    /// ror
    Ror = 1,
    /// shl
    Shl = 4,
    /// shr (logical)
    Shr = 5,
    /// sar (arithmetic)
    Sar = 7,
}

/// Unary F6/F7 group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Unary {
    /// test r/m, imm32
    Test = 0,
    /// not
    Not = 2,
    /// neg
    Neg = 3,
    /// mul (unsigned, rdx:rax)
    Mul = 4,
    /// imul (one-operand)
    Imul = 5,
    /// div (unsigned)
    Div = 6,
    /// idiv (signed)
    Idiv = 7,
}

/// Jump/label reference.
pub type Label = u32;

/// Accumulating code buffer with label fixups.
pub struct Code {
    buf: Vec<u8>,
    labels: Vec<Option<u32>>,
    patches: Vec<(u32, u32)>, // (position of rel32 field, label id)
}

impl Default for Code {
    fn default() -> Self {
        Self::new()
    }
}

impl Code {
    /// New empty buffer.
    pub fn new() -> Code {
        Code { buf: Vec::with_capacity(512), labels: Vec::new(), patches: Vec::new() }
    }

    /// Current offset.
    pub fn pos(&self) -> u32 {
        self.buf.len() as u32
    }

    /// Raw bytes out.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Finish (panics if a label was never bound).
    pub fn finish(mut self) -> Vec<u8> {
        self.resolve_patches();
        self.buf
    }

    fn resolve_patches(&mut self) {
        for (pos, lab) in self.patches.drain(..) {
            let target = self.labels[lab as usize].expect("unbound label");
            let rel = target as i64 - (pos as i64 + 4);
            self.buf[pos as usize..pos as usize + 4].copy_from_slice(&(rel as i32).to_le_bytes());
        }
    }

    /// Allocate a new label id.
    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        (self.labels.len() - 1) as Label
    }

    /// Bind a label at the current position.
    pub fn bind(&mut self, l: Label) {
        assert!(self.labels[l as usize].is_none(), "label redefined");
        self.labels[l as usize] = Some(self.pos());
    }

    // ---- byte-level helpers -------------------------------------------------

    #[inline]
    fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    #[inline]
    fn u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    #[inline]
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Emit REX prefix if any bit is needed (`w` forces REX.W for 64-bit ops).
    fn rex(&mut self, w: bool, r: bool, x: bool, b: bool) {
        if w || r || x || b {
            self.u8(0x40 | (w as u8) << 3 | (r as u8) << 2 | (x as u8) << 1 | b as u8);
        }
    }

    /// Emit ModRM + SIB + displacement for an operand in r/m with register
    /// already chosen in the `reg` field. `w` decides disp handling for RBP/R13.
    fn modrm_operand(&mut self, reg_field: Reg, rm: &Mem, force_rex_b: bool, force_rex_x: bool) {
        // Encoding rules:
        //  - base rsp/r12: modrm.rm=100 + SIB byte (with index=100 (none), base=rsp/r12)
        //  - base rbp/r13 with disp==0: must use mod=01 disp8=0
        //  - base None: mod=00, rm=101, disp32 absolute (we use it for rip-relative,
        //    which shares encoding: [rip+disp32] is rm=101 mod=00)
        //  - index present: SIB; index rsp is illegal (but we allow and it means none)
        let modrm_mod;
        match rm.base {
            Some(base) => {
                modrm_mod = match rm.disp {
                    0 if base != Reg::Rbp && base != Reg::R13 => 0b00,
                    d if d >= -128 && d <= 127 => 0b01,
                    _ => 0b10,
                };
                let need_sib = rm.index.is_some() || base == Reg::Rsp || base == Reg::R12;
                if need_sib {
                    self.u8((modrm_mod << 6) | (reg_field.low() << 3) | 0b100);
                    let (idx, scale) = match rm.index {
                        Some((i, s)) if i != Reg::Rsp => (i.low(), s.trailing_zeros() as u8),
                        _ => (0b100, 0), // no index
                    };
                    self.u8((scale << 6) | (idx << 3) | base.low());
                } else {
                    self.u8((modrm_mod << 6) | (reg_field.low() << 3) | base.low());
                }
                match modrm_mod {
                    0b01 => self.u8(rm.disp as i8 as u8),
                    0b10 => self.u32(rm.disp as u32),
                    _ => {}
                }
                let _ = force_rex_b;
                let _ = force_rex_x;
                let _ = modrm_mod;
            }
            None => {
                // rip-relative / absolute: mod=00 rm=101 disp32
                modrm_mod = 0b00;
                self.u8((modrm_mod << 6) | (reg_field.low() << 3) | 0b101);
                self.u32(rm.disp as u32);
            }
        }
    }

    /// Emit a `opcode, reg, r/m(Mem)` instruction; `w` = 64-bit form.
    fn op_mr(&mut self, op: u8, reg: Reg, m: Mem, w: bool) {
        self.rex(w, reg.high(), m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(op);
        self.modrm_operand(reg, &m, false, false);
    }

    /// Emit a `opcode, r/m(Mem), reg` instruction.
    fn op_rm(&mut self, op: u8, m: Mem, reg: Reg, w: bool) {
        self.op_mr(op, reg, m, w);
    }

    /// Emit `opcode, reg, reg` (any direction).
    fn op_rr(&mut self, op: u8, reg: Reg, rm: Reg, w: bool) {
        self.rex(w, reg.high(), false, rm.high());
        self.u8(op);
        self.u8(0b11 << 6 | (reg.low() << 3) | rm.low());
    }

    // ---- public instruction set ---------------------------------------------


    /// Compare/test memory with immediate (sign-extended imm32, imm8 when
    /// it fits — mirrors [`Code::alu_ri`].
    pub fn alu_mi(&mut self, op: Alu, m: Mem, imm: i32, w: bool) -> &mut Self {
        self.rex(w, false, m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        if (-128..=127).contains(&imm) {
            self.u8(0x83);
            self.modrm_operand_ext(op as u8, &m);
            self.u8(imm as i8 as u8);
        } else {
            self.u8(0x81);
            self.modrm_operand_ext(op as u8, &m);
            self.u32(imm as u32);
        }
        self
    }

    /// `movsx r64, [m32]`? — use [`Code::movsx_rm`] for byte/word and this
    /// for dword (MOVSXD).
    pub fn movsxd_rm(&mut self, dst: Reg, m: Mem) -> &mut Self {
        self.op_mr(0x63, dst, m, true);
        self
    }

    /// Store a register to memory at the given size in bytes (1/2/4/8).
    pub fn mov_mr_size(&mut self, m: Mem, src: Reg, size: u8) -> &mut Self {
        match size {
            1 => self.mov_mr8(m, src),
            2 => self.mov_mr16(m, src),
            4 => self.mov32_mr(m, src),
            8 => self.mov_mr(m, src),
            _ => unreachable!("store size {size}"),
        }
    }

    /// Load from memory at the given size in bytes, zero-extending (1/2/4/8).
    pub fn movzx_load(&mut self, dst: Reg, m: Mem, size: u8) -> &mut Self {
        match size {
            1 | 2 => self.movzx_rm(dst, m, size),
            4 => self.mov32_rm(dst, m),
            8 => self.mov_rm(dst, m),
            _ => unreachable!("load size {size}"),
        }
    }

    /// Load from memory at the given size in bytes, sign-extending (1/2/4/8).
    pub fn movsx_load(&mut self, dst: Reg, m: Mem, size: u8) -> &mut Self {
        match size {
            1 | 2 => self.movsx_rm(dst, m, size, true),
            4 => self.movsxd_rm(dst, m),
            8 => self.mov_rm(dst, m),
            _ => unreachable!("load size {size}"),
        }
    }

    /// Single-operand `imul r/m` (F7 /5): rdx:rax = rax * r/m.
    pub fn imul_r(&mut self, rm: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Imul, rm, w)
    }

    /// Two-operand `imul dst, src` (0F AF); wraps [`Code::imul2`].
    pub fn imul_rr(&mut self, dst: Reg, src: Reg, w: bool) -> &mut Self {
        self.imul2(dst, src, w)
    }

    /// `mul r/m` (F7 /4): rdx:rax = rax * r/m (unsigned).
    pub fn mul_r(&mut self, rm: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Mul, rm, w)
    }

    /// `div r/m` (F7 /6): rax = rdx:rax / r/m, rdx = remainder (unsigned).
    pub fn div_r(&mut self, rm: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Div, rm, w)
    }

    /// `idiv r/m` (F7 /7): signed division.
    pub fn idiv_r(&mut self, rm: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Idiv, rm, w)
    }

    /// `bswap r64` (0F C8+rd).
    pub fn bswap(&mut self, dst: Reg, w: bool) -> &mut Self {
        self.rex(w, false, false, dst.high());
        self.u8(0x0F);
        self.u8(0xC8 + dst.low());
        self
    }

    /// `bsr dst, src` (0F BD) — index of the most significant set bit;
    /// dst is UNDEFINED when src == 0 (caller handles that case).
    pub fn bsr(&mut self, dst: Reg, src: Reg, w: bool) -> &mut Self {
        self.rex(w, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(0xBD);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// `lzcnt dst, src` (F3 0F BD) — count leading zeros, defined for 0.
    pub fn lzcnt(&mut self, dst: Reg, src: Reg, w: bool) -> &mut Self {
        self.u8(0xF3);
        self.rex(w, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(0xBD);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// Emit a NOP sled of `n` bytes (multi-byte nops for n >= 2).
    pub fn nops(&mut self, mut n: usize) -> &mut Self {
        while n >= 9 {
            self.raw(&[0x66, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0]);
            n -= 9;
        }
        match n {
            0 => {}
            1 => self.u8(0x90),
            2 => self.raw(&[0x66, 0x90]),
            3 => self.raw(&[0x0F, 0x1F, 0x00]),
            4 => self.raw(&[0x0F, 0x1F, 0x40, 0x00]),
            5 => self.raw(&[0x0F, 0x1F, 0x44, 0x00, 0x00]),
            6 => self.raw(&[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]),
            7 => self.raw(&[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]),
            _ => self.raw(&[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
        }
        self
    }

    fn modrm_operand_ext(&mut self, op_field: u8, m: &Mem) {
        let reg_field = match op_field {
            0 => Reg::Rax,
            1 => Reg::Rcx,
            2 => Reg::Rdx,
            3 => Reg::Rbx,
            4 => Reg::Rsp,
            5 => Reg::Rbp,
            6 => Reg::Rsi,
            _ => Reg::Rdi,
        };
        self.modrm_operand(reg_field, m, false, false);
    }

    /// `mov r64, imm64` (B8+r).
    pub fn mov_ri(&mut self, dst: Reg, imm: u64) -> &mut Self {
        self.rex(true, false, false, dst.high());
        self.u8(0xB8 + dst.low());
        self.u64(imm as u64);
        self
    }

    /// `mov r32, imm32` (zero-extends to 64).
    pub fn mov32_ri(&mut self, dst: Reg, imm: u32) -> &mut Self {
        self.rex(false, false, false, dst.high());
        self.u8(0xB8 + dst.low());
        self.u32(imm);
        self
    }

    /// `mov r, r`.
    pub fn mov_rr(&mut self, dst: Reg, src: Reg) -> &mut Self {
        self.op_rr(0x89, src, dst, true);
        self
    }

    /// `mov r32, r32` (clears upper half).
    pub fn mov32_rr(&mut self, dst: Reg, src: Reg) -> &mut Self {
        self.op_rr(0x89, src, dst, false);
        self
    }

    /// `mov r, [m]`.
    pub fn mov_rm(&mut self, dst: Reg, m: Mem) -> &mut Self {
        self.op_mr(0x8B, dst, m, true);
        self
    }

    /// `mov r32, [m]` (zero-extend load).
    pub fn mov32_rm(&mut self, dst: Reg, m: Mem) -> &mut Self {
        self.op_mr(0x8B, dst, m, false);
        self
    }

    /// `mov [m], r`.
    pub fn mov_mr(&mut self, m: Mem, src: Reg) -> &mut Self {
        self.op_rm(0x89, m, src, true);
        self
    }

    /// `mov [m], r32`.
    pub fn mov32_mr(&mut self, m: Mem, src: Reg) -> &mut Self {
        self.op_rm(0x89, m, src, false);
        self
    }

    /// `mov byte [m], r8` (reg must be low 8 for encoding without REX).
    pub fn mov_mr8(&mut self, m: Mem, src: Reg) -> &mut Self {
        // 88 /r; note: with REX the four low regs map to al/cl/dl/bl fine.
        self.rex(false, src.high(), m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0x88);
        self.modrm_operand(src, &m, false, false);
        self
    }

    /// `mov word [m], r16`.
    pub fn mov_mr16(&mut self, m: Mem, src: Reg) -> &mut Self {
        self.u8(0x66);
        self.rex(false, src.high(), m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0x89);
        self.modrm_operand(src, &m, false, false);
        self
    }

    /// `mov qword [m], imm32` (sign-extended).
    pub fn mov_mi(&mut self, m: Mem, imm: i32) -> &mut Self {
        self.rex(true, false, m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0xC7);
        self.modrm_operand(Reg::Rax, &m, false, false);
        self.u32(imm as u32);
        self
    }

    /// `mov dword [m], imm32`.
    pub fn mov32_mi(&mut self, m: Mem, imm: u32) -> &mut Self {
        self.rex(false, false, m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0xC7);
        self.modrm_operand(Reg::Rax, &m, false, false);
        self.u32(imm);
        self
    }

    /// `mov byte [m], imm8`.
    pub fn mov_mi8(&mut self, m: Mem, imm: u8) -> &mut Self {
        self.rex(false, false, m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0xC6);
        self.modrm_operand(Reg::Rax, &m, false, false);
        self.u8(imm);
        self
    }

    /// `movzx r64, byte/word [m]`.
    pub fn movzx_rm(&mut self, dst: Reg, m: Mem, src_size: u8) -> &mut Self {
        debug_assert!(src_size == 1 || src_size == 2);
        let op = if src_size == 1 { 0xB6 } else { 0xB7 };
        self.rex(true, dst.high(), m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0x0F);
        self.u8(op);
        self.modrm_operand(dst, &m, false, false);
        self
    }

    /// `movzx r64, r8/r16`.
    pub fn movzx_rr(&mut self, dst: Reg, src: Reg, src_size: u8) -> &mut Self {
        debug_assert!(src_size == 1 || src_size == 2);
        let op = if src_size == 1 { 0xB6 } else { 0xB7 };
        self.rex(true, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(op);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// `movsx r, r/m8` / `r/m16`; `w` selects a 64-bit destination
    /// (REX.W); for a 32-bit source use [`Code::movsxd`].
    pub fn movsx_rm(&mut self, dst: Reg, m: Mem, src_size: u8, w: bool) -> &mut Self {
        debug_assert!(src_size == 1 || src_size == 2);
        let op = if src_size == 1 { 0xBE } else { 0xBF };
        self.rex(w, dst.high(), m.index.map(|(i, _)| i.high()).unwrap_or(false), m.base.map(|b| b.high()).unwrap_or(false));
        self.u8(0x0F);
        self.u8(op);
        self.modrm_operand(dst, &m, false, false);
        self
    }

    /// `movsx r, r8/r16` (see [`Code::movsx_rm`]).
    pub fn movsx_rr(&mut self, dst: Reg, src: Reg, src_size: u8, w: bool) -> &mut Self {
        debug_assert!(src_size == 1 || src_size == 2);
        let op = if src_size == 1 { 0xBE } else { 0xBF };
        self.rex(w, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(op);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// `movsxd r64, r/m32`.
    pub fn movsxd(&mut self, dst: Reg, src: Reg) -> &mut Self {
        self.op_rr(0x63, dst, src, true);
        self
    }

    /// Alias for [`Code::movsxd`] (register form reads naturally).
    pub fn movsxd_rr(&mut self, dst: Reg, src: Reg) -> &mut Self {
        self.movsxd(dst, src)
    }

    /// `lea r, [m]`.
    pub fn lea(&mut self, dst: Reg, m: Mem) -> &mut Self {
        self.op_mr(0x8D, dst, m, true);
        self
    }

    /// ALU op `dst = dst op src` (register form).
    pub fn alu_rr(&mut self, op: Alu, dst: Reg, src: Reg, w: bool) -> &mut Self {
        let opc = (op as u8) << 3 | 0b01; // r, rm <- 01 /r
        self.op_rr(opc, src, dst, w);
        self
    }

    /// ALU op with sign-extended immediate (imm8 when it fits, else imm32).
    pub fn alu_ri(&mut self, op: Alu, dst: Reg, imm: i32, w: bool) -> &mut Self {
        self.rex(w, false, false, dst.high());
        if (-128..=127).contains(&imm) {
            self.u8(0x83);
            self.u8(0b11 << 6 | ((op as u8) << 3) | dst.low());
            self.u8(imm as i8 as u8);
        } else {
            self.u8(0x81);
            self.u8(0b11 << 6 | ((op as u8) << 3) | dst.low());
            self.u32(imm as u32);
        }
        self
    }

    /// `test r, r`.
    pub fn test_rr(&mut self, a: Reg, b: Reg, w: bool) -> &mut Self {
        self.op_rr(0x85, a, b, w);
        self
    }

    /// Unary group on register (mul/div family uses rdx:rax implicitly).
    pub fn unary(&mut self, op: Unary, rm: Reg, w: bool) -> &mut Self {
        self.rex(w, false, false, rm.high());
        self.u8(0xF7);
        self.u8(0b11 << 6 | ((op as u8) << 3) | rm.low());
        self
    }

    /// 2-operand form `imul dst, src` (flags: CF/OF by overflow).
    pub fn imul2(&mut self, dst: Reg, src: Reg, w: bool) -> &mut Self {
        self.rex(w, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(0xAF);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// 3-operand form `imul dst, src, imm32`.
    pub fn imul3(&mut self, dst: Reg, src: Reg, imm: i32, w: bool) -> &mut Self {
        self.rex(w, dst.high(), false, src.high());
        if (-128..=127).contains(&imm) {
            self.u8(0x6B);
            self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
            self.u8(imm as i8 as u8);
        } else {
            self.u8(0x69);
            self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
            self.u32(imm as u32);
        }
        self
    }

    /// Shift by CL (`shl/shr/sar/rcl/rcr/rol/ror`).
    pub fn shift_cl(&mut self, op: Shift, dst: Reg, w: bool) -> &mut Self {
        self.rex(w, false, false, dst.high());
        self.u8(0xD3);
        self.u8(0b11 << 6 | ((op as u8) << 3) | dst.low());
        self
    }

    /// Shift by imm8.
    pub fn shift_ri(&mut self, op: Shift, dst: Reg, imm: u8, w: bool) -> &mut Self {
        self.rex(w, false, false, dst.high());
        if imm == 1 {
            self.u8(0xD1);
            self.u8(0b11 << 6 | ((op as u8) << 3) | dst.low());
        } else {
            self.u8(0xC1);
            self.u8(0b11 << 6 | ((op as u8) << 3) | dst.low());
            self.u8(imm);
        }
        self
    }

    /// `bt r, r` — bit test into CF.
    pub fn bt_rr(&mut self, base: Reg, bit: Reg, w: bool) -> &mut Self {
        self.rex(w, base.high(), false, bit.high());
        self.u8(0x0F);
        self.u8(0xA3);
        self.u8(0b11 << 6 | (base.low() << 3) | bit.low());
        self
    }

    /// `bt r, imm8`.
    pub fn bt_ri(&mut self, base: Reg, bit: u8, w: bool) -> &mut Self {
        self.rex(w, false, false, base.high());
        self.u8(0x0F);
        self.u8(0xBA);
        self.u8(0b11 << 6 | (4 << 3) | base.low());
        self.u8(bit);
        self
    }

    /// `setcc r8_low` into a register's low byte.
    pub fn setcc(&mut self, cc: Cc, dst: Reg) -> &mut Self {
        self.rex(false, false, false, dst.high());
        self.u8(0x0F);
        self.u8(0x90 + cc as u8);
        self.u8(0b11 << 6 | dst.low());
        self
    }

    /// `cmovcc dst, src`.
    pub fn cmov(&mut self, cc: Cc, dst: Reg, src: Reg, w: bool) -> &mut Self {
        self.rex(w, dst.high(), false, src.high());
        self.u8(0x0F);
        self.u8(0x40 + cc as u8);
        self.u8(0b11 << 6 | (dst.low() << 3) | src.low());
        self
    }

    /// `neg r` / `not r` via unary group (convenience wrappers).
    pub fn neg(&mut self, dst: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Neg, dst, w)
    }

    /// `not r`.
    pub fn not(&mut self, dst: Reg, w: bool) -> &mut Self {
        self.unary(Unary::Not, dst, w)
    }

    /// `cdq` (w=false) / `cqo` (w=true): sign-extend rax into rdx.
    pub fn cqo(&mut self, w: bool) -> &mut Self {
        self.rex(w, false, false, false);
        self.u8(0x99);
        self
    }

    /// `xchg r, r`.
    pub fn xchg(&mut self, a: Reg, b: Reg, w: bool) -> &mut Self {
        self.op_rr(0x87, a, b, w);
        self
    }

    /// `push r`.
    pub fn push(&mut self, r: Reg) -> &mut Self {
        if r.high() {
            self.u8(0x41);
        }
        self.u8(0x50 + r.low());
        self
    }

    /// `pop r`.
    pub fn pop(&mut self, r: Reg) -> &mut Self {
        if r.high() {
            self.u8(0x41);
        }
        self.u8(0x58 + r.low());
        self
    }

    // ---- control flow --------------------------------------------------------

    /// `call r` (indirect).
    pub fn call_r(&mut self, r: Reg) -> &mut Self {
        self.rex(false, false, false, r.high());
        self.u8(0xFF);
        self.u8(0b11 << 6 | (2 << 3) | r.low());
        self
    }

    /// `jmp r` (indirect).
    pub fn jmp_r(&mut self, r: Reg) -> &mut Self {
        self.rex(false, false, false, r.high());
        self.u8(0xFF);
        self.u8(0b11 << 6 | (4 << 3) | r.low());
        self
    }

    /// `ret`.
    pub fn ret(&mut self) -> &mut Self {
        self.u8(0xC3);
        self
    }

    /// `jmp rel32` to a label.
    pub fn jmp(&mut self, l: Label) -> &mut Self {
        self.u8(0xE9);
        self.patches.push((self.pos(), l));
        self.u32(0);
        self
    }

    /// `jcc rel32` to a label.
    pub fn jcc(&mut self, cc: Cc, l: Label) -> &mut Self {
        self.u8(0x0F);
        self.u8(0x80 + cc as u8);
        self.patches.push((self.pos(), l));
        self.u32(0);
        self
    }

    /// `nop`.
    pub fn nop(&mut self) -> &mut Self {
        self.u8(0x90);
        self
    }

    /// `int3`.
    pub fn int3(&mut self) -> &mut Self {
        self.u8(0xCC);
        self
    }

    /// Patch the last-emitted 4-byte field at `pos` with the displacement to
    /// the *current* position (for hand-rolled rel32 sites).
    pub fn patch_rel32(&mut self, pos: u32) {
        let rel = self.pos() as i64 - (pos as i64 + 4);
        self.buf[pos as usize..pos as usize + 4].copy_from_slice(&(rel as i32).to_le_bytes());
    }

    /// Encode `movabs`-style raw bytes of an exit slot header — used by the
    /// code cache to patch slot interiors; emits nothing itself, just a
    /// convenience for computing slot sizes.
    pub fn raw_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.raw(bytes);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(f: impl FnOnce(&mut Code)) -> Vec<u8> {
        let mut c = Code::new();
        f(&mut c);
        c.finish()
    }

    #[test]
    fn golden_encodings() {
        // mov rax, 0x1122334455667788
        assert_eq!(
            code(|c| { c.mov_ri(Reg::Rax, 0x1122_3344_5566_7788); }),
            [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        // mov rbx, rcx
        assert_eq!(code(|c| { c.mov_rr(Reg::Rbx, Reg::Rcx); }), [0x48, 0x89, 0xCB]);
        // mov r15, r14
        assert_eq!(code(|c| { c.mov_rr(Reg::R15, Reg::R14); }), [0x4D, 0x89, 0xF7]);
        // mov [rdi+0x10], rax
        assert_eq!(code(|c| { c.mov_mr(Mem::bd(Reg::Rdi, 0x10), Reg::Rax); }), [0x48, 0x89, 0x47, 0x10]);
        // mov rax, [r8+0x1000]
        assert_eq!(
            code(|c| { c.mov_rm(Reg::Rax, Mem::bd(Reg::R8, 0x1000)); }),
            [0x49, 0x8B, 0x80, 0x00, 0x10, 0x00, 0x00]
        );
        // mov [rsp+8], rax  (SIB required)
        assert_eq!(
            code(|c| { c.mov_mr(Mem::bd(Reg::Rsp, 8), Reg::Rax); }),
            [0x48, 0x89, 0x44, 0x24, 0x08]
        );
        // mov [rbp], rax (disp8 0 forced)
        assert_eq!(
            code(|c| { c.mov_mr(Mem::bd(Reg::Rbp, 0), Reg::Rax); }),
            [0x48, 0x89, 0x45, 0x00]
        );
        // mov [r12], rax (SIB)
        assert_eq!(
            code(|c| { c.mov_mr(Mem::bd(Reg::R12, 0), Reg::Rax); }),
            [0x49, 0x89, 0x04, 0x24]
        );
        // mov [r13], rax (disp8 forced)
        assert_eq!(
            code(|c| { c.mov_mr(Mem::bd(Reg::R13, 0), Reg::Rax); }),
            [0x49, 0x89, 0x45, 0x00]
        );
        // add rax, rcx
        assert_eq!(code(|c| { c.alu_rr(Alu::Add, Reg::Rax, Reg::Rcx, true); }), [0x48, 0x01, 0xC8]);
        // add rax, 5 (imm8)
        assert_eq!(code(|c| { c.alu_ri(Alu::Add, Reg::Rax, 5, true); }), [0x48, 0x83, 0xC0, 0x05]);
        // sub r15, 0x100 (imm32)
        assert_eq!(
            code(|c| { c.alu_ri(Alu::Sub, Reg::R15, 0x100, true); }),
            [0x49, 0x81, 0xEF, 0x00, 0x01, 0x00, 0x00]
        );
        // xor eax, eax (32-bit)
        assert_eq!(code(|c| { c.alu_rr(Alu::Xor, Reg::Rax, Reg::Rax, false); }), [0x31, 0xC0]);
        // cmp rcx, rax 32-bit
        assert_eq!(code(|c| { c.alu_rr(Alu::Cmp, Reg::Rcx, Reg::Rax, false); }), [0x39, 0xC1]);
        // shl rax, 3
        assert_eq!(code(|c| { c.shift_ri(Shift::Shl, Reg::Rax, 3, true); }), [0x48, 0xC1, 0xE0, 0x03]);
        // shr rdx, cl
        assert_eq!(code(|c| { c.shift_cl(Shift::Shr, Reg::Rdx, true); }), [0x48, 0xD3, 0xEA]);
        // cqo
        assert_eq!(code(|c| { c.cqo(true); }), [0x48, 0x99]);
        // idiv rcx
        assert_eq!(code(|c| { c.unary(Unary::Idiv, Reg::Rcx, true); }), [0x48, 0xF7, 0xF9]);
        // imul rax, rcx
        assert_eq!(
            code(|c| { c.imul2(Reg::Rax, Reg::Rcx, true); }),
            [0x48, 0x0F, 0xAF, 0xC1]
        );
        // setne al
        assert_eq!(code(|c| { c.setcc(Cc::Ne, Reg::Rax); }), [0x0F, 0x95, 0xC0]);
        // movzx rax, byte [rbx]
        assert_eq!(
            code(|c| { c.movzx_rm(Reg::Rax, Mem::bd(Reg::Rbx, 0), 1); }),
            [0x48, 0x0F, 0xB6, 0x03]
        );
        // movsxd rax, ecx
        assert_eq!(code(|c| { c.movsxd(Reg::Rax, Reg::Rcx); }), [0x48, 0x63, 0xC1]);
        // bt rax, 33 imm8?? bit index 33 needs 66 prefix trick — allowed as imm8 with w
        assert_eq!(
            code(|c| { c.bt_ri(Reg::Rax, 33, true); }),
            [0x48, 0x0F, 0xBA, 0xE0, 0x21]
        );
        // push r13 / pop r13
        assert_eq!(code(|c| { c.push(Reg::R13); c.pop(Reg::R13); }), [0x41, 0x55, 0x41, 0x5D]);
        // call r10
        assert_eq!(code(|c| { c.call_r(Reg::R10); }), [0x41, 0xFF, 0xD2]);
        // ret
        assert_eq!(code(|c| { c.ret(); }), [0xC3]);
        // labels: back + forward
        let b = code(|c| {
            let l = c.label();
            c.jcc(Cc::E, l);
            c.bind(l);
            c.nop();
            c.jmp(l);
        });
        assert_eq!(b[0], 0x0F);
        assert_eq!(b[1], 0x84);
        assert_eq!(&b[2..6], &0i32.to_le_bytes());
        assert_eq!(b[6], 0x90);
        assert_eq!(b[7], 0xE9);
        let rel = i32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        assert_eq!(rel, -6);
        // lea rax, [rip+0x100]
        assert_eq!(
            code(|c| { c.lea(Reg::Rax, Mem::rip(0x100)); }),
            [0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00]
        );
        // mov dword [rax], 0x11223344 (32-bit, no rex)
        assert_eq!(
            code(|c| { c.mov32_mi(Mem::bd(Reg::Rax, 0), 0x1122_3344); }),
            [0xC7, 0x00, 0x44, 0x33, 0x22, 0x11]
        );
        // movzx rax, r16 word reg form
        assert_eq!(
            code(|c| { c.movzx_rr(Reg::Rax, Reg::Rcx, 2); }),
            [0x48, 0x0F, 0xB7, 0xC1]
        );
    }
}
