//! # a64x-api — Win32 API translation (the second pillar)
//!
//! ARM64 Windows binaries do not get emulated DLLs. Every imported Win32
//! entry point is bound to a **gateway address**; when control flow
//! reaches it, the dispatcher calls the corresponding *native* adapter —
//! ordinary Rust code with direct access to the guest CpuState and
//! address space (Rosetta-2 / box64 style wrapping). The adapter reads
//! the arguments from the guest registers (Windows ARM64 ABI: x0..x7,
//! d0/d1 for floating point), performs the operation natively, and writes
//! the result into x0 (or v0).
//!
//! The process model behind the adapters lives in this crate:
//!
//! * a real heap allocator over guest memory ([`heap`]),
//! * a page-granular virtual memory map with reserve/commit/protect
//!   bookkeeping ([`vm`]),
//! * a handle table with typed kernel objects ([`handles`]),
//! * green threads with a scheduler, blocking waits and deadlock detection
//!   ([`sched`]),
//! * continuation frames so adapters can call back into guest code (CRT
//!   initializers, `atexit`, thread start routines, SEH filters) and finish
//!   their Windows call afterwards ([`cont`]),
//! * stdio streams with buffering and text-mode translation ([`stdio`]),
//! * printf/scanf engines with Windows (MSVC UCRT) semantics ([`format`],
//!   [`scan`]),
//! * ARM64 structured-exception unwinding over `.pdata`/`.xdata` ([`unwind`]).
//!
//! Adapters are host-portable Rust (std) and perform the Windows operation on
//! the host wherever the host offers it. Where a value cannot be derived
//! from the host (time zones, NUMA topology, page protection enforcement),
//! the adapter states its fixed answer; `docs/api-surface.md` lists each one.

#![warn(missing_docs)]

use a64x_core::state::CpuState;
use a64x_core::{Error, Memory, Result};

mod cont;
mod convert;
mod crt;
mod env;
mod format;
mod handles;
mod heap;
mod k32_file;
mod k32_info;
mod k32_mem;
mod k32_seh;
mod k32_sync;
mod kernel32;
mod locale;
mod mathfn;
mod proc;
mod scan;
mod sched;
mod shell32;
mod stdio;
mod strings;
mod timefmt;
mod unwind;
mod vm;

/// Gateway addressing: one 16-byte slot per imported API.
///
/// A guest PC in this range means "enter API number (pc - BASE)/16".
pub mod gateway {
    pub use a64x_core::memory::{GATEWAY_BASE as BASE, GATEWAY_STRIDE as STRIDE};

    /// Slot index for a gateway address, if the pc is in the gateway range.
    pub fn id_of(pc: u64) -> Option<u32> {
        if pc >= BASE && pc < BASE + (1 << 20) * STRIDE && (pc - BASE) % STRIDE == 0 {
            Some(((pc - BASE) / STRIDE) as u32)
        } else {
            None
        }
    }

    /// Gateway address for slot `id`.
    pub fn addr_of(id: u32) -> u64 {
        BASE + id as u64 * STRIDE
    }
}

/// Gateway slot of the internal continuation entry (`__continue`). Guest
/// code never imports it; the API layer uses it as the return address of
/// callbacks so that control comes back to an adapter when they return.
pub const CONTINUATION_ID: u32 = 0;

/// One section of a loaded module, as the API layer needs it.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name (`.text`, `.pdata`, ...).
    pub name: String,
    /// Guest virtual address.
    pub va: u64,
    /// Virtual size in bytes.
    pub size: u64,
    /// PE section characteristics (`IMAGE_SCN_*`).
    pub characteristics: u32,
}

/// A loaded image as the API layer sees it (for unwinding, VirtualQuery,
/// GetProcAddress on the image and GetModuleFileName).
#[derive(Debug, Clone, Default)]
pub struct ModuleInfo {
    /// Path (or bare name) of the image file.
    pub path: String,
    /// Load address.
    pub base: u64,
    /// SizeOfImage.
    pub size: u64,
    /// Section table.
    pub sections: Vec<SectionInfo>,
    /// Exception directory (`.pdata`): guest VA and byte size.
    pub pdata: Option<(u64, u32)>,
    /// Named exports: `(name, guest VA)`.
    pub exports: Vec<(String, u64)>,
}

/// Per-call mutable context handed to adapters.
pub struct ApiCtx<'a> {
    /// Guest CPU state of the *running* thread (registers are the ABI).
    pub state: &'a mut CpuState,
    /// Guest address space.
    pub mem: &'a mut Memory,
    /// Command line the guest sees (GetCommandLineA/W, `__p__acmdln`).
    pub cmd_line: Vec<u8>,
    /// Loaded image base (GetModuleHandle(NULL) returns this).
    pub image_base: u64,
    /// Back-reference for GetProcAddress resolution.
    pub api: Option<&'a ApiLayer>,
    /// Message to show when the process exits.
    pub exit_message: Option<String>,
    /// Images known to the runtime (the main executable).
    pub modules: Vec<ModuleInfo>,
    /// Process-level state (heaps, handles, threads, stdio, CRT state).
    pub(crate) p: proc::Process,
    /// Gateway address of the adapter currently running.
    pub(crate) gw: u64,
    /// Set by an adapter that already chose the next pc (redirect,
    /// retry, thread switch); the dispatcher then leaves pc alone.
    pub(crate) pc_set: bool,
    /// Set by an adapter that asked for the scheduler to run after it.
    pub(crate) resched: bool,
    /// The running call blocked and will be re-run: its results are
    /// discarded so the re-run sees the original arguments.
    pub(crate) blocked: bool,
}

impl<'a> ApiCtx<'a> {
    /// New context over guest state/memory.
    pub fn new(state: &'a mut CpuState, mem: &'a mut Memory) -> ApiCtx<'a> {
        let p = proc::Process::new(mem.size());
        ApiCtx {
            state,
            mem,
            cmd_line: b"guest.exe\0".to_vec(),
            image_base: a64x_core::memory::DEFAULT_IMAGE_BASE,
            api: None,
            exit_message: None,
            modules: Vec::new(),
            p,
            gw: 0,
            pc_set: false,
            resched: false,
            blocked: false,
        }
    }

    /// Called by the dispatcher just before an adapter runs.
    pub fn enter(&mut self, gateway_pc: u64) {
        self.gw = gateway_pc;
        self.pc_set = false;
        self.resched = false;
        self.blocked = false;
    }

    /// Called by the dispatcher after an adapter returned successfully:
    /// applies the return address and performs any requested thread switch.
    pub fn post_call(&mut self) {
        if !self.pc_set && self.state.running != 0 {
            self.state.pc = self.state.x[30];
        }
        if self.resched {
            sched::reschedule(self);
        }
        self.pc_set = false;
        self.resched = false;
        self.blocked = false;
    }

    /// Called by the dispatcher at a translator round boundary: gives
    /// other runnable threads their turn (preemptive round robin).
    pub fn preempt(&mut self) {
        sched::preempt(self);
    }

    /// Terminate the process with a diagnostic (used for guest errors the
    /// Windows process would also die from, and for unrecoverable states).
    pub(crate) fn fatal(&mut self, msg: String) {
        self.exit_message = Some(msg);
        self.state.exit_reason = a64x_core::ExitReason::Stopped as u8;
        self.state.running = 0;
    }

    /// Argument register `i` (x0..x7), full 64 bits.
    pub(crate) fn a(&self, i: usize) -> u64 {
        self.state.x[i]
    }

    /// Argument register `i` as a 32-bit signed int (`int`/`LONG`).
    pub(crate) fn ai(&self, i: usize) -> i32 {
        self.state.x[i] as u32 as i32
    }

    /// Argument register `i` as a 32-bit unsigned int (`DWORD`/`UINT`).
    pub(crate) fn au(&self, i: usize) -> u32 {
        self.state.x[i] as u32
    }

    /// Argument register `i` as a 64-bit signed int (`__int64`, `SSIZE_T`).
    pub(crate) fn ai64(&self, i: usize) -> i64 {
        self.state.x[i] as i64
    }

    /// Floating-point argument `i` (d-register, low 64 bits of v`i`).
    pub(crate) fn af(&self, i: usize) -> f64 {
        f64::from_bits(self.state.v[i][0])
    }

    /// Set the 64-bit return value (x0). Ignored once the call has blocked:
    /// the call re-runs with its original arguments.
    pub(crate) fn ret(&mut self, v: u64) {
        if !self.blocked {
            self.state.x[0] = v;
        }
    }

    /// Set a signed 32-bit return value (`int`), sign-extended into x0.
    pub(crate) fn ret_i32(&mut self, v: i32) {
        self.ret(v as i64 as u64);
    }

    /// Set a BOOL return value.
    pub(crate) fn ret_bool(&mut self, b: bool) {
        self.ret(b as u64);
    }

    /// Set a double return value (d0).
    pub(crate) fn ret_f64(&mut self, v: f64) {
        if !self.blocked {
            self.state.v[0] = [v.to_bits(), 0];
        }
    }

    /// Set a float return value (s0).
    pub(crate) fn ret_f32(&mut self, v: f32) {
        if !self.blocked {
            self.state.v[0] = [v.to_bits() as u64, 0];
        }
    }

    /// Read a little-endian scalar from guest memory (1, 2, 4 or 8 bytes).
    pub(crate) fn rd(&self, addr: u64, n: u8) -> Result<u64> {
        self.mem.read_int(addr, n)
    }

    /// Write a little-endian scalar to guest memory (1, 2, 4 or 8 bytes).
    pub(crate) fn wr(&mut self, addr: u64, n: u8, v: u64) -> Result<()> {
        self.mem.write_int(addr, n, v)
    }

    /// Read a 64-bit pointer from guest memory.
    pub(crate) fn rd_ptr(&self, addr: u64) -> Result<u64> {
        self.mem.read_int(addr, 8)
    }

    /// Copy `len` guest bytes out.
    pub(crate) fn bytes(&self, addr: u64, len: u64) -> Result<Vec<u8>> {
        Ok(self.mem.slice(addr, len)?.to_vec())
    }

    /// Copy host bytes into guest memory.
    pub(crate) fn put(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.mem.write(addr, data)
    }

    /// Zero `len` guest bytes.
    pub(crate) fn zero(&mut self, addr: u64, len: u64) -> Result<()> {
        self.mem.zero(addr, len)
    }

    /// Read a NUL-terminated byte string (without the NUL). `max` bounds the
    /// scan; a string longer than that is truncated, never UB.
    pub(crate) fn cstr_max(&self, addr: u64, max: usize) -> Result<Vec<u8>> {
        self.mem.read_cstr(addr, max)
    }

    /// Read a NUL-terminated byte string of practically unbounded length.
    pub(crate) fn cstr(&self, addr: u64) -> Result<Vec<u8>> {
        self.mem.read_cstr(addr, 1 << 24)
    }

    /// Read a NUL-terminated UTF-16 string as code units.
    pub(crate) fn wstr(&self, addr: u64) -> Result<Vec<u16>> {
        self.mem.read_wstr(addr, 1 << 23)
    }

    /// Read a NUL-terminated UTF-16 string as a Rust string (lossy).
    pub(crate) fn wstr_string(&self, addr: u64) -> Result<String> {
        Ok(String::from_utf16_lossy(&self.wstr(addr)?))
    }

    /// Read a NUL-terminated ANSI string as a Rust string (lossy).
    pub(crate) fn cstr_string(&self, addr: u64) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.cstr(addr)?).into_owned())
    }

    /// Write `units` as UTF-16LE (no terminator added).
    pub(crate) fn put_wide(&mut self, addr: u64, units: &[u16]) -> Result<()> {
        let mut bytes = Vec::with_capacity(units.len() * 2);
        for u in units {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        self.mem.write(addr, &bytes)
    }

    /// Read `n` UTF-16 code units starting at `addr` (no NUL scan).
    pub(crate) fn wide_units(&self, addr: u64, n: u64) -> Result<Vec<u16>> {
        let raw = self.mem.slice(addr, n * 2)?;
        Ok(raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect())
    }

    /// Current thread's `errno` value.
    pub(crate) fn errno(&self) -> i32 {
        let addr = self.p.sched.cur_errno_addr();
        self.mem
            .read_int(addr, 4)
            .map(|v| v as u32 as i32)
            .unwrap_or(0)
    }

    /// Set the current thread's `errno` (the value `_errno()` points at).
    pub(crate) fn set_errno(&mut self, e: i32) {
        let addr = self.p.sched.cur_errno_addr();
        let _ = self.mem.write_int(addr, 4, e as u32 as u64);
    }

    /// Set the Win32 last-error value of the current thread.
    pub(crate) fn set_last_error(&mut self, e: u32) {
        self.state.last_error = e as u64;
    }

    /// Win32 last-error value of the current thread.
    pub(crate) fn last_error(&self) -> u32 {
        self.state.last_error as u32
    }

    /// Ask the scheduler to pick the next runnable thread once this adapter
    /// returns (the current thread stays runnable).
    pub(crate) fn yield_now(&mut self) {
        self.resched = true;
    }

    /// Block the current thread: the same adapter is re-entered when the
    /// thread is scheduled again (pc stays on the gateway address). The
    /// adapter must not have changed any state before calling this.
    pub(crate) fn block_retry(&mut self, deadline: Option<Instant>) {
        sched::block_current(self, deadline);
        self.state.pc = self.gw;
        self.pc_set = true;
        self.resched = true;
        self.blocked = true;
    }

    /// Intern a NUL-terminated ANSI string in the static data area and
    /// return its guest address (stable for the whole process).
    pub(crate) fn intern_cstr(&mut self, s: &[u8]) -> Result<u64> {
        self.p.statics.intern(self.mem, 0, s)
    }

    /// Intern a NUL-terminated UTF-16 string in the static data area.
    pub(crate) fn intern_wstr(&mut self, s: &[u16]) -> Result<u64> {
        let mut bytes = Vec::with_capacity(s.len() * 2);
        for u in s {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        self.p.statics.intern(self.mem, 1, &bytes)
    }
}

/// `Instant` re-export for adapters that compute deadlines.
pub(crate) use std::time::Instant;

/// Handle-space layout and fixed addresses (Windows-flavoured).
pub mod win_shared {
    /// Start of the process heap arena in guest memory.
    pub const HEAP_BASE: u64 = 0x0100_0000;
    /// End (exclusive) of the process heap arena.
    pub const HEAP_END: u64 = 0x0800_0000;
    /// Start of the static data area (command line, argv, FILE objects,
    /// interned strings, CRT variables, per-thread errno slots).
    pub const STATIC_BASE: u64 = 0x0008_0000;
    /// End (exclusive) of the static data area.
    pub const STATIC_END: u64 = 0x000F_0000;
    /// Standard input handle value (GetStdHandle(STD_INPUT_HANDLE)).
    pub const H_STDIN: u64 = 0x3;
    /// Standard output handle value.
    pub const H_STDOUT: u64 = 0x7;
    /// Standard error handle value.
    pub const H_STDERR: u64 = 0xB;
}

/// Normalise a DLL name the way the Windows loader resolves API sets:
/// `api-ms-win-crt-*` and `msvcrt`/`ucrtbase` share the UCRT
/// implementation, `api-ms-win-crt-private-*` and `vcruntime140*` are
/// hosted by vcruntime140, `api-ms-win-*`/`kernelbase`/`ntdll` are hosted
/// by kernel32, and `api-ms-win-shell-*` by shell32.
pub fn canonical_dll(dll: &str) -> String {
    let mut s = dll.to_ascii_lowercase();
    if let Some(stripped) = s.strip_suffix(".dll") {
        s = stripped.to_string();
    }
    if s.starts_with("api-ms-win-crt-private") || s.starts_with("vcruntime140") {
        "vcruntime140".to_string()
    } else if s.starts_with("api-ms-win-crt-") || s == "ucrtbase" || s == "msvcrt" {
        "ucrtbase".to_string()
    } else if s.starts_with("api-ms-win-shell-") || s == "shell32" {
        "shell32".to_string()
    } else if s.starts_with("api-ms-win-")
        || s.starts_with("ext-ms-win-")
        || matches!(s.as_str(), "kernel32" | "kernelbase" | "ntdll")
    {
        "kernel32".to_string()
    } else {
        s
    }
}

/// An adapter function signature.
pub(crate) type Adapter = fn(&mut ApiCtx) -> Result<()>;

/// One exported API.
#[derive(Clone, Copy)]
pub(crate) struct ApiDef {
    pub(crate) dll: &'static str,
    pub(crate) name: &'static str,
    pub(crate) f: Adapter,
}

/// The API layer: resolves DLL imports to gateway ids and invokes the
/// native adapters.
pub struct ApiLayer {
    defs: Box<[ApiDef]>,
}

impl Default for ApiLayer {
    fn default() -> Self {
        ApiLayer::new()
    }
}

impl ApiLayer {
    /// Build the adapter table.
    pub fn new() -> ApiLayer {
        let mut v: Vec<ApiDef> = Vec::with_capacity(1024);
        // slot 0: the continuation entry (see CONTINUATION_ID)
        v.push(ApiDef {
            dll: "a64x-internal",
            name: "__continue",
            f: cont::resume_adapter,
        });
        kernel32::register(&mut v);
        k32_file::register(&mut v);
        k32_info::register(&mut v);
        k32_mem::register(&mut v);
        k32_sync::register(&mut v);
        k32_seh::register(&mut v);
        shell32::register(&mut v);
        crt::register(&mut v);
        stdio::register(&mut v);
        strings::register(&mut v);
        convert::register(&mut v);
        locale::register(&mut v);
        mathfn::register(&mut v);
        timefmt::register(&mut v);
        ApiLayer {
            defs: v.into_boxed_slice(),
        }
    }

    /// Resolve an imported function by DLL/name; returns its gateway id
    /// (stable for the lifetime of this layer). API-set names are mapped to
    /// their host with [`canonical_dll`].
    pub fn resolve(&self, dll: &str, name: &str) -> Option<u32> {
        let want = canonical_dll(dll);
        self.defs
            .iter()
            .position(|d| d.dll == want && name.eq_ignore_ascii_case(d.name))
            .map(|i| i as u32)
    }

    /// (dll, name) for a gateway id — diagnostics.
    pub fn describe(&self, id: u32) -> String {
        match self.defs.get(id as usize) {
            Some(d) => format!("{}!{}", d.dll, d.name),
            None => format!("<gateway #{id}>"),
        }
    }

    /// Number of adapters.
    pub fn len(&self) -> usize {
        self.defs.len()
    }

    /// True if no adapters are registered (never the case in practice).
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// Every `(dll, name)` pair this layer implements (for manifests).
    pub fn exports(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.defs.iter().skip(1).map(|d| (d.dll, d.name))
    }

    /// Invoke the adapter for gateway `id` with the current guest state.
    pub fn invoke(&self, id: u32, ctx: &mut ApiCtx) -> Result<()> {
        match self.defs.get(id as usize) {
            Some(d) => (d.f)(ctx),
            None => Err(Error::Host(format!("unknown API gateway id {id}"))),
        }
    }
}

/// Helper used by adapter tables.
pub(crate) fn push(v: &mut Vec<ApiDef>, dll: &'static str, name: &'static str, f: Adapter) {
    v.push(ApiDef { dll, name, f });
}

/// Table-registration macro: `reg!(v, "dll", "Name" => func, ...)`.
macro_rules! reg {
    ($v:ident, $dll:literal, $($name:literal => $f:path),* $(,)?) => {
        $( $crate::push($v, $dll, $name, $f); )*
    };
}
pub(crate) use reg;

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Run `f` with a fresh guest (256 MiB flat memory) and a fresh context.
    pub(crate) fn with_ctx<R>(f: impl FnOnce(&mut ApiCtx) -> R) -> R {
        let mut mem = Memory::new(a64x_core::GUEST_DEFAULT_SIZE).expect("guest memory");
        let mut st = CpuState::default();
        st.mem_base = mem.base() as u64;
        st.mem_size = mem.size();
        st.running = 1;
        let mut ctx = ApiCtx::new(&mut st, &mut mem);
        f(&mut ctx)
    }

    /// Call adapter `name` of `dll` with the given integer arguments and
    /// return x0 (test helper for the manifest and unit tests).
    pub(crate) fn call(ctx: &mut ApiCtx, dll: &str, name: &str, args: &[u64]) -> u64 {
        let api = ApiLayer::new();
        let id = api
            .resolve(dll, name)
            .unwrap_or_else(|| panic!("{dll}!{name} not registered"));
        for (i, a) in args.iter().enumerate() {
            ctx.state.x[i] = *a;
        }
        ctx.state.x[30] = 0x1234_5678;
        ctx.enter(gateway::addr_of(id));
        api.invoke(id, ctx).expect("adapter");
        ctx.state.x[0]
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::testutil::{call, with_ctx};
    use super::*;

    fn put_str(ctx: &mut ApiCtx, addr: u64, s: &str) {
        ctx.put(addr, s.as_bytes()).unwrap();
        ctx.mem.write(addr + s.len() as u64, &[0]).unwrap();
    }

    #[test]
    fn strtol_clamps_to_long_and_reports_erange() {
        with_ctx(|ctx| {
            let s = 0x20_0000;
            put_str(ctx, s, "  -2147483649x");
            let endp = 0x20_1000;
            let r = call(ctx, "ucrtbase", "strtol", &[s, endp, 10]);
            assert_eq!(r as u32 as i32, i32::MIN);
            assert_eq!(ctx.errno(), 34);
            assert_eq!(ctx.rd(endp, 8).unwrap(), s + 13);
        });
    }

    #[test]
    fn strtoul_negates_modulo_width() {
        with_ctx(|ctx| {
            let s = 0x20_0000;
            put_str(ctx, s, "-1");
            let r = call(ctx, "ucrtbase", "strtoul", &[s, 0, 10]);
            assert_eq!(r, 0xFFFF_FFFF);
            assert_eq!(ctx.errno(), 0);
        });
    }

    #[test]
    fn sprintf_formats_sizes_and_floats() {
        with_ctx(|ctx| {
            let buf = 0x20_0000;
            let fmt = 0x20_1000;
            let word = 0x20_2000;
            put_str(ctx, fmt, "%d %s %.3f %x %ld");
            put_str(ctx, word, "ok");
            let args = [
                buf,
                fmt,
                (-42i64) as u64,
                word,
                2.5f64.to_bits(),
                255,
                0x1_0000_0002,
            ];
            let n = call(ctx, "ucrtbase", "sprintf", &args);
            assert_eq!(n, "-42 ok 2.500 ff 2".len() as u64);
            let out = ctx.cstr(buf).unwrap();
            assert_eq!(out, b"-42 ok 2.500 ff 2");
        });
    }

    #[test]
    fn snprintf_standard_return_is_the_would_be_length() {
        with_ctx(|ctx| {
            let buf = 0x20_0000;
            let fmt = 0x20_1000;
            put_str(ctx, fmt, "abcdef");
            let n = call(ctx, "ucrtbase", "snprintf", &[buf, 4, fmt]);
            assert_eq!(n, 6);
            assert_eq!(ctx.cstr(buf).unwrap(), b"abc");
        });
    }

    #[test]
    fn printf_percent_n_is_rejected() {
        with_ctx(|ctx| {
            let buf = 0x20_0000;
            let fmt = 0x20_1000;
            put_str(ctx, fmt, "x%n");
            let n = call(ctx, "ucrtbase", "sprintf", &[buf, fmt, 0x20_3000]);
            assert_eq!(n as i64, -1);
            assert_eq!(ctx.errno(), 22);
        });
    }

    #[test]
    fn memmove_handles_overlap() {
        with_ctx(|ctx| {
            let a = 0x20_0000;
            ctx.put(a, b"abcd\0").unwrap();
            call(ctx, "vcruntime140", "memmove", &[a + 1, a, 4]);
            assert_eq!(ctx.bytes(a, 5).unwrap(), b"aabcd");
        });
    }

    #[test]
    fn malloc_realloc_keep_contents() {
        with_ctx(|ctx| {
            let p = call(ctx, "ucrtbase", "malloc", &[10]);
            assert_ne!(p, 0);
            ctx.put(p, b"0123456789").unwrap();
            let q = call(ctx, "ucrtbase", "realloc", &[p, 4000]);
            assert_ne!(q, 0);
            assert_eq!(ctx.bytes(q, 10).unwrap(), b"0123456789");
            call(ctx, "ucrtbase", "free", &[q]);
        });
    }

    #[test]
    fn virtual_alloc_reserve_then_commit_zeroes_pages() {
        with_ctx(|ctx| {
            let base = call(ctx, "kernel32", "VirtualAlloc", &[0, 0x10000, 0x2000, 0x04]);
            assert_ne!(base, 0);
            let mbi = 0x20_0000;
            call(ctx, "kernel32", "VirtualQuery", &[base, mbi, 48]);
            assert_eq!(ctx.rd(mbi + 32, 4).unwrap(), 0x2000, "reserved");
            let c = call(
                ctx,
                "kernel32",
                "VirtualAlloc",
                &[base, 0x1000, 0x1000, 0x04],
            );
            assert_eq!(c, base);
            call(ctx, "kernel32", "VirtualQuery", &[base, mbi, 48]);
            assert_eq!(ctx.rd(mbi + 32, 4).unwrap(), 0x1000, "committed");
            assert_eq!(ctx.rd(base, 8).unwrap(), 0);
        });
    }

    #[test]
    fn blocked_call_keeps_its_arguments_for_the_retry() {
        with_ctx(|ctx| {
            let api = ApiLayer::new();
            let h = call(ctx, "kernel32", "CreateEventW", &[0, 1, 0, 0]);
            // an unsignaled auto-reset event with an infinite wait: the call parks
            let event = call(ctx, "kernel32", "CreateEventW", &[0, 0, 0, 0]);
            let id = api.resolve("kernel32", "WaitForSingleObject").unwrap();
            ctx.state.x[0] = event;
            ctx.state.x[1] = 0xFFFF_FFFF;
            ctx.state.x[30] = 0x1234;
            ctx.enter(gateway::addr_of(id));
            api.invoke(id, ctx).unwrap();
            assert!(ctx.blocked, "the wait parks the call");
            assert_eq!(ctx.state.x[0], event, "the handle argument survives the block");
            assert_eq!(ctx.state.pc, gateway::addr_of(id), "the call re-runs at its gateway");
            let _ = h;
        });
    }

    #[test]
    fn critical_section_is_recursive_for_its_owner() {
        with_ctx(|ctx| {
            let cs = 0x20_0000;
            call(ctx, "kernel32", "InitializeCriticalSection", &[cs]);
            call(ctx, "kernel32", "EnterCriticalSection", &[cs]);
            call(ctx, "kernel32", "EnterCriticalSection", &[cs]);
            assert_eq!(ctx.rd(cs + 12, 4).unwrap(), 2);
            assert_eq!(call(ctx, "kernel32", "TryEnterCriticalSection", &[cs]), 1);
            call(ctx, "kernel32", "LeaveCriticalSection", &[cs]);
            call(ctx, "kernel32", "LeaveCriticalSection", &[cs]);
            call(ctx, "kernel32", "LeaveCriticalSection", &[cs]);
            assert_eq!(ctx.rd(cs + 16, 8).unwrap(), 0, "released");
        });
    }

    #[test]
    fn events_and_waits_report_win32_codes() {
        with_ctx(|ctx| {
            let h = call(ctx, "kernel32", "CreateEventW", &[0, 1, 0, 0]);
            assert_eq!(
                call(ctx, "kernel32", "WaitForSingleObject", &[h, 0]),
                258,
                "timeout"
            );
            call(ctx, "kernel32", "SetEvent", &[h]);
            assert_eq!(
                call(ctx, "kernel32", "WaitForSingleObject", &[h, 0]),
                0,
                "signaled"
            );
            assert_eq!(
                call(ctx, "kernel32", "WaitForSingleObject", &[h, 0]),
                0,
                "manual reset stays signaled"
            );
        });
    }

    #[test]
    fn mutex_release_by_non_owner_fails() {
        with_ctx(|ctx| {
            let m = call(ctx, "kernel32", "CreateMutexW", &[0, 1, 0]);
            assert_eq!(call(ctx, "kernel32", "ReleaseMutex", &[m]), 1);
            assert_eq!(call(ctx, "kernel32", "ReleaseMutex", &[m]), 0);
            assert_eq!(ctx.last_error(), 288);
        });
    }

    #[test]
    fn format_message_system_text_has_crlf() {
        with_ctx(|ctx| {
            let buf = 0x20_0000;
            let n = call(
                ctx,
                "kernel32",
                "FormatMessageA",
                &[0x1000, 0, 2, 0, buf, 200, 0],
            );
            let text = ctx.cstr(buf).unwrap();
            assert_eq!(text, b"The system cannot find the file specified.\r\n");
            assert_eq!(n as usize, text.len());
            let miss = call(
                ctx,
                "kernel32",
                "FormatMessageA",
                &[0x1000, 0, 123456, 0, buf, 200, 0],
            );
            assert_eq!(miss, 0);
            assert_eq!(ctx.last_error(), 317);
        });
    }

    #[test]
    fn environment_variables_are_case_insensitive() {
        with_ctx(|ctx| {
            ctx.p.env.set("A64X_Case", Some("v"));
            let name = 0x20_0000;
            let buf = 0x20_1000;
            put_str(ctx, name, "a64x_case");
            let n = call(ctx, "kernel32", "GetEnvironmentVariableA", &[name, buf, 16]);
            assert_eq!(n, 1);
            assert_eq!(ctx.cstr(buf).unwrap(), b"v");
        });
    }

    #[test]
    fn command_line_argv_follows_msvc_rules() {
        let args = shell32::parse_command_line(b"p \"a b\" c\\\"d");
        assert_eq!(args.len(), 3);
        assert_eq!(args[1], b"a b");
        assert_eq!(args[2], b"c\"d");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_set_names_map_to_their_hosts() {
        assert_eq!(
            canonical_dll("api-ms-win-crt-private-l1-1-0.dll"),
            "vcruntime140"
        );
        assert_eq!(canonical_dll("api-ms-win-crt-stdio-l1-1-0.dll"), "ucrtbase");
        assert_eq!(canonical_dll("msvcrt.dll"), "ucrtbase");
        assert_eq!(canonical_dll("KERNEL32.dll"), "kernel32");
        assert_eq!(
            canonical_dll("api-ms-win-core-synch-l1-2-0.dll"),
            "kernel32"
        );
        assert_eq!(canonical_dll("SHELL32.dll"), "shell32");
    }

    #[test]
    fn gateway_round_trip() {
        for id in [0u32, 1, 777] {
            assert_eq!(gateway::id_of(gateway::addr_of(id)), Some(id));
        }
        assert_eq!(gateway::id_of(gateway::addr_of(3) + 4), None);
    }

    #[test]
    fn registry_has_no_duplicate_entries() {
        let api = ApiLayer::new();
        let mut seen = std::collections::BTreeSet::new();
        for (dll, name) in api.exports() {
            let key = (dll, name.to_ascii_lowercase());
            assert!(seen.insert(key), "duplicate registration {dll}!{name}");
        }
    }
}
