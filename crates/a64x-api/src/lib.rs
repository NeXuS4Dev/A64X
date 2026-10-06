//! # a64x-api — Win32 API translation (the second pillar)
//!
//! ARM64 Windows binaries do not get emulated DLLs. Every imported Win32
//! entry point is bound to a **gateway address**; when control flow
//! reaches it, the dispatcher calls the corresponding *native* adapter —
//! ordinary Rust code with direct access to the guest CpuState and
//! address space (Rosetta-2 / box64 style wrapping). The adapter reads
//! the arguments from the guest registers (Windows ARM64 ABI: x0..x7),
//! performs the operation natively, and writes the result into x0.
//!
//! All adapters here are host-portable Rust (std). On real Windows the
//! same table can additionally forward to the true system DLLs, but the
//! portable implementations are the default — they are real code, not
//! stubs (files are actually read/written via `std::fs`, `Sleep` really
//! sleeps, the heap really allocates from guest memory).

#![warn(missing_docs)]

use a64x_core::state::CpuState;
use a64x_core::{Memory, Result};

mod crt;
mod kernel32;

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

/// Per-API mutable context handed to adapters.
pub struct ApiCtx<'a> {
    /// Guest CPU state (registers are the ABI).
    pub state: &'a mut CpuState,
    /// Guest address space.
    pub mem: &'a mut Memory,
    pub(crate) handles: Vec<(u64, Handle)>,
    /// Next free fresh-handle value.
    pub(crate) next_file_handle: u64,
    pub(crate) heap_next: u64,
    /// TLS slots (small fixed table is plenty).
    pub(crate) tls: [u64; 64],
    pub(crate) tls_used: u32,
    /// Command line the guest sees (GetCommandLineA/W).
    pub cmd_line: Vec<u8>,
    /// Loaded image base (GetModuleHandle* returns this).
    pub image_base: u64,
    /// Back-reference for GetProcAddress resolution.
    pub api: Option<&'a ApiLayer>,
    /// Message to show when the process exits.
    pub exit_message: Option<String>,
}

impl<'a> ApiCtx<'a> {
    /// New context over guest state/memory.
    pub fn new(state: &'a mut CpuState, mem: &'a mut Memory) -> ApiCtx<'a> {
        ApiCtx {
            state,
            mem,
            handles: Vec::new(),
            next_file_handle: 0x30,
            heap_next: crate::win_shared::HEAP_BASE,
            tls: [0; 64],
            tls_used: 0,
            cmd_line: b"guest.exe\0".to_vec(),
            image_base: a64x_core::memory::DEFAULT_IMAGE_BASE,
            api: None,
            exit_message: None,
        }
    }

    /// Bump-allocate from the guest heap arena.
    pub(crate) fn alloc_heap(&mut self, size: u64, align: u64) -> u64 {
        let a = (self.heap_next + align - 1) & !(align - 1);
        self.heap_next = a + size.max(1);
        a
    }
}

pub(crate) enum Handle {
    File(std::fs::File),
}

/// Handle-space layout (Windows): pseudo-handles for the console streams,
/// real values for files opened via CreateFileA/W.
pub mod win_shared {
    /// Guest address where the bump heap arena starts.
    pub const HEAP_BASE: u64 = 0x0100_0000;
    /// Guest address where scratch strings (command line etc.) go.
    pub const STRINGS_BASE: u64 = 0x000F_0000;
    /// stdin handle value.
    pub const H_STDIN: u64 = 1;
    /// stdout handle value.
    pub const H_STDOUT: u64 = 2;
    /// stderr handle value.
    pub const H_STDERR: u64 = 3;
}

/// An adapter function signature.
type Adapter = fn(&mut ApiCtx) -> Result<()>;

/// One exported API.
#[derive(Clone, Copy)]
struct ApiDef {
    dll: &'static str,
    name: &'static str,
    f: Adapter,
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
    /// Build the adapter table (kernel32 + CRT subset).
    pub fn new() -> ApiLayer {
        let mut v: Vec<ApiDef> = Vec::new();
        v.extend(kernel32::TABLE.iter().copied());
        v.extend(crt::TABLE.iter().copied());
        ApiLayer { defs: v.into_boxed_slice() }
    }

    /// Resolve an imported function by DLL/name; returns its gateway id
    /// (stable for the lifetime of this layer).
    pub fn resolve(&self, dll: &str, name: &str) -> Option<u32> {
        let dll_l = dll.to_ascii_lowercase();
        let base = dll_l.strip_suffix(".dll").unwrap_or(&dll_l);
        self.defs
            .iter()
            .position(|d| d.dll == base && name.eq_ignore_ascii_case(d.name))
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

    /// Invoke the adapter for gateway `id` with the current guest state.
    pub fn invoke(&self, id: u32, ctx: &mut ApiCtx) -> Result<()> {
        match self.defs.get(id as usize) {
            Some(d) => (d.f)(ctx),
            None => Err(a64x_core::Error::Host(format!("unknown API gateway id {id}"))),
        }
    }
}

// -----------------------------------------------------------------------
// adapter helpers
// -----------------------------------------------------------------------

/// Argument register (Windows ARM64 ABI): x0..x7.
pub(crate) fn arg(state: &CpuState, i: usize) -> u64 {
    state.x[i]
}

/// Set the return value register.
pub(crate) fn ret(state: &mut CpuState, v: u64) {
    state.x[0] = v;
}

/// Read a NUL-terminated ANSI string from guest memory.
pub(crate) fn read_cstr(ctx: &ApiCtx, addr: u64, max: usize) -> Vec<u8> {
    ctx.mem.read_cstr(addr, max).unwrap_or_default()
}

/// Read a NUL-terminated UTF-16 string and lossy-convert to String.
pub(crate) fn read_wstr(ctx: &ApiCtx, addr: u64, max: usize) -> String {
    let units = ctx.mem.read_wstr(addr, max).unwrap_or_default();
    String::from_utf16_lossy(&units)
}

/// Write raw bytes to the guest console (stdout).
pub(crate) fn write_stdout(bytes: &[u8]) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

/// Write raw bytes to stderr.
pub(crate) fn write_stderr(bytes: &[u8]) {
    use std::io::Write;
    let mut out = std::io::stderr().lock();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}
