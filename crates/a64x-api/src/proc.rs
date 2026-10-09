//! Process-level state shared by all adapters.

use crate::win_shared::{HEAP_BASE, HEAP_END, STATIC_BASE, STATIC_END};
use crate::{crt, env, handles, heap, kernel32, locale, sched, stdio, vm};
use a64x_core::{Error, Memory, Result};
use std::collections::BTreeMap;

/// Start of the virtual-memory arena (VirtualAlloc, file views, thread
/// stacks). The process heap sits below it.
pub(crate) const VM_BASE: u64 = HEAP_END;

/// Bytes at the top of guest memory kept for the initial thread stack.
pub(crate) const TOP_RESERVE: u64 = 0x0020_0000;

/// The process: everything that outlives a single API call.
pub(crate) struct Process {
    /// Heaps: index 0 is the process heap; HeapCreate appends.
    pub heaps: Vec<Option<heap::Heap>>,
    /// Virtual memory map over the arena.
    pub vm: vm::VmMap,
    /// Handle table.
    pub handles: handles::Handles,
    /// Threads and the scheduler.
    pub sched: sched::Sched,
    /// C stdio streams and file descriptors.
    pub stdio: stdio::Stdio,
    /// Static data area (interned strings and CRT variables).
    pub statics: Statics,
    /// Environment variables.
    pub env: env::Env,
    /// CRT state (atexit, signal and invalid-parameter handlers, ...).
    pub crt: crt::CrtState,
    /// Kernel32 state (code pages, FLS, unhandled exception filter, ...).
    pub k32: kernel32::K32State,
    /// Locale state.
    pub locale: locale::LocaleState,
    /// Process id reported by GetCurrentProcessId.
    pub pid: u32,
}

impl Process {
    /// Create the process for a guest of `mem_size` bytes. The main thread's
    /// CPU state stays in the machine; the scheduler only tracks it.
    pub(crate) fn new(mem_size: u64) -> Process {
        let mut statics = Statics::new(STATIC_BASE, STATIC_END);
        let mut handles = handles::Handles::new();
        let errno = statics.alloc(16, 16).unwrap_or(STATIC_BASE);
        let sched = sched::Sched::new(errno, &mut handles);
        let mut std_files = [0u64; 3];
        for f in std_files.iter_mut() {
            *f = statics.alloc(stdio::FILE_SIZE, 16).unwrap_or(STATIC_BASE);
        }
        Process {
            heaps: vec![Some(heap::Heap::new(HEAP_BASE, HEAP_END))],
            vm: vm::VmMap::new(VM_BASE, mem_size - TOP_RESERVE),
            handles,
            sched,
            stdio: stdio::Stdio::new(std_files),
            statics,
            env: env::Env::from_host(),
            crt: crt::CrtState::default(),
            k32: kernel32::K32State::default(),
            locale: locale::LocaleState::default(),
            pid: 4242,
        }
    }
}

/// Bump allocator over the static data area, plus interned strings and
/// named CRT variables (which must keep their guest address forever).
pub(crate) struct Statics {
    next: u64,
    end: u64,
    interned: BTreeMap<(u8, Vec<u8>), u64>,
    vars: BTreeMap<&'static str, u64>,
}

impl Statics {
    fn new(base: u64, end: u64) -> Statics {
        Statics {
            next: base,
            end,
            interned: BTreeMap::new(),
            vars: BTreeMap::new(),
        }
    }

    /// Allocate `size` zeroed bytes with `align` alignment.
    pub(crate) fn alloc(&mut self, size: u64, align: u64) -> Result<u64> {
        let a = (self.next + align - 1) & !(align - 1);
        let end = a
            .checked_add(size.max(1))
            .ok_or_else(|| Error::Host("static area overflow".into()))?;
        if end > self.end {
            return Err(Error::Host("static data area exhausted".into()));
        }
        self.next = end;
        Ok(a)
    }

    /// Intern `bytes` (plus a NUL of the right width) and return its address.
    /// `kind` 0 = narrow string, 1 = wide string (bytes are UTF-16LE units).
    pub(crate) fn intern(&mut self, mem: &mut Memory, kind: u8, bytes: &[u8]) -> Result<u64> {
        let key = (kind, bytes.to_vec());
        if let Some(a) = self.interned.get(&key) {
            return Ok(*a);
        }
        let term = if kind == 1 { 2 } else { 1 };
        let addr = self.alloc((bytes.len() + term) as u64, 8)?;
        mem.write(addr, bytes)?;
        mem.zero(addr + bytes.len() as u64, term as u64)?;
        self.interned.insert(key, addr);
        Ok(addr)
    }

    /// Address of the named variable `key`, allocating `size` zeroed bytes
    /// on first use. Returns `(address, first_use)`.
    pub(crate) fn var(&mut self, key: &'static str, size: u64) -> Result<(u64, bool)> {
        if let Some(a) = self.vars.get(key) {
            return Ok((*a, false));
        }
        let a = self.alloc(size, 16)?;
        self.vars.insert(key, a);
        Ok((a, true))
    }
}
