//! Dependency-free host page allocation.
//!
//! POSIX hosts use raw `mmap`/`mprotect`/`munmap` syscalls via `asm!`
//! (works on both glibc and musl, no `libc` crate needed).
//! Windows uses `VirtualAlloc`/`VirtualFree`/`VirtualProtect` from kernel32.

use crate::error::{Error, Result};
use core::ffi::c_void;

/// Page access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub exec: bool,
}

impl Prot {
    /// Read+write data pages.
    pub const RW: Prot = Prot { read: true, write: true, exec: false };
    /// Read+write+execute pages for freshly translated code.
    pub const RWX: Prot = Prot { read: true, write: true, exec: true };
    /// Read+execute.
    pub const RX: Prot = Prot { read: true, write: false, exec: true };
}

/// A mapped region of page-aligned memory.
pub struct Mapping {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: the mapping is exclusively owned; pointers handed out are derived
// from the base address and never outlive the Mapping.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Map `len` bytes of anonymous memory (page aligned, zero filled).
    pub fn anon(len: usize, prot: Prot) -> Result<Mapping> {
        let len = align_up(len, page_size());
        let ptr = unsafe { map_anon(len, prot)? };
        Ok(Mapping { ptr, len })
    }

    /// Base pointer.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Change protection of the whole region.
    pub fn protect(&self, prot: Prot) -> Result<()> {
        unsafe { protect(self.ptr, self.len, prot) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { unmap(self.ptr, self.len) }
    }
}

/// Host page size (cached).
pub fn page_size() -> usize {
    4096
}

pub(crate) fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

// --------------------------------------------------------------------------
// POSIX implementation (Linux & macOS on x86-64), direct syscalls.
// --------------------------------------------------------------------------
#[cfg(all(unix, target_arch = "x86_64"))]
mod os {
    use super::*;

    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    const MAP_PRIVATE: i32 = 0x02;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;

    #[cfg(target_os = "linux")]
    const SYS_MMAP: i64 = 9;
    #[cfg(target_os = "linux")]
    const SYS_MPROTECT: i64 = 10;
    #[cfg(target_os = "linux")]
    const SYS_MUNMAP: i64 = 11;
    #[cfg(target_os = "macos")]
    const SYS_MMAP: i64 = 0x2000_00C5;
    #[cfg(target_os = "macos")]
    const SYS_MPROTECT: i64 = 0x2000_004A;
    #[cfg(target_os = "macos")]
    const SYS_MUNMAP: i64 = 0x2000_0049;

    fn prot_bits(p: Prot) -> i32 {
        (if p.read { PROT_READ } else { 0 })
            | if p.write { PROT_WRITE } else { 0 }
            | if p.exec { PROT_EXEC } else { 0 }
    }

    unsafe fn syscall6(n: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
        let ret: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                in("r8") a5,
                in("r9") a6,
                out("rcx") _,
                out("r11") _,
                options(nostack)
            );
        }
        ret
    }

    pub unsafe fn map_anon(len: usize, prot: Prot) -> Result<*mut u8> {
        let p = unsafe {
            syscall6(
                SYS_MMAP,
                0,
                len as i64,
                prot_bits(prot) as i64,
                (MAP_PRIVATE | MAP_ANONYMOUS) as i64,
                -1,
                0,
            )
        };
        if p < 0 && p >= -4095 {
            return Err(Error::Host(format!("mmap failed: errno {}", -p)));
        }
        Ok(p as *mut u8)
    }

    pub unsafe fn protect(ptr: *mut u8, len: usize, prot: Prot) -> Result<()> {
        let r = unsafe { syscall6(SYS_MPROTECT, ptr as i64, len as i64, prot_bits(prot) as i64, 0, 0, 0) };
        if r != 0 {
            return Err(Error::Host(format!("mprotect failed: errno {}", -r)));
        }
        Ok(())
    }

    pub unsafe fn unmap(ptr: *mut u8, len: usize) {
        unsafe { syscall6(SYS_MUNMAP, ptr as i64, len as i64, 0, 0, 0, 0) };
    }
}

// --------------------------------------------------------------------------
// Windows implementation: VirtualAlloc & friends from kernel32.
// --------------------------------------------------------------------------
#[cfg(windows)]
mod os {
    use super::*;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
        fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    }

    fn prot_bits(p: Prot) -> u32 {
        match (p.read, p.write, p.exec) {
            (true, false, false) => PAGE_READONLY,
            (true, true, false) => PAGE_READWRITE,
            (true, false, true) => PAGE_EXECUTE_READ,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (false, false, true) => PAGE_EXECUTE,
            _ => PAGE_READWRITE,
        }
    }

    pub unsafe fn map_anon(len: usize, prot: Prot) -> Result<*mut u8> {
        let p = unsafe { VirtualAlloc(core::ptr::null_mut(), len, MEM_COMMIT | MEM_RESERVE, prot_bits(prot)) };
        if p.is_null() {
            return Err(Error::Host("VirtualAlloc failed".into()));
        }
        Ok(p as *mut u8)
    }

    pub unsafe fn protect(ptr: *mut u8, len: usize, prot: Prot) -> Result<()> {
        let mut old = 0u32;
        let ok = unsafe { VirtualProtect(ptr as *mut c_void, len, prot_bits(prot), &mut old) };
        if ok == 0 {
            return Err(Error::Host("VirtualProtect failed".into()));
        }
        Ok(())
    }

    pub unsafe fn unmap(ptr: *mut u8, _len: usize) {
        unsafe { VirtualFree(ptr as *mut c_void, 0, MEM_RELEASE) };
    }
}

pub(crate) use os::{map_anon, protect, unmap};

/// Silence unused warning for c_void on unix builds.
#[cfg(unix)]
type _UnusedVoid = c_void;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_write_read() {
        let m = Mapping::anon(8192, Prot::RW).unwrap();
        assert_eq!(m.len(), 8192);
        unsafe {
            for i in 0..4096 {
                m.as_ptr().add(i).write((i & 0xFF) as u8);
            }
            assert_eq!(m.as_ptr().add(123).read(), 123);
        }
    }
}
