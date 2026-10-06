//! Guest address space.
//!
//! The whole guest address space is a single flat host allocation:
//! guest address `a` is host address `mem_base + a`. Translated code keeps
//! `mem_base` in `r14`, so a guest load/store costs one `lea` + one
//! `mov` — no software TLB walk on the hot path.

use crate::error::{Error, Result};
use crate::platform::{Mapping, Prot};

/// Default guest address space size (256 MiB — plenty for user apps,
/// committed lazily by the OS since the pages start zeroed).
pub const GUEST_DEFAULT_SIZE: u64 = 0x1000_0000;

/// Where executables are loaded when their preferred base must be changed.
pub const DEFAULT_IMAGE_BASE: u64 = 0x0040_0000;

/// Size of the default guest stack (1 MiB, placed at the top of memory).
pub const STACK_SIZE: u64 = 0x10_0000;

/// Base of the API-gateway address range.
///
/// Gateway addresses are not real memory; they are sentinel PCs intercepted
/// by the dispatcher. When translated code sets `pc` into this range (by
/// calling through an import thunk), the dispatcher invokes the matching
/// host-side Win32 API adapter instead of translating.
pub const GATEWAY_BASE: u64 = 0x6A64_0000_0000;

/// Stride between gateway slots.
pub const GATEWAY_STRIDE: u64 = 16;

/// The guest address space: a flat, zero-initialised mapping.
pub struct Memory {
    map: Mapping,
    size: u64,
}

impl Memory {
    /// Allocate a guest address space of `size` bytes (page aligned).
    pub fn new(size: u64) -> Result<Memory> {
        let map = Mapping::anon(size as usize, Prot::RW)?;
        Ok(Memory { map, size })
    }

    /// Size of the address space in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Host pointer of guest address zero. Used to initialise `r14`.
    pub fn base(&self) -> *mut u8 {
        self.map.as_ptr()
    }

    /// Host address for `addr` after bounds checking.
    #[inline]
    pub fn host_ptr(&mut self, addr: u64, len: u64) -> Result<*mut u8> {
        if addr.checked_add(len).map_or(true, |end| end > self.size) {
            return Err(Error::OutOfBounds { addr, len });
        }
        Ok(unsafe { self.map.as_ptr().add(addr as usize) })
    }

    /// Constant variant of [`Memory::host_ptr`].
    #[inline]
    pub fn host_ptr_const(&self, addr: u64, len: u64) -> Result<*const u8> {
        if addr.checked_add(len).map_or(true, |end| end > self.size) {
            return Err(Error::OutOfBounds { addr, len });
        }
        Ok(unsafe { self.map.as_ptr().add(addr as usize) })
    }

    /// Slice into guest memory.
    #[inline]
    pub fn slice(&self, addr: u64, len: u64) -> Result<&[u8]> {
        Ok(unsafe { &*core::ptr::slice_from_raw_parts(self.host_ptr_const(addr, len)?, len as usize) })
    }

    /// Mutable slice into guest memory.
    #[inline]
    pub fn slice_mut(&mut self, addr: u64, len: u64) -> Result<&mut [u8]> {
        Ok(unsafe { &mut *core::ptr::slice_from_raw_parts_mut(self.host_ptr(addr, len)?, len as usize) })
    }

    /// Write `data` at guest address `addr`.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.slice_mut(addr, data.len() as u64)?.copy_from_slice(data);
        Ok(())
    }

    /// Read `data.len()` bytes at guest address `addr`.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        data.copy_from_slice(self.slice(addr, data.len() as u64)?);
        Ok(())
    }

    /// Little-endian scalar read (1, 2, 4 or 8 bytes).
    pub fn read_int(&self, addr: u64, bytes: u8) -> Result<u64> {
        match bytes {
            1 => Ok(self.slice(addr, 1)?[0] as u64),
            2 => Ok(u16::from_le_bytes(self.slice(addr, 2)?.try_into().unwrap()) as u64),
            4 => Ok(u32::from_le_bytes(self.slice(addr, 4)?.try_into().unwrap()) as u64),
            8 => Ok(u64::from_le_bytes(self.slice(addr, 8)?.try_into().unwrap())),
            _ => Err(Error::Host(format!("unsupported int size {bytes}"))),
        }
    }

    /// Little-endian scalar write (1, 2, 4 or 8 bytes).
    pub fn write_int(&mut self, addr: u64, bytes: u8, val: u64) -> Result<()> {
        match bytes {
            1 => self.write(addr, &[val as u8]),
            2 => self.write(addr, &(val as u16).to_le_bytes()),
            4 => self.write(addr, &(val as u32).to_le_bytes()),
            8 => self.write(addr, &val.to_le_bytes()),
            _ => Err(Error::Host(format!("unsupported int size {bytes}"))),
        }
    }

    /// Read a NUL-terminated byte string (ANSI path of the API layer).
    pub fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut a = addr;
        while out.len() < max {
            let b = self.slice(a, 1)?[0];
            if b == 0 {
                return Ok(out);
            }
            out.push(b);
            a += 1;
        }
        Ok(out)
    }

    /// Read a NUL-terminated UTF-16 string (wide path of the API layer).
    pub fn read_wstr(&self, addr: u64, max: usize) -> Result<Vec<u16>> {
        let mut out = Vec::new();
        let mut a = addr;
        while out.len() < max {
            let w = self.read_int(a, 2)? as u16;
            if w == 0 {
                return Ok(out);
            }
            out.push(w);
            a += 2;
        }
        Ok(out)
    }

    /// Write a byte string *with* terminating NUL.
    pub fn write_cstr(&mut self, addr: u64, s: &[u8]) -> Result<()> {
        self.write(addr, s)?;
        self.write(addr + s.len() as u64, &[0])
    }

    /// Fetch the 32-bit instruction word at `guest_pc`.
    #[inline]
    pub fn fetch_insn(&self, guest_pc: u64) -> Result<u32> {
        Ok(self.read_int(guest_pc, 4)? as u32)
    }

    /// Zero `len` bytes at `addr`.
    pub fn zero(&mut self, addr: u64, len: u64) -> Result<()> {
        self.slice_mut(addr, len)?.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_read_write() {
        let mut m = Memory::new(0x1_0000).unwrap();
        m.write(0x1000, b"hello").unwrap();
        assert_eq!(m.slice(0x1000, 5).unwrap(), b"hello");
        m.write_int(0x2000, 8, 0xDEAD_BEEF_CAFEF00D).unwrap();
        assert_eq!(m.read_int(0x2000, 8).unwrap(), 0xDEAD_BEEF_CAFEF00D);
        assert!(matches!(m.read_int(0x1_0000 - 4, 8), Err(Error::OutOfBounds { .. })));
    }

    #[test]
    fn strings() {
        let mut m = Memory::new(0x1_0000).unwrap();
        m.write_cstr(0x400, b"kernel32.dll").unwrap();
        assert_eq!(m.read_cstr(0x400, 256).unwrap(), b"kernel32.dll");
        let wide: Vec<u16> = "A64X".encode_utf16().collect();
        for (i, w) in wide.iter().enumerate() {
            m.write_int(0x800 + 2 * i as u64, 2, *w as u64).unwrap();
        }
        m.write_int(0x800 + 8, 2, 0).unwrap();
        assert_eq!(String::from_utf16(&m.read_wstr(0x800, 64).unwrap()).unwrap(), "A64X");
    }
}
