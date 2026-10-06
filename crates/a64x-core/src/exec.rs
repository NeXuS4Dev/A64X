//! Executable memory buffers holding translated code.

use crate::error::Result;
use crate::platform::{align_up, Mapping, Prot};

/// A block of host memory containing executable machine code.
///
/// Simple owning container: one allocation per block. The code cache
/// (a64x-xlat) stacks thousands of these in practice; large-scale
/// deployments group them into arenas (see ARCHITECTURE.md §7).
pub struct ExecBuffer {
    map: Mapping,
    code_len: usize,
}

// SAFETY: ownership is exclusive; the pointer stays valid until drop.
unsafe impl Send for ExecBuffer {}
unsafe impl Sync for ExecBuffer {}

impl ExecBuffer {
    /// Copy `code` into a new executable buffer.
    pub fn from_bytes(code: &[u8]) -> Result<ExecBuffer> {
        let len = align_up(code.len(), crate::platform::page_size());
        let map = Mapping::anon(len, Prot::RWX)?;
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), map.as_ptr(), code.len());
            // Zero the page tail so stray fetches can't decode garbage call
            // targets out of alignment padding.
            core::ptr::write_bytes(map.as_ptr().add(code.len()), 0xCC, len - code.len());
        }
        Ok(ExecBuffer { map, code_len: code.len() })
    }

    /// Address of the first instruction.
    pub fn entry(&self) -> *const u8 {
        self.map.as_ptr() as *const u8
    }

    /// Length of the machine code in bytes.
    pub fn code_len(&self) -> usize {
        self.code_len
    }

    /// Read back the stored machine code (for the persistent cache).
    pub fn bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.map.as_ptr(), self.code_len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_machine_code() {
        // mov eax, 42 ; ret  =>  b8 2a 00 00 00 c3
        let buf = ExecBuffer::from_bytes(&[0xB8, 42, 0, 0, 0, 0xC3]).unwrap();
        let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(buf.entry()) };
        assert_eq!(f(), 42);
    }
}
