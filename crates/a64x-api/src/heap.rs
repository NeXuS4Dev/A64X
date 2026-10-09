//! Heaps: a real allocator over guest memory.
//!
//! Each heap owns an address range. Blocks are carved first-fit from a
//! free map (`start -> length`), aligned as requested, and returned blocks
//! are coalesced with their neighbours. Live blocks are tracked host-side
//! (`address -> requested size, capacity`), so HeapSize, HeapFree and
//! realloc can validate their arguments the way the Windows heap does.

use crate::ApiCtx;
use a64x_core::Result;
use std::collections::BTreeMap;

/// Allocation granule (MEMORY_ALLOCATION_ALIGNMENT on ARM64).
pub(crate) const GRAIN: u64 = 16;

#[derive(Clone, Copy)]
struct Blk {
    req: u64,
    cap: u64,
}

/// One heap.
pub(crate) struct Heap {
    /// First guest address of the heap's range.
    pub base: u64,
    /// One past the last guest address of the heap's range.
    pub end: u64,
    /// HeapCreate options (HEAP_NO_SERIALIZE etc.), informational.
    pub flags: u32,
    free: BTreeMap<u64, u64>,
    live: BTreeMap<u64, Blk>,
}

impl Heap {
    /// Empty heap over `[base, end)`.
    pub(crate) fn new(base: u64, end: u64) -> Heap {
        let mut free = BTreeMap::new();
        if end > base {
            free.insert(base, end - base);
        }
        Heap {
            base,
            end,
            flags: 0,
            free,
            live: BTreeMap::new(),
        }
    }

    /// Allocate `size` bytes aligned to `align` (power of two, >= 16).
    /// Returns `None` when the heap cannot satisfy the request.
    pub(crate) fn alloc(&mut self, size: u64, align: u64) -> Option<u64> {
        let align = align.max(GRAIN).next_power_of_two();
        let cap = size.max(1).checked_add(GRAIN - 1)? & !(GRAIN - 1);
        let mut pick = None;
        for (&s, &len) in &self.free {
            let a = s.checked_add(align - 1)? & !(align - 1);
            if a.checked_add(cap)? <= s + len {
                pick = Some((s, len, a));
                break;
            }
        }
        let (s, len, a) = pick?;
        self.free.remove(&s);
        if a > s {
            self.free.insert(s, a - s);
        }
        let tail = a + cap;
        if tail < s + len {
            self.free.insert(tail, s + len - tail);
        }
        self.live.insert(a, Blk { req: size, cap });
        Some(a)
    }

    /// Return the block at `addr` to the free map. False if `addr` is not a
    /// live block of this heap.
    pub(crate) fn free(&mut self, addr: u64) -> bool {
        let Some(b) = self.live.remove(&addr) else {
            return false;
        };
        let mut start = addr;
        let mut len = b.cap;
        if let Some((&ps, &pl)) = self.free.range(..addr).next_back() {
            if ps + pl == addr {
                self.free.remove(&ps);
                start = ps;
                len += pl;
            }
        }
        if let Some(nl) = self.free.remove(&(addr + b.cap)) {
            len += nl;
        }
        self.free.insert(start, len);
        true
    }

    /// Requested size of the live block at `addr`.
    pub(crate) fn size(&self, addr: u64) -> Option<u64> {
        self.live.get(&addr).map(|b| b.req)
    }

    /// Change the requested size of a live block without moving it, when
    /// the block's capacity allows it.
    pub(crate) fn resize_in_place(&mut self, addr: u64, new_req: u64) -> bool {
        match self.live.get_mut(&addr) {
            Some(b) if new_req <= b.cap => {
                b.req = new_req;
                true
            }
            _ => false,
        }
    }

    /// Largest contiguous free run (HeapCompact's return value).
    pub(crate) fn largest_free(&self) -> u64 {
        self.free.values().copied().max().unwrap_or(0)
    }
}

/// Allocate from heap `h` (zeroing when `zero`). Returns 0 on exhaustion.
pub(crate) fn alloc(ctx: &mut ApiCtx, h: usize, size: u64, align: u64, zero: bool) -> Result<u64> {
    let got = ctx
        .p
        .heaps
        .get_mut(h)
        .and_then(|x| x.as_mut())
        .and_then(|hp| hp.alloc(size, align));
    match got {
        Some(addr) => {
            if zero {
                ctx.zero(addr, size)?;
            }
            Ok(addr)
        }
        None => Ok(0),
    }
}

/// Free a block of heap `h`. False if `addr` is not live in that heap.
pub(crate) fn free(ctx: &mut ApiCtx, h: usize, addr: u64) -> bool {
    match ctx.p.heaps.get_mut(h).and_then(|x| x.as_mut()) {
        Some(hp) => hp.free(addr),
        None => false,
    }
}

/// Requested size of the live block `addr` in heap `h`.
pub(crate) fn size_of(ctx: &ApiCtx, h: usize, addr: u64) -> Option<u64> {
    ctx.p
        .heaps
        .get(h)
        .and_then(|x| x.as_ref())
        .and_then(|hp| hp.size(addr))
}

/// Resize the block `addr` of heap `h` to `size` bytes, moving it when it
/// does not fit. Preserves contents up to the smaller size; zero-fills the
/// new tail when `zero`. Returns 0 if `addr` is not live or memory ran out.
pub(crate) fn realloc(
    ctx: &mut ApiCtx,
    h: usize,
    addr: u64,
    size: u64,
    align: u64,
    zero: bool,
) -> Result<u64> {
    if addr == 0 {
        return alloc(ctx, h, size, align, zero);
    }
    let Some(old) = size_of(ctx, h, addr) else {
        return Ok(0);
    };
    let grown = ctx
        .p
        .heaps
        .get_mut(h)
        .and_then(|x| x.as_mut())
        .map(|hp| hp.resize_in_place(addr, size))
        .unwrap_or(false);
    if grown {
        if zero && size > old {
            ctx.zero(addr + old, size - old)?;
        }
        return Ok(addr);
    }
    let new = alloc(ctx, h, size, align, false)?;
    if new == 0 {
        return Ok(0);
    }
    let n = old.min(size);
    let data = ctx.bytes(addr, n)?;
    ctx.put(new, &data)?;
    if zero && size > n {
        ctx.zero(new + n, size - n)?;
    }
    free(ctx, h, addr);
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_coalesces() {
        let mut h = Heap::new(0x1000, 0x1000 + 0x1000);
        let a = h.alloc(100, 16).unwrap();
        let b = h.alloc(100, 16).unwrap();
        assert!(a < b && a % 16 == 0 && b % 16 == 0);
        assert!(h.free(a));
        assert!(h.free(b));
        assert!(!h.free(b), "double free must be rejected");
        // everything merged back into one run
        assert_eq!(h.largest_free(), 0x1000);
        assert!(h.largest_free() == 0x1000);
    }

    #[test]
    fn alignment_is_honoured() {
        let mut h = Heap::new(0x1008, 0x10_0000);
        let a = h.alloc(10, 256).unwrap();
        assert_eq!(a % 256, 0);
        assert_eq!(h.size(a), Some(10));
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut h = Heap::new(0x1000, 0x1100);
        assert!(h.alloc(0x200, 16).is_none());
        assert!(h.alloc(0x80, 16).is_some());
    }

    #[test]
    fn in_place_resize_respects_capacity() {
        let mut h = Heap::new(0x1000, 0x2000);
        let a = h.alloc(20, 16).unwrap(); // capacity 32
        assert!(h.resize_in_place(a, 32));
        assert!(!h.resize_in_place(a, 33));
        assert_eq!(h.size(a), Some(32));
    }
}
