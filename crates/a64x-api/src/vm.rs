//! Virtual memory bookkeeping (VirtualAlloc/VirtualProtect/VirtualQuery).
//!
//! The guest address space is one flat host mapping, so every page is
//! always physically present. What this map tracks is the Windows view of
//! it: which ranges are free, reserved or committed, their protection, and
//! which allocation they belong to. Protection is therefore reported exactly
//! but not enforced on translated loads and stores (see docs).

pub(crate) const MEM_COMMIT: u32 = 0x1000;
pub(crate) const MEM_RESERVE: u32 = 0x2000;
pub(crate) const MEM_DECOMMIT: u32 = 0x4000;
pub(crate) const MEM_RELEASE: u32 = 0x8000;
pub(crate) const MEM_FREE: u32 = 0x10000;
pub(crate) const MEM_PRIVATE: u32 = 0x20000;
pub(crate) const MEM_MAPPED: u32 = 0x40000;
pub(crate) const MEM_IMAGE: u32 = 0x100_0000;
pub(crate) const PAGE_NOACCESS: u32 = 0x01;
pub(crate) const PAGE_READONLY: u32 = 0x02;
pub(crate) const PAGE_READWRITE: u32 = 0x04;
pub(crate) const PAGE_WRITECOPY: u32 = 0x08;
pub(crate) const PAGE_EXECUTE: u32 = 0x10;
pub(crate) const PAGE_EXECUTE_READ: u32 = 0x20;
pub(crate) const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub(crate) const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// Page size of the guest.
pub(crate) const PAGE: u64 = 0x1000;
/// Allocation granularity (VirtualAlloc base addresses).
pub(crate) const GRANULARITY: u64 = 0x1_0000;

/// True for the single PAGE_* protection values Windows accepts.
pub(crate) fn valid_protect(p: u32) -> bool {
    matches!(
        p,
        PAGE_NOACCESS
            | PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

/// One run of pages with uniform attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Range {
    pub start: u64,
    pub end: u64,
    /// MEM_FREE, MEM_RESERVE or MEM_COMMIT.
    pub state: u32,
    /// Current protection (PAGE_*), meaningful when committed.
    pub protect: u32,
    /// Base address of the allocation this run belongs to.
    pub alloc_base: u64,
    /// Protection the allocation was created with.
    pub alloc_protect: u32,
    /// MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE (0 when free).
    pub kind: u32,
}

/// The address-space map over `[base, end)`.
pub(crate) struct VmMap {
    base: u64,
    end: u64,
    ranges: Vec<Range>,
}

impl VmMap {
    /// Map with the whole arena free.
    pub(crate) fn new(base: u64, end: u64) -> VmMap {
        let free = Range {
            start: base,
            end,
            state: MEM_FREE,
            protect: 0,
            alloc_base: 0,
            alloc_protect: 0,
            kind: 0,
        };
        VmMap {
            base,
            end,
            ranges: vec![free],
        }
    }

    /// The run containing `addr`, if `addr` is inside the arena.
    pub(crate) fn range_of(&self, addr: u64) -> Option<Range> {
        self.ranges
            .iter()
            .copied()
            .find(|r| r.start <= addr && addr < r.end)
    }

    /// Lowest free address for a `size`-byte block aligned to `align`.
    pub(crate) fn find_free(&self, size: u64, align: u64) -> Option<u64> {
        let align = align.max(PAGE);
        for r in &self.ranges {
            if r.state != MEM_FREE {
                continue;
            }
            let a = r.start.checked_add(align - 1)? & !(align - 1);
            if a.checked_add(size)? <= r.end {
                return Some(a);
            }
        }
        None
    }

    fn split_at(&mut self, addr: u64) {
        if addr <= self.base || addr >= self.end {
            return;
        }
        if let Some(i) = self
            .ranges
            .iter()
            .position(|r| r.start < addr && addr < r.end)
        {
            let mut right = self.ranges[i];
            right.start = addr;
            self.ranges[i].end = addr;
            self.ranges.insert(i + 1, right);
        }
    }

    fn merge(&mut self) {
        let mut out: Vec<Range> = Vec::with_capacity(self.ranges.len());
        for r in self.ranges.drain(..) {
            if let Some(last) = out.last_mut() {
                let same = last.state == r.state
                    && last.protect == r.protect
                    && last.alloc_base == r.alloc_base
                    && last.alloc_protect == r.alloc_protect
                    && last.kind == r.kind
                    && last.end == r.start;
                if same {
                    last.end = r.end;
                    continue;
                }
            }
            out.push(r);
        }
        self.ranges = out;
    }

    /// Apply `f` to every run inside `[start, end)`.
    pub(crate) fn apply(&mut self, start: u64, end: u64, f: impl Fn(&mut Range)) {
        self.split_at(start);
        self.split_at(end);
        for r in self.ranges.iter_mut() {
            if r.start >= start && r.end <= end {
                f(r);
            }
        }
        self.merge();
    }

    /// Reserve `[start, start+size)` as one allocation.
    pub(crate) fn reserve(&mut self, start: u64, size: u64, protect: u32, kind: u32) {
        self.apply(start, start + size, |r| {
            r.state = MEM_RESERVE;
            r.protect = protect;
            r.alloc_base = start;
            r.alloc_protect = protect;
            r.kind = kind;
        });
    }

    /// Commit `[start, start+size)` with `protect`.
    pub(crate) fn commit(&mut self, start: u64, size: u64, protect: u32) {
        self.apply(start, start + size, |r| {
            r.state = MEM_COMMIT;
            r.protect = protect;
        });
    }

    /// Decommit `[start, start+size)` (back to reserved).
    pub(crate) fn decommit(&mut self, start: u64, size: u64) {
        self.apply(start, start + size, |r| {
            r.state = MEM_RESERVE;
            r.protect = 0;
        });
    }

    /// Free every run belonging to the allocation based at `alloc_base`.
    pub(crate) fn release(&mut self, alloc_base: u64) {
        self.apply(0, u64::MAX, |r| {
            if r.alloc_base == alloc_base && r.state != MEM_FREE {
                r.state = MEM_FREE;
                r.protect = 0;
                r.alloc_base = 0;
                r.alloc_protect = 0;
                r.kind = 0;
            }
        });
    }

    /// Change protection of `[start, start+size)`. Returns the protection of
    /// the first run before the change.
    pub(crate) fn protect(&mut self, start: u64, size: u64, protect: u32) -> u32 {
        let old = self.range_of(start).map(|r| r.protect).unwrap_or(0);
        self.apply(start, start + size, |r| r.protect = protect);
        old
    }

    /// Start of the first run that begins after `addr`.
    pub(crate) fn next_start_after(&self, addr: u64) -> Option<u64> {
        self.ranges.iter().map(|r| r.start).find(|s| *s > addr)
    }

    /// True if every page of `[start, start+size)` is committed.
    pub(crate) fn all_committed(&self, start: u64, size: u64) -> bool {
        let mut a = start;
        let end = start + size;
        while a < end {
            match self.range_of(a) {
                Some(r) if r.state == MEM_COMMIT => a = r.end,
                _ => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_commit_release_round_trip() {
        let mut m = VmMap::new(0x1000_0000, 0x2000_0000);
        let a = m.find_free(0x10000, GRANULARITY).unwrap();
        assert_eq!(a % GRANULARITY, 0);
        m.reserve(a, 0x10000, PAGE_READWRITE, MEM_PRIVATE);
        assert_eq!(m.range_of(a).unwrap().state, MEM_RESERVE);
        m.commit(a, 0x1000, PAGE_READWRITE);
        assert_eq!(m.range_of(a).unwrap().state, MEM_COMMIT);
        assert_eq!(m.range_of(a + 0x1000).unwrap().state, MEM_RESERVE);
        assert!(m.all_committed(a, 0x1000));
        assert!(!m.all_committed(a, 0x2000));
        m.release(a);
        assert_eq!(m.range_of(a).unwrap().state, MEM_FREE);
        assert_eq!(m.ranges.len(), 1, "runs coalesce back to one free run");
    }

    #[test]
    fn protect_returns_previous_and_splits() {
        let mut m = VmMap::new(0x1000_0000, 0x2000_0000);
        m.reserve(0x1000_0000, 0x4000, PAGE_READWRITE, MEM_PRIVATE);
        m.commit(0x1000_0000, 0x4000, PAGE_READWRITE);
        let old = m.protect(0x1000_1000, 0x1000, PAGE_READONLY);
        assert_eq!(old, PAGE_READWRITE);
        assert_eq!(m.range_of(0x1000_1000).unwrap().protect, PAGE_READONLY);
        assert_eq!(m.range_of(0x1000_0000).unwrap().protect, PAGE_READWRITE);
    }
}
