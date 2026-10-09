//! KERNEL32 memory: heaps (process and private), virtual memory, file
//! mappings, and the Local/Global allocation families.

use crate::handles::{Obj, ObjRef};
use crate::heap::{self, Heap};
use crate::kernel32::{Mapping, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, INVALID_HANDLE};
use crate::vm::{
    self, GRANULARITY, MEM_COMMIT, MEM_DECOMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    MEM_RELEASE, MEM_RESERVE, PAGE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};
use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;

/// Size of the arena reserved for each HeapCreate heap.
const PRIVATE_HEAP_SIZE: u64 = 16 << 20;
/// ERROR_NOT_ENOUGH_MEMORY.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// ERROR_INVALID_ADDRESS.
const ERROR_INVALID_ADDRESS: u32 = 487;
/// ERROR_NOT_LOCKED.
const ERROR_NOT_LOCKED: u32 = 158;
/// ERROR_ALREADY_EXISTS.
const ERROR_ALREADY_EXISTS: u32 = 183;
/// ERROR_FILE_NOT_FOUND.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const HEAP_ZERO_MEMORY: u32 = 0x8;
const LMEM_ZEROINIT: u32 = 0x40;
const PAGE_ALIGN_MASK: u64 = !(PAGE - 1);

fn round_page(n: u64) -> u64 {
    n.saturating_add(PAGE - 1) & PAGE_ALIGN_MASK
}

/// Heap index behind a heap handle.
fn heap_index(ctx: &ApiCtx, h: u64) -> Option<usize> {
    match ctx.p.handles.get(h).map(|o| match &*o.borrow() {
        Obj::Heap(i) => Some(*i),
        _ => None,
    }) {
        Some(Some(i)) => Some(i),
        _ => None,
    }
}

fn get_process_heap(ctx: &mut ApiCtx) -> Result<()> {
    if ctx.p.k32.process_heap == 0 {
        ctx.p.k32.process_heap = ctx.p.handles.insert(Obj::Heap(0));
    }
    let h = ctx.p.k32.process_heap;
    ctx.ret(h);
    Ok(())
}

fn heap_create(ctx: &mut ApiCtx) -> Result<()> {
    let flags = ctx.au(0);
    let Some(base) = ctx.p.vm.find_free(PRIVATE_HEAP_SIZE, GRANULARITY) else {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        ctx.ret(0);
        return Ok(());
    };
    ctx.p
        .vm
        .reserve(base, PRIVATE_HEAP_SIZE, PAGE_READWRITE, MEM_PRIVATE);
    commit_zeroed(ctx, base, PRIVATE_HEAP_SIZE, PAGE_READWRITE)?;
    let mut hp = Heap::new(base, base + PRIVATE_HEAP_SIZE);
    hp.flags = flags;
    ctx.p.heaps.push(Some(hp));
    let idx = ctx.p.heaps.len() - 1;
    let h = ctx.p.handles.insert(Obj::Heap(idx));
    ctx.ret(h);
    Ok(())
}

fn heap_destroy(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    match heap_index(ctx, h) {
        Some(0) | None => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret_bool(false);
        }
        Some(i) => {
            if let Some(Some(hp)) = ctx.p.heaps.get(i) {
                let base = hp.base;
                ctx.p.vm.release(base);
            }
            if let Some(slot) = ctx.p.heaps.get_mut(i) {
                *slot = None;
            }
            ctx.p.handles.close(h);
            ctx.ret_bool(true);
        }
    }
    Ok(())
}

fn heap_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let (h, flags, size) = (ctx.a(0), ctx.au(1), ctx.a(2));
    let Some(i) = heap_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    };
    let p = heap::alloc(ctx, i, size.max(1), 16, flags & HEAP_ZERO_MEMORY != 0)?;
    if p == 0 {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ctx.ret(p);
    Ok(())
}

fn heap_free(ctx: &mut ApiCtx) -> Result<()> {
    let (h, p) = (ctx.a(0), ctx.a(2));
    let Some(i) = heap_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let ok = p != 0 && heap::free(ctx, i, p);
    if !ok {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
    }
    ctx.ret_bool(ok);
    Ok(())
}

fn heap_realloc(ctx: &mut ApiCtx) -> Result<()> {
    let (h, flags, p, size) = (ctx.a(0), ctx.au(1), ctx.a(2), ctx.a(3));
    let Some(i) = heap_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    };
    let r = heap::realloc(ctx, i, p, size.max(1), 16, flags & HEAP_ZERO_MEMORY != 0)?;
    if r == 0 {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ctx.ret(r);
    Ok(())
}

fn heap_size(ctx: &mut ApiCtx) -> Result<()> {
    let (h, p) = (ctx.a(0), ctx.a(2));
    let Some(i) = heap_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(u64::MAX);
        return Ok(());
    };
    match heap::size_of(ctx, i, p) {
        Some(n) => ctx.ret(n),
        None => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret(u64::MAX);
        }
    }
    Ok(())
}

fn heap_validate(ctx: &mut ApiCtx) -> Result<()> {
    let (h, p) = (ctx.a(0), ctx.a(2));
    let ok = match heap_index(ctx, h) {
        Some(i) => p == 0 || heap::size_of(ctx, i, p).is_some(),
        None => false,
    };
    ctx.ret_bool(ok);
    Ok(())
}

fn heap_compact(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let r = match heap_index(ctx, h)
        .and_then(|i| ctx.p.heaps.get(i))
        .and_then(|x| x.as_ref())
    {
        Some(hp) => hp.largest_free(),
        None => 0,
    };
    ctx.ret(r);
    Ok(())
}

fn ret_true(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_bool(true);
    Ok(())
}

/// Commit `[base, base+size)`, zero-filling the pages that were only reserved.
pub(crate) fn commit_zeroed(ctx: &mut ApiCtx, base: u64, size: u64, protect: u32) -> Result<()> {
    let mut a = base;
    let end = base + size;
    while a < end {
        let Some(r) = ctx.p.vm.range_of(a) else {
            break;
        };
        let run_end = r.end.min(end);
        if r.state == vm::MEM_RESERVE {
            ctx.zero(a, run_end - a)?;
        }
        a = run_end;
    }
    ctx.p.vm.commit(base, size, protect);
    Ok(())
}

fn virtual_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let (addr, size, ty, protect) = (ctx.a(0), ctx.a(1), ctx.au(2), ctx.au(3));
    let size = round_page(size);
    let reserve = ty & MEM_RESERVE != 0;
    let commit = ty & MEM_COMMIT != 0;
    let prot = if protect == 0 {
        PAGE_READWRITE
    } else {
        protect
    };
    if size == 0 || (!reserve && !commit) || (commit && !vm::valid_protect(prot)) {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let base = if reserve {
        let base = if addr != 0 {
            if addr % GRANULARITY != 0
                || ctx.p.vm.range_of(addr).is_none_or(|r| r.state != MEM_FREE)
            {
                ctx.set_last_error(ERROR_INVALID_ADDRESS);
                ctx.ret(0);
                return Ok(());
            }
            addr
        } else {
            match ctx.p.vm.find_free(size, GRANULARITY) {
                Some(b) => b,
                None => {
                    ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
                    ctx.ret(0);
                    return Ok(());
                }
            }
        };
        ctx.p.vm.reserve(base, size, prot, MEM_PRIVATE);
        base
    } else {
        // commit-only: the range must lie in reserved memory
        if addr == 0 {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret(0);
            return Ok(());
        }
        let mut a = addr;
        while a < addr + size {
            match ctx.p.vm.range_of(a) {
                Some(r) if r.state == vm::MEM_RESERVE || r.state == MEM_COMMIT => a = r.end,
                _ => {
                    ctx.set_last_error(ERROR_INVALID_ADDRESS);
                    ctx.ret(0);
                    return Ok(());
                }
            }
        }
        addr
    };
    if commit {
        commit_zeroed(ctx, base, size, prot)?;
    }
    ctx.ret(base);
    Ok(())
}

fn virtual_free(ctx: &mut ApiCtx) -> Result<()> {
    let (addr, size, ty) = (ctx.a(0), ctx.a(1), ctx.au(2));
    let release = ty & MEM_RELEASE != 0;
    let decommit = ty & MEM_DECOMMIT != 0;
    if release == decommit || (release && size != 0) {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    let Some(r) = ctx.p.vm.range_of(addr) else {
        ctx.set_last_error(ERROR_INVALID_ADDRESS);
        ctx.ret_bool(false);
        return Ok(());
    };
    if release {
        if r.alloc_base != addr {
            ctx.set_last_error(ERROR_INVALID_ADDRESS);
            ctx.ret_bool(false);
            return Ok(());
        }
        // a heap region must be destroyed through HeapDestroy
        if ctx.p.heaps.iter().flatten().any(|h| h.base == addr) {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret_bool(false);
            return Ok(());
        }
        ctx.p.vm.release(addr);
    } else {
        let size = round_page(size);
        ctx.p.vm.decommit(addr, size);
    }
    ctx.ret_bool(true);
    Ok(())
}

fn virtual_protect(ctx: &mut ApiCtx) -> Result<()> {
    let (addr, size, prot, old_p) = (ctx.a(0), ctx.a(1), ctx.au(2), ctx.a(3));
    let size = round_page(size);
    if !vm::valid_protect(prot) || size == 0 {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    if !ctx.p.vm.all_committed(addr, size) {
        ctx.set_last_error(ERROR_INVALID_ADDRESS);
        ctx.ret_bool(false);
        return Ok(());
    }
    let old = ctx.p.vm.protect(addr, size, prot);
    if old_p != 0 {
        ctx.wr(old_p, 4, old as u64)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

/// Write a MEMORY_BASIC_INFORMATION for `addr`.
fn query_region(ctx: &mut ApiCtx, addr: u64, mbi: u64) -> Result<u64> {
    let page = addr & PAGE_ALIGN_MASK;
    let (base, size, state, protect, alloc_base, alloc_protect, kind) =
        if let Some(r) = ctx.p.vm.range_of(page) {
            (
                r.start,
                r.end - r.start,
                r.state,
                r.protect,
                r.alloc_base,
                r.alloc_protect,
                r.kind,
            )
        } else if let Some(m) = ctx
            .modules
            .iter()
            .find(|m| page >= m.base && page < m.base + m.size)
        {
            let end = m.base + round_page(m.size);
            (
                m.base,
                end - m.base,
                MEM_COMMIT,
                PAGE_READONLY,
                m.base,
                PAGE_READONLY,
                MEM_IMAGE,
            )
        } else if let Some(h) = ctx
            .p
            .heaps
            .iter()
            .flatten()
            .find(|h| page >= h.base && page < h.end)
        {
            (
                h.base,
                h.end - h.base,
                MEM_COMMIT,
                PAGE_READWRITE,
                h.base,
                PAGE_READWRITE,
                MEM_PRIVATE,
            )
        } else {
            // free address space up to the next known region
            let next = ctx
                .p
                .vm
                .next_start_after(page)
                .unwrap_or(ctx.state.mem_size);
            let start = page;
            (
                start,
                next.saturating_sub(start).max(PAGE),
                MEM_FREE,
                PAGE_NOACCESS,
                0,
                0,
                0,
            )
        };
    let state = if state == MEM_RESERVE {
        vm::MEM_RESERVE
    } else {
        state
    };
    ctx.zero(mbi, 48)?;
    ctx.wr(mbi, 8, base)?;
    ctx.wr(mbi + 8, 8, alloc_base)?;
    ctx.wr(mbi + 16, 4, alloc_protect as u64)?;
    ctx.wr(mbi + 24, 8, size)?;
    ctx.wr(mbi + 32, 4, state as u64)?;
    ctx.wr(mbi + 36, 4, protect as u64)?;
    ctx.wr(mbi + 40, 4, kind as u64)?;
    Ok(48)
}

fn virtual_query(ctx: &mut ApiCtx) -> Result<()> {
    let (addr, mbi, len) = (ctx.a(0), ctx.a(1), ctx.a(2));
    if len < 48 {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let n = query_region(ctx, addr, mbi)?;
    ctx.ret(n);
    Ok(())
}

fn virtual_query_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (addr, mbi, len) = (ctx.a(1), ctx.a(2), ctx.a(3));
    if len < 48 {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let n = query_region(ctx, addr, mbi)?;
    ctx.ret(n);
    Ok(())
}

/// IsBadReadPtr/IsBadWritePtr: FALSE when the range is committed memory.
fn is_bad_ptr(ctx: &mut ApiCtx) -> Result<()> {
    let (p, n) = (ctx.a(0), ctx.a(1));
    let ok = n == 0
        || ctx.p.vm.all_committed(p, n)
        || ctx
            .modules
            .iter()
            .any(|m| p >= m.base && p + n <= m.base + m.size)
        || ctx
            .p
            .heaps
            .iter()
            .flatten()
            .any(|h| p >= h.base && p + n <= h.end);
    ctx.ret_bool(!ok);
    Ok(())
}

/// Write a file mapping's contents back to its file.
fn write_back(ctx: &mut ApiCtx, idx: usize) -> Result<()> {
    let (base, size, file, protect) = match ctx.p.k32.mappings.get(idx) {
        Some(m) => (m.base, m.size, m.file.clone(), m.protect),
        None => return Ok(()),
    };
    let Some(path) = file else {
        return Ok(());
    };
    if base == 0 || protect & 0xC == 0 {
        return Ok(());
    }
    let data = ctx.bytes(base, size)?;
    let host = path.replace('\\', "/");
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&host) {
        use std::io::Write;
        let _ = f.write_all(&data);
    }
    Ok(())
}

fn create_file_mapping_common(
    ctx: &mut ApiCtx,
    hfile: u64,
    protect: u32,
    maxhi: u64,
    maxlo: u64,
    name: Option<String>,
) -> Result<()> {
    if let Some(n) = &name {
        if let Some(existing) = ctx.p.k32.names.get(n).cloned() {
            let h = ctx.p.handles.insert_ref(existing);
            ctx.set_last_error(ERROR_ALREADY_EXISTS);
            ctx.ret(h);
            return Ok(());
        }
    }
    let (size, file) = if hfile == INVALID_HANDLE {
        ((maxhi << 32) | maxlo, None)
    } else {
        let info = ctx.p.handles.get(hfile).map(|o| match &*o.borrow() {
            Obj::File(f) => Some((
                f.path.clone(),
                f.file.metadata().map(|m| m.len()).unwrap_or(0),
            )),
            _ => None,
        });
        match info {
            Some(Some((path, len))) => {
                let want = (maxhi << 32) | maxlo;
                let size = if want == 0 { len } else { want };
                (size, Some(path))
            }
            _ => {
                ctx.set_last_error(ERROR_INVALID_HANDLE);
                ctx.ret(0);
                return Ok(());
            }
        }
    };
    if size == 0 {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    ctx.p.k32.mappings.push(Mapping {
        size,
        base: 0,
        views: 0,
        file,
        protect: if protect == 0 {
            PAGE_READWRITE
        } else {
            protect
        },
    });
    let idx = ctx.p.k32.mappings.len() - 1;
    let obj: ObjRef = std::rc::Rc::new(std::cell::RefCell::new(Obj::Mapping(idx)));
    if let Some(n) = name {
        ctx.p.k32.names.insert(n, obj.clone());
    }
    let h = ctx.p.handles.insert_ref(obj);
    ctx.set_last_error(0);
    ctx.ret(h);
    Ok(())
}

fn create_file_mapping_a(ctx: &mut ApiCtx) -> Result<()> {
    let (hf, prot, hi, lo) = (ctx.a(0), ctx.au(2), ctx.a(3), ctx.a(4));
    let name = ctx.a(5);
    let name = if name == 0 {
        None
    } else {
        Some(ctx.cstr_string(name)?)
    };
    create_file_mapping_common(ctx, hf, prot, hi, lo, name)
}

fn create_file_mapping_w(ctx: &mut ApiCtx) -> Result<()> {
    let (hf, prot, hi, lo) = (ctx.a(0), ctx.au(2), ctx.a(3), ctx.a(4));
    let name = ctx.a(5);
    let name = if name == 0 {
        None
    } else {
        Some(ctx.wstr_string(name)?)
    };
    create_file_mapping_common(ctx, hf, prot, hi, lo, name)
}

fn open_file_mapping_common(ctx: &mut ApiCtx, name: String) -> Result<()> {
    match ctx.p.k32.names.get(&name).cloned() {
        Some(obj) => {
            let h = ctx.p.handles.insert_ref(obj);
            ctx.ret(h);
        }
        None => {
            ctx.set_last_error(ERROR_FILE_NOT_FOUND);
            ctx.ret(0);
        }
    }
    Ok(())
}

fn open_file_mapping_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(2))?;
    open_file_mapping_common(ctx, n)
}

fn open_file_mapping_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(2))?;
    open_file_mapping_common(ctx, n)
}

fn mapping_index(ctx: &ApiCtx, h: u64) -> Option<usize> {
    match ctx.p.handles.get(h).map(|o| match &*o.borrow() {
        Obj::Mapping(i) => Some(*i),
        _ => None,
    }) {
        Some(Some(i)) => Some(i),
        _ => None,
    }
}

/// Map a view of mapping `idx` at `offset`, `size` bytes (0 = to the end).
fn map_view(ctx: &mut ApiCtx, idx: usize, offset: u64, size: u64) -> Result<u64> {
    let (msize, base0, file, protect) = {
        let m = &ctx.p.k32.mappings[idx];
        (m.size, m.base, m.file.clone(), m.protect)
    };
    if offset >= msize {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        return Ok(0);
    }
    let total = round_page(msize);
    let base = if base0 != 0 {
        base0
    } else {
        let Some(b) = ctx.p.vm.find_free(total, GRANULARITY) else {
            ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return Ok(0);
        };
        ctx.p.vm.reserve(b, total, protect, MEM_MAPPED);
        commit_zeroed(ctx, b, total, protect)?;
        if let Some(path) = &file {
            let host = path.replace('\\', "/");
            if let Ok(data) = std::fs::read(&host) {
                let n = data.len().min(msize as usize);
                ctx.put(b, &data[..n])?;
            }
        }
        ctx.p.k32.mappings[idx].base = b;
        b
    };
    let _ = size;
    ctx.p.k32.mappings[idx].views += 1;
    ctx.p.k32.views.insert(base + offset, idx);
    Ok(base + offset)
}

fn map_view_of_file(ctx: &mut ApiCtx) -> Result<()> {
    let (h, _access, hi, lo, size) = (ctx.a(0), ctx.au(1), ctx.a(2), ctx.a(3), ctx.a(4));
    let Some(idx) = mapping_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    };
    let offset = (hi << 32) | lo;
    let r = map_view(ctx, idx, offset, size)?;
    ctx.ret(r);
    Ok(())
}

fn map_view_of_file_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (h, _access, hi, lo, size) = (ctx.a(0), ctx.au(1), ctx.a(2), ctx.a(3), ctx.a(4));
    let Some(idx) = mapping_index(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    };
    let offset = (hi << 32) | lo;
    let r = map_view(ctx, idx, offset, size)?;
    ctx.ret(r);
    Ok(())
}

fn unmap_view_of_file(ctx: &mut ApiCtx) -> Result<()> {
    let addr = ctx.a(0);
    let Some(idx) = ctx.p.k32.views.remove(&addr) else {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    };
    write_back(ctx, idx)?;
    let remove_block = {
        let m = &mut ctx.p.k32.mappings[idx];
        m.views = m.views.saturating_sub(1);
        // file-backed blocks are re-read from the file on the next view;
        // anonymous blocks keep their contents for the life of the object
        m.views == 0 && m.file.is_some()
    };
    if remove_block {
        let base = ctx.p.k32.mappings[idx].base;
        if base != 0 {
            ctx.p.vm.release(base);
            ctx.p.k32.mappings[idx].base = 0;
        }
    }
    ctx.ret_bool(true);
    Ok(())
}

fn flush_view_of_file(ctx: &mut ApiCtx) -> Result<()> {
    let addr = ctx.a(0);
    if let Some(i) = ctx.p.k32.views.get(&addr).copied() {
        write_back(ctx, i)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn local_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let (flags, size) = (ctx.au(0), ctx.a(1));
    let p = heap::alloc(ctx, 0, size.max(1), 16, flags & LMEM_ZEROINIT != 0)?;
    if p == 0 {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ctx.ret(p);
    Ok(())
}

fn local_free(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    if p == 0 || heap::free(ctx, 0, p) {
        ctx.ret(0);
    } else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(p);
    }
    Ok(())
}

fn local_realloc(ctx: &mut ApiCtx) -> Result<()> {
    let (p, size, flags) = (ctx.a(0), ctx.a(1), ctx.au(2));
    let r = heap::realloc(ctx, 0, p, size.max(1), 16, flags & LMEM_ZEROINIT != 0)?;
    if r == 0 {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ctx.ret(r);
    Ok(())
}

fn local_size(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let n = heap::size_of(ctx, 0, p).unwrap_or(0);
    ctx.ret(n);
    Ok(())
}

/// Fixed memory: the handle is the pointer; locking is the identity.
fn local_lock(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(ctx.a(0));
    Ok(())
}

fn local_unlock(ctx: &mut ApiCtx) -> Result<()> {
    // fixed memory is never locked, so there is nothing to unlock
    ctx.set_last_error(ERROR_NOT_LOCKED);
    ctx.ret_bool(false);
    Ok(())
}

fn global_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let (flags, size) = (ctx.au(0), ctx.a(1));
    let p = heap::alloc(ctx, 0, size.max(1), 16, flags & LMEM_ZEROINIT != 0)?;
    if p == 0 {
        ctx.set_last_error(ERROR_NOT_ENOUGH_MEMORY);
    }
    ctx.ret(p);
    Ok(())
}

fn global_free(ctx: &mut ApiCtx) -> Result<()> {
    local_free(ctx)
}

fn global_realloc(ctx: &mut ApiCtx) -> Result<()> {
    local_realloc(ctx)
}

fn global_size(ctx: &mut ApiCtx) -> Result<()> {
    local_size(ctx)
}

fn global_lock(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    if heap::size_of(ctx, 0, h).is_none() {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    }
    *ctx.p.k32.global_locks.entry(h).or_insert(0) += 1;
    ctx.ret(h);
    Ok(())
}

fn global_unlock(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let remaining = match ctx.p.k32.global_locks.get_mut(&h) {
        Some(c) if *c > 0 => {
            *c -= 1;
            *c
        }
        _ => {
            ctx.set_last_error(ERROR_NOT_LOCKED);
            ctx.ret_bool(false);
            return Ok(());
        }
    };
    if remaining == 0 {
        ctx.p.k32.global_locks.remove(&h);
        ctx.set_last_error(0);
        ctx.ret_bool(false);
    } else {
        ctx.ret_bool(true);
    }
    Ok(())
}

fn large_page_minimum(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(0);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "kernel32",
        "GetProcessHeap" => get_process_heap,
        "HeapCreate" => heap_create,
        "HeapDestroy" => heap_destroy,
        "HeapAlloc" => heap_alloc,
        "HeapFree" => heap_free,
        "HeapReAlloc" => heap_realloc,
        "HeapSize" => heap_size,
        "HeapValidate" => heap_validate,
        "HeapCompact" => heap_compact,
        "HeapLock" => ret_true,
        "HeapUnlock" => ret_true,
        "VirtualAlloc" => virtual_alloc,
        "VirtualFree" => virtual_free,
        "VirtualProtect" => virtual_protect,
        "VirtualQuery" => virtual_query,
        "VirtualQueryEx" => virtual_query_ex,
        "IsBadReadPtr" => is_bad_ptr,
        "IsBadWritePtr" => is_bad_ptr,
        "CreateFileMappingA" => create_file_mapping_a,
        "CreateFileMappingW" => create_file_mapping_w,
        "OpenFileMappingA" => open_file_mapping_a,
        "OpenFileMappingW" => open_file_mapping_w,
        "MapViewOfFile" => map_view_of_file,
        "MapViewOfFileEx" => map_view_of_file_ex,
        "UnmapViewOfFile" => unmap_view_of_file,
        "FlushViewOfFile" => flush_view_of_file,
        "LocalAlloc" => local_alloc,
        "LocalFree" => local_free,
        "LocalReAlloc" => local_realloc,
        "LocalSize" => local_size,
        "LocalLock" => local_lock,
        "LocalUnlock" => local_unlock,
        "GlobalAlloc" => global_alloc,
        "GlobalFree" => global_free,
        "GlobalReAlloc" => global_realloc,
        "GlobalSize" => global_size,
        "GlobalLock" => global_lock,
        "GlobalUnlock" => global_unlock,
        "GetLargePageMinimum" => large_page_minimum,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_rounding() {
        assert_eq!(round_page(1), PAGE);
        assert_eq!(round_page(PAGE), PAGE);
        assert_eq!(round_page(0), 0);
    }
}
