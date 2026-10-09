//! KERNEL32 synchronization, threads, TLS and FLS.
//!
//! Blocking calls follow the scheduler's retry protocol (see `sched`): an
//! adapter that cannot complete checks readiness without side effects, parks
//! the thread with [`ApiCtx::block_retry`] and re-runs when a synchronization
//! object changes. Critical sections keep their state in the guest structure
//! (LockCount, RecursionCount, OwningThread at their Windows offsets).

use crate::cont;
use crate::handles::{EventObj, MutexObj, Obj, ObjRef, SemObj};
use crate::kernel32::{
    CvState, InitState, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, PSEUDO_THREAD, STILL_ACTIVE,
};
use crate::sched::{self, TState};
use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;
use std::time::Instant;

const WAIT_OBJECT_0: u64 = 0;
const WAIT_ABANDONED_0: u64 = 0x80;
const WAIT_TIMEOUT: u64 = 0x102;
const WAIT_FAILED: u64 = 0xFFFF_FFFF;
const ERROR_TIMEOUT: u32 = 1460;
const ERROR_NOT_OWNER: u32 = 288;
const ERROR_TOO_MANY_POSTS: u32 = 298;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const TLS_SLOTS: usize = 64;
const FLS_SLOTS: usize = 4080;

/// Win32 readiness of one object for thread `me`.
fn ready(ctx: &ApiCtx, o: &ObjRef, seen: u64, me: u32) -> bool {
    match &*o.borrow() {
        Obj::Event(e) => e.signaled || e.pulse_gen != seen,
        Obj::Mutex(m) => m.owner == 0 || m.owner == me,
        Obj::Semaphore(s) => s.count > 0,
        Obj::Thread(tid) => ctx
            .p
            .sched
            .threads
            .iter()
            .any(|t| t.tid == *tid && t.state == TState::Finished),
        Obj::Console(_) | Obj::File(_) => true,
        Obj::Mapping(_) | Obj::Heap(_) | Obj::Find { .. } => false,
    }
}

/// Take ownership of an object that `ready` reported as signaled.
/// Returns true if a mutex was abandoned by its previous owner.
fn consume(o: &ObjRef, me: u32) -> bool {
    match &mut *o.borrow_mut() {
        Obj::Event(e) => {
            if !e.manual {
                e.signaled = false;
            }
            false
        }
        Obj::Mutex(m) => {
            if m.owner == me {
                m.count += 1;
                false
            } else {
                m.owner = me;
                m.count = 1;
                std::mem::take(&mut m.abandoned)
            }
        }
        Obj::Semaphore(s) => {
            s.count -= 1;
            false
        }
        _ => false,
    }
}

/// Pulse generation of an event (0 for other objects).
fn pulse_of(o: &ObjRef) -> u64 {
    match &*o.borrow() {
        Obj::Event(e) => e.pulse_gen,
        _ => 0,
    }
}

/// Wait for one or all of `hs`. Returns the Win32 wait result.
fn wait_on(ctx: &mut ApiCtx, hs: &[u64], all: bool, ms: u32) -> Result<u64> {
    let retry = sched::take_wait(ctx);
    let me = ctx.p.sched.cur_tid();
    let cur = ctx.p.sched.cur;
    let deadline = match retry {
        Some(d) => d,
        None => sched::deadline_for(ms),
    };
    let mut objs = Vec::with_capacity(hs.len());
    for h in hs {
        match ctx.p.handles.get(*h) {
            Some(o) => objs.push(o),
            None => {
                ctx.p.sched.threads[cur].wait_seen.clear();
                ctx.set_last_error(ERROR_INVALID_HANDLE);
                return Ok(WAIT_FAILED);
            }
        }
    }
    let seen: Vec<u64> = if retry.is_none() {
        objs.iter().map(pulse_of).collect()
    } else {
        ctx.p.sched.threads[cur].wait_seen.clone()
    };
    ctx.p.sched.threads[cur].wait_seen.clear();
    if all {
        if objs.iter().zip(&seen).all(|(o, s)| ready(ctx, o, *s, me)) {
            let mut abandoned = false;
            for o in &objs {
                abandoned |= consume(o, me);
            }
            return Ok(if abandoned {
                WAIT_ABANDONED_0
            } else {
                WAIT_OBJECT_0
            });
        }
    } else if let Some(i) = objs
        .iter()
        .zip(&seen)
        .position(|(o, s)| ready(ctx, o, *s, me))
    {
        let abandoned = consume(&objs[i], me);
        return Ok(if abandoned {
            WAIT_ABANDONED_0 + i as u64
        } else {
            WAIT_OBJECT_0 + i as u64
        });
    }
    let expired = deadline.is_some_and(|d| Instant::now() >= d);
    if ms == 0 || expired {
        return Ok(WAIT_TIMEOUT);
    }
    ctx.p.sched.threads[cur].wait_seen = seen;
    ctx.block_retry(deadline);
    Ok(WAIT_OBJECT_0)
}

fn wait_for_single_object(ctx: &mut ApiCtx) -> Result<()> {
    let (h, ms) = (ctx.a(0), ctx.au(1));
    let r = wait_on(ctx, &[h], false, ms)?;
    ctx.ret(r);
    Ok(())
}

fn wait_for_single_object_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (h, ms) = (ctx.a(0), ctx.au(1));
    let r = wait_on(ctx, &[h], false, ms)?;
    ctx.ret(r);
    Ok(())
}

fn wait_for_multiple_objects_common(
    ctx: &mut ApiCtx,
    count: u32,
    arr: u64,
    all: bool,
    ms: u32,
) -> Result<()> {
    if count == 0 || count > 64 {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(WAIT_FAILED);
        return Ok(());
    }
    let mut hs = Vec::with_capacity(count as usize);
    for i in 0..count as u64 {
        hs.push(ctx.rd(arr + 8 * i, 8)?);
    }
    let r = wait_on(ctx, &hs, all, ms)?;
    ctx.ret(r);
    Ok(())
}

fn wait_for_multiple_objects(ctx: &mut ApiCtx) -> Result<()> {
    let (count, arr, all, ms) = (ctx.au(0), ctx.a(1), ctx.au(2) != 0, ctx.au(3));
    wait_for_multiple_objects_common(ctx, count, arr, all, ms)
}

fn wait_for_multiple_objects_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (count, arr, all, ms) = (ctx.au(0), ctx.a(1), ctx.au(2) != 0, ctx.au(3));
    wait_for_multiple_objects_common(ctx, count, arr, all, ms)
}

/// Signal an event, mutex or semaphore (the "signal" half of SignalObjectAndWait).
fn signal_object(ctx: &mut ApiCtx, h: u64) -> bool {
    let Some(o) = ctx.p.handles.get(h) else {
        return false;
    };
    let me = ctx.p.sched.cur_tid();
    let ok = match &mut *o.borrow_mut() {
        Obj::Event(e) => {
            e.signaled = true;
            true
        }
        Obj::Mutex(m) => {
            if m.owner == me && m.count > 0 {
                m.count -= 1;
                if m.count == 0 {
                    m.owner = 0;
                }
                true
            } else {
                false
            }
        }
        Obj::Semaphore(s) => {
            if s.count < s.max {
                s.count += 1;
                true
            } else {
                false
            }
        }
        _ => false,
    };
    if ok {
        sched::notify(ctx);
    }
    ok
}

fn signal_object_and_wait(ctx: &mut ApiCtx) -> Result<()> {
    let (hs, hw, ms) = (ctx.a(0), ctx.a(1), ctx.au(2));
    // the signal happens once, on the first attempt
    let first = ctx.p.sched.threads[ctx.p.sched.cur].wait.is_none()
        && ctx.p.sched.threads[ctx.p.sched.cur].wait_seen.is_empty();
    if first && !signal_object(ctx, hs) {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(WAIT_FAILED);
        return Ok(());
    }
    let r = wait_on(ctx, &[hw], false, ms)?;
    ctx.ret(r);
    Ok(())
}

fn sleep_common(ctx: &mut ApiCtx, ms: u32) -> Result<()> {
    match sched::take_wait(ctx) {
        Some(deadline) => {
            if deadline.is_none() || deadline.is_some_and(|d| Instant::now() < d) {
                ctx.block_retry(deadline);
            }
            Ok(())
        }
        None => {
            if ms == 0 {
                ctx.yield_now();
                return Ok(());
            }
            let deadline = sched::deadline_for(ms);
            ctx.block_retry(deadline);
            Ok(())
        }
    }
}

fn sleep(ctx: &mut ApiCtx) -> Result<()> {
    let ms = ctx.au(0);
    sleep_common(ctx, ms)
}

fn sleep_ex(ctx: &mut ApiCtx) -> Result<()> {
    let ms = ctx.au(0);
    sleep_common(ctx, ms)?;
    ctx.ret(0);
    Ok(())
}

fn switch_to_thread(ctx: &mut ApiCtx) -> Result<()> {
    let others = ctx.p.sched.threads.len() > 1;
    if others {
        ctx.yield_now();
    }
    ctx.ret_bool(others);
    Ok(())
}

// ----- objects: events, mutexes, semaphores -----

fn create_named(ctx: &mut ApiCtx, name: Option<String>, obj: Obj) -> u64 {
    if let Some(n) = &name {
        if let Some(existing) = ctx.p.k32.names.get(n).cloned() {
            ctx.set_last_error(ERROR_ALREADY_EXISTS);
            return ctx.p.handles.insert_ref(existing);
        }
    }
    ctx.set_last_error(0);
    let r: ObjRef = std::rc::Rc::new(std::cell::RefCell::new(obj));
    if let Some(n) = name {
        ctx.p.k32.names.insert(n, r.clone());
    }
    ctx.p.handles.insert_ref(r)
}

fn open_named(ctx: &mut ApiCtx, name: String) -> u64 {
    match ctx.p.k32.names.get(&name).cloned() {
        Some(o) => ctx.p.handles.insert_ref(o),
        None => {
            ctx.set_last_error(ERROR_FILE_NOT_FOUND);
            0
        }
    }
}

fn optional_name_a(ctx: &ApiCtx, p: u64) -> Result<Option<String>> {
    if p == 0 {
        Ok(None)
    } else {
        Ok(Some(ctx.cstr_string(p)?))
    }
}

fn optional_name_w(ctx: &ApiCtx, p: u64) -> Result<Option<String>> {
    if p == 0 {
        Ok(None)
    } else {
        Ok(Some(ctx.wstr_string(p)?))
    }
}

fn create_event_common(ctx: &mut ApiCtx, name: Option<String>) -> Result<()> {
    let (manual, initial) = (ctx.au(1) != 0, ctx.au(2) != 0);
    let h = create_named(
        ctx,
        name,
        Obj::Event(EventObj {
            manual,
            signaled: initial,
            pulse_gen: 0,
        }),
    );
    ctx.ret(h);
    Ok(())
}

fn create_event_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_a(ctx, ctx.a(3))?;
    create_event_common(ctx, n)
}

fn create_event_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_w(ctx, ctx.a(3))?;
    create_event_common(ctx, n)
}

fn open_event_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn open_event_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn event_op(ctx: &mut ApiCtx, h: u64, op: u8) -> Result<()> {
    let Some(o) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let ok = match &mut *o.borrow_mut() {
        Obj::Event(e) => {
            match op {
                0 => e.signaled = true,
                1 => e.signaled = false,
                _ => {
                    e.pulse_gen += 1;
                    e.signaled = false;
                }
            }
            true
        }
        _ => false,
    };
    if !ok {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
    }
    if ok && op != 1 {
        sched::notify(ctx);
    }
    ctx.ret_bool(ok);
    Ok(())
}

fn set_event(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    event_op(ctx, h, 0)
}

fn reset_event(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    event_op(ctx, h, 1)
}

fn pulse_event(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    event_op(ctx, h, 2)
}

fn create_mutex_common(ctx: &mut ApiCtx, name: Option<String>) -> Result<()> {
    let initial = ctx.au(1) != 0;
    let me = ctx.p.sched.cur_tid();
    let m = MutexObj {
        owner: if initial { me } else { 0 },
        count: initial as u32,
        abandoned: false,
    };
    let h = create_named(ctx, name, Obj::Mutex(m));
    ctx.ret(h);
    Ok(())
}

fn create_mutex_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_a(ctx, ctx.a(2))?;
    create_mutex_common(ctx, n)
}

fn create_mutex_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_w(ctx, ctx.a(2))?;
    create_mutex_common(ctx, n)
}

fn open_mutex_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn open_mutex_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn release_mutex(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let me = ctx.p.sched.cur_tid();
    let Some(o) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let r: std::result::Result<(), u32> = match &mut *o.borrow_mut() {
        Obj::Mutex(m) if m.owner == me && m.count > 0 => {
            m.count -= 1;
            if m.count == 0 {
                m.owner = 0;
            }
            Ok(())
        }
        Obj::Mutex(_) => Err(ERROR_NOT_OWNER),
        _ => Err(ERROR_INVALID_HANDLE),
    };
    match r {
        Ok(()) => {
            sched::notify(ctx);
            ctx.ret_bool(true);
        }
        Err(e) => {
            ctx.set_last_error(e);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn create_semaphore_common(ctx: &mut ApiCtx, name: Option<String>) -> Result<()> {
    let (initial, max) = (ctx.ai(1) as i64, ctx.ai(2) as i64);
    if max <= 0 || initial < 0 || initial > max {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let h = create_named(
        ctx,
        name,
        Obj::Semaphore(SemObj {
            count: initial,
            max,
        }),
    );
    ctx.ret(h);
    Ok(())
}

fn create_semaphore_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_a(ctx, ctx.a(3))?;
    create_semaphore_common(ctx, n)
}

fn create_semaphore_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = optional_name_w(ctx, ctx.a(3))?;
    create_semaphore_common(ctx, n)
}

fn open_semaphore_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn open_semaphore_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(2))?;
    let h = open_named(ctx, n);
    ctx.ret(h);
    Ok(())
}

fn release_semaphore(ctx: &mut ApiCtx) -> Result<()> {
    let (h, count, prev_p) = (ctx.a(0), ctx.ai(1) as i64, ctx.a(2));
    let Some(o) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let r: std::result::Result<i64, u32> = match &mut *o.borrow_mut() {
        Obj::Semaphore(s) => {
            if count <= 0 {
                Err(ERROR_INVALID_PARAMETER)
            } else if s.count + count > s.max {
                Err(ERROR_TOO_MANY_POSTS)
            } else {
                let prev = s.count;
                s.count += count;
                Ok(prev)
            }
        }
        _ => Err(ERROR_INVALID_HANDLE),
    };
    match r {
        Ok(prev) => {
            if prev_p != 0 {
                ctx.wr(prev_p, 4, prev as u64)?;
            }
            sched::notify(ctx);
            ctx.ret_bool(true);
        }
        Err(e) => {
            ctx.set_last_error(e);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

// ----- critical sections (CRITICAL_SECTION: LockCount@8, RecursionCount@12, OwningThread@16, SpinCount@32) -----

fn cs_init(ctx: &mut ApiCtx, cs: u64, spin: u64) -> Result<()> {
    ctx.zero(cs, 40)?;
    ctx.wr(cs + 8, 4, 0xFFFF_FFFF)?;
    ctx.wr(cs + 32, 8, spin)?;
    Ok(())
}

fn initialize_critical_section(ctx: &mut ApiCtx) -> Result<()> {
    let cs = ctx.a(0);
    cs_init(ctx, cs, 0)
}

fn initialize_critical_section_and_spin_count(ctx: &mut ApiCtx) -> Result<()> {
    let (cs, spin) = (ctx.a(0), ctx.au(1) as u64);
    cs_init(ctx, cs, spin)?;
    ctx.ret_bool(true);
    Ok(())
}

fn enter_critical_section(ctx: &mut ApiCtx) -> Result<()> {
    let _ = sched::take_wait(ctx);
    let cs = ctx.a(0);
    let me = ctx.p.sched.cur_tid() as u64;
    let owner = ctx.rd(cs + 16, 8)?;
    if owner == 0 {
        ctx.wr(cs + 16, 8, me)?;
        ctx.wr(cs + 12, 4, 1)?;
        ctx.wr(cs + 8, 4, 0)?;
    } else if owner == me {
        let r = ctx.rd(cs + 12, 4)?;
        ctx.wr(cs + 12, 4, r + 1)?;
    } else {
        ctx.block_retry(None);
    }
    Ok(())
}

fn try_enter_critical_section(ctx: &mut ApiCtx) -> Result<()> {
    let cs = ctx.a(0);
    let me = ctx.p.sched.cur_tid() as u64;
    let owner = ctx.rd(cs + 16, 8)?;
    if owner == 0 {
        ctx.wr(cs + 16, 8, me)?;
        ctx.wr(cs + 12, 4, 1)?;
        ctx.wr(cs + 8, 4, 0)?;
        ctx.ret_bool(true);
    } else if owner == me {
        let r = ctx.rd(cs + 12, 4)?;
        ctx.wr(cs + 12, 4, r + 1)?;
        ctx.ret_bool(true);
    } else {
        ctx.ret_bool(false);
    }
    Ok(())
}

fn leave_critical_section(ctx: &mut ApiCtx) -> Result<()> {
    let cs = ctx.a(0);
    let owner = ctx.rd(cs + 16, 8)?;
    let rec = ctx.rd(cs + 12, 4)?;
    if owner != ctx.p.sched.cur_tid() as u64 || rec == 0 {
        return Ok(());
    }
    if rec > 1 {
        ctx.wr(cs + 12, 4, rec - 1)?;
    } else {
        ctx.wr(cs + 12, 4, 0)?;
        ctx.wr(cs + 16, 8, 0)?;
        ctx.wr(cs + 8, 4, 0xFFFF_FFFF)?;
        sched::notify(ctx);
    }
    Ok(())
}

fn delete_critical_section(ctx: &mut ApiCtx) -> Result<()> {
    let cs = ctx.a(0);
    ctx.zero(cs, 40)?;
    ctx.wr(cs, 8, u64::MAX)?;
    Ok(())
}

fn set_critical_section_spin_count(ctx: &mut ApiCtx) -> Result<()> {
    let (cs, spin) = (ctx.a(0), ctx.au(1) as u64);
    let prev = ctx.rd(cs + 32, 8)?;
    ctx.wr(cs + 32, 8, spin)?;
    ctx.ret(prev);
    Ok(())
}

// ----- threads -----

fn create_thread(ctx: &mut ApiCtx) -> Result<()> {
    let (stack, start, param, flags, tid_p) = (ctx.a(1), ctx.a(2), ctx.a(3), ctx.au(4), ctx.a(5));
    let h = sched::spawn(ctx, start, param, stack, flags & 4 != 0)?;
    if h == 0 {
        ctx.set_last_error(8);
        ctx.ret(0);
        return Ok(());
    }
    if tid_p != 0 {
        let tid = ctx.p.sched.threads.last().map(|t| t.tid).unwrap_or(0);
        ctx.wr(tid_p, 4, tid as u64)?;
    }
    ctx.ret(h);
    Ok(())
}

fn exit_thread(ctx: &mut ApiCtx) -> Result<()> {
    let code = ctx.au(0) as u64;
    cont::exit_thread(ctx, code)
}

fn get_current_thread(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(PSEUDO_THREAD);
    Ok(())
}

fn get_current_thread_id(ctx: &mut ApiCtx) -> Result<()> {
    let t = ctx.p.sched.cur_tid();
    ctx.ret(t as u64);
    Ok(())
}

/// Thread id behind a thread handle (or the current thread for the pseudo handle).
fn tid_of(ctx: &ApiCtx, h: u64) -> Option<u32> {
    if h == PSEUDO_THREAD {
        return Some(ctx.p.sched.cur_tid());
    }
    match ctx.p.handles.get(h).map(|o| match &*o.borrow() {
        Obj::Thread(t) => Some(*t),
        _ => None,
    }) {
        Some(Some(t)) => Some(t),
        _ => None,
    }
}

fn get_thread_id(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let t = tid_of(ctx, h).unwrap_or(0);
    ctx.ret(t as u64);
    Ok(())
}

fn suspend_thread(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let Some(tid) = tid_of(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(u64::MAX);
        return Ok(());
    };
    let Some(i) = ctx.p.sched.index_of(tid) else {
        ctx.ret(u64::MAX);
        return Ok(());
    };
    let t = &mut ctx.p.sched.threads[i];
    if t.state == TState::Finished {
        ctx.ret(u64::MAX);
        return Ok(());
    }
    let prev = t.suspend_count;
    t.suspend_count += 1;
    if i == ctx.p.sched.cur {
        t.state = TState::Suspended;
        ctx.yield_now();
    } else {
        t.state = TState::Suspended;
    }
    ctx.ret(prev as u64);
    Ok(())
}

fn resume_thread(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let Some(tid) = tid_of(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(u64::MAX);
        return Ok(());
    };
    let Some(i) = ctx.p.sched.index_of(tid) else {
        ctx.ret(u64::MAX);
        return Ok(());
    };
    let t = &mut ctx.p.sched.threads[i];
    let prev = t.suspend_count;
    if t.suspend_count > 0 {
        t.suspend_count -= 1;
        if t.suspend_count == 0 && t.state == TState::Suspended {
            t.state = TState::Runnable;
        }
    }
    sched::notify(ctx);
    ctx.ret(prev as u64);
    Ok(())
}

/// Abandon the mutexes a finished thread still owns (WAIT_ABANDONED for the
/// next waiter).
pub(crate) fn abandon_mutexes(ctx: &mut ApiCtx, tid: u32) {
    let owned: Vec<ObjRef> = ctx
        .p
        .handles
        .iter()
        .map(|(_, o)| o.clone())
        .filter(|o| matches!(&*o.borrow(), Obj::Mutex(m) if m.owner == tid))
        .collect();
    for o in owned {
        if let Obj::Mutex(m) = &mut *o.borrow_mut() {
            m.owner = 0;
            m.count = 0;
            m.abandoned = true;
        }
    }
}

fn terminate_thread(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let code = ctx.au(1) as u64;
    let Some(tid) = tid_of(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    if tid == ctx.p.sched.cur_tid() {
        abandon_mutexes(ctx, tid);
        cont::finish_thread(ctx, code);
        return Ok(());
    }
    let Some(i) = ctx.p.sched.index_of(tid) else {
        ctx.ret_bool(false);
        return Ok(());
    };
    {
        let t = &mut ctx.p.sched.threads[i];
        if t.state != TState::Finished {
            t.state = TState::Finished;
            t.exit_code = Some(code & 0xFFFF_FFFF);
            t.frames.clear();
            t.cpu = None;
        }
    }
    abandon_mutexes(ctx, tid);
    sched::notify(ctx);
    ctx.ret_bool(true);
    Ok(())
}

fn get_exit_code_thread(ctx: &mut ApiCtx) -> Result<()> {
    let (h, out) = (ctx.a(0), ctx.a(1));
    let Some(tid) = tid_of(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let code = ctx
        .p
        .sched
        .index_of(tid)
        .and_then(|i| ctx.p.sched.threads[i].exit_code)
        .unwrap_or(STILL_ACTIVE as u64);
    ctx.wr(out, 4, code)?;
    ctx.ret_bool(true);
    Ok(())
}

fn set_thread_priority(ctx: &mut ApiCtx) -> Result<()> {
    let (h, p) = (ctx.a(0), ctx.ai(1));
    match tid_of(ctx, h).and_then(|t| ctx.p.sched.index_of(t)) {
        Some(i) => {
            ctx.p.sched.threads[i].priority = p;
            ctx.ret_bool(true);
        }
        None => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn get_thread_priority(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    match tid_of(ctx, h).and_then(|t| ctx.p.sched.index_of(t)) {
        Some(i) => ctx.ret_i32(ctx.p.sched.threads[i].priority),
        None => ctx.ret_i32(i32::MAX),
    }
    Ok(())
}

// ----- TLS -----

fn tls_alloc(ctx: &mut ApiCtx) -> Result<()> {
    match ctx.p.k32.tls_used.iter().position(|u| !*u) {
        Some(i) => {
            ctx.p.k32.tls_used[i] = true;
            ctx.ret(i as u64);
        }
        None => ctx.ret(u32::MAX as u64),
    }
    Ok(())
}

fn tls_free(ctx: &mut ApiCtx) -> Result<()> {
    let i = ctx.au(0) as usize;
    if i >= TLS_SLOTS || !ctx.p.k32.tls_used[i] {
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.k32.tls_used[i] = false;
    for t in ctx.p.sched.threads.iter_mut() {
        if i < t.tls.len() {
            t.tls[i] = 0;
        }
    }
    ctx.ret_bool(true);
    Ok(())
}

fn tls_get_value(ctx: &mut ApiCtx) -> Result<()> {
    let i = ctx.au(0) as usize;
    if i >= TLS_SLOTS || !ctx.p.k32.tls_used[i] {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let cur = ctx.p.sched.cur;
    let v = ctx.p.sched.threads[cur].tls.get(i).copied().unwrap_or(0);
    ctx.set_last_error(0);
    ctx.ret(v);
    Ok(())
}

fn tls_set_value(ctx: &mut ApiCtx) -> Result<()> {
    let (i, v) = (ctx.au(0) as usize, ctx.a(1));
    if i >= TLS_SLOTS || !ctx.p.k32.tls_used[i] {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    let cur = ctx.p.sched.cur;
    let slots = &mut ctx.p.sched.threads[cur].tls;
    if slots.len() < TLS_SLOTS {
        slots.resize(TLS_SLOTS, 0);
    }
    slots[i] = v;
    ctx.ret_bool(true);
    Ok(())
}

// ----- FLS -----

fn fls_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let cb = ctx.a(0);
    let used = &mut ctx.p.k32.fls_used;
    let idx = match used.iter().position(|u| !*u) {
        Some(i) => i,
        None if used.len() < FLS_SLOTS => {
            used.push(false);
            used.len() - 1
        }
        None => {
            ctx.ret(u32::MAX as u64);
            return Ok(());
        }
    };
    ctx.p.k32.fls_used[idx] = true;
    if ctx.p.k32.fls_callbacks.len() <= idx {
        ctx.p.k32.fls_callbacks.resize(idx + 1, 0);
    }
    ctx.p.k32.fls_callbacks[idx] = cb;
    ctx.ret(idx as u64);
    Ok(())
}

fn fls_free(ctx: &mut ApiCtx) -> Result<()> {
    let i = ctx.au(0) as usize;
    if i >= ctx.p.k32.fls_used.len() || !ctx.p.k32.fls_used[i] {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.k32.fls_used[i] = false;
    if let Some(cb) = ctx.p.k32.fls_callbacks.get_mut(i) {
        *cb = 0;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn fls_get_value(ctx: &mut ApiCtx) -> Result<()> {
    let i = ctx.au(0) as usize;
    if i >= ctx.p.k32.fls_used.len() || !ctx.p.k32.fls_used[i] {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret(0);
        return Ok(());
    }
    let cur = ctx.p.sched.cur;
    let v = ctx.p.sched.threads[cur].fls.get(i).copied().unwrap_or(0);
    ctx.set_last_error(0);
    ctx.ret(v);
    Ok(())
}

fn fls_set_value(ctx: &mut ApiCtx) -> Result<()> {
    let (i, v) = (ctx.au(0) as usize, ctx.a(1));
    if i >= ctx.p.k32.fls_used.len() || !ctx.p.k32.fls_used[i] {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    let cur = ctx.p.sched.cur;
    let slots = &mut ctx.p.sched.threads[cur].fls;
    if slots.len() <= i {
        slots.resize(i + 1, 0);
    }
    slots[i] = v;
    ctx.ret_bool(true);
    Ok(())
}

/// Called when an InitOnceExecuteOnce callback returns.
pub(crate) fn init_once_done(ctx: &mut ApiCtx, once: u64, ok: bool) {
    if ok {
        ctx.p.k32.init_once.insert(once, InitState::Done);
    } else {
        ctx.p.k32.init_once.remove(&once);
    }
    sched::notify(ctx);
}

fn init_once_initialize(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    ctx.zero(p, 8)?;
    ctx.p.k32.init_once.remove(&p);
    Ok(())
}

fn init_once_begin(ctx: &mut ApiCtx) -> Result<()> {
    let retry = sched::take_wait(ctx);
    let (p, flags, pending) = (ctx.a(0), ctx.au(1), ctx.a(2));
    let me = ctx.p.sched.cur_tid();
    let state = ctx.p.k32.init_once.get(&p).copied();
    let check_only = flags & 1 != 0;
    match state {
        Some(InitState::Done) => {
            if pending != 0 {
                ctx.wr(pending, 4, 0)?;
            }
            ctx.ret_bool(true);
        }
        Some(InitState::Running(t)) if t != me => {
            let _ = retry;
            ctx.block_retry(None);
        }
        Some(InitState::Running(_)) => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret_bool(false);
        }
        None => {
            if check_only {
                if pending != 0 {
                    ctx.wr(pending, 4, 0)?;
                }
                ctx.ret_bool(false);
                return Ok(());
            }
            ctx.p.k32.init_once.insert(p, InitState::Running(me));
            if pending != 0 {
                ctx.wr(pending, 4, 1)?;
            }
            ctx.ret_bool(true);
        }
    }
    Ok(())
}

fn init_once_complete(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let flags = ctx.au(1);
    let me = ctx.p.sched.cur_tid();
    match ctx.p.k32.init_once.get(&p).copied() {
        Some(InitState::Running(t)) if t == me => {
            if flags & 4 != 0 {
                ctx.p.k32.init_once.remove(&p);
            } else {
                ctx.p.k32.init_once.insert(p, InitState::Done);
            }
            sched::notify(ctx);
            ctx.ret_bool(true);
        }
        _ => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn init_once_execute_once(ctx: &mut ApiCtx) -> Result<()> {
    let retry = sched::take_wait(ctx);
    let (p, f, param, out) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.a(3));
    let me = ctx.p.sched.cur_tid();
    let _ = retry;
    match ctx.p.k32.init_once.get(&p).copied() {
        Some(InitState::Done) => ctx.ret_bool(true),
        Some(InitState::Running(t)) if t != me => ctx.block_retry(None),
        Some(InitState::Running(_)) => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret_bool(false);
        }
        None => {
            ctx.p.k32.init_once.insert(p, InitState::Running(me));
            let lr = ctx.state.x[30];
            cont::call_guest(
                ctx,
                f,
                &[p, param, out],
                cont::Frame::InitOnce { lr, once: p },
            );
        }
    }
    Ok(())
}

// ----- SRW locks (state keyed by address: (writer tid, readers)) -----

fn srw_init(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    ctx.zero(p, 8)?;
    ctx.p.k32.srw.remove(&p);
    Ok(())
}

fn srw_try(ctx: &mut ApiCtx, p: u64, shared: bool) -> bool {
    let me = ctx.p.sched.cur_tid();
    let entry = ctx.p.k32.srw.entry(p).or_insert((0, 0));
    if shared {
        if entry.0 == 0 {
            entry.1 += 1;
            return true;
        }
    } else if entry.0 == 0 && entry.1 == 0 {
        entry.0 = me;
        return true;
    }
    false
}

fn srw_acquire(ctx: &mut ApiCtx, shared: bool) -> Result<()> {
    let _ = sched::take_wait(ctx);
    let p = ctx.a(0);
    if srw_try(ctx, p, shared) {
        return Ok(());
    }
    ctx.block_retry(None);
    Ok(())
}

fn srw_release(ctx: &mut ApiCtx, shared: bool) -> Result<()> {
    let p = ctx.a(0);
    let me = ctx.p.sched.cur_tid();
    if let Some(e) = ctx.p.k32.srw.get_mut(&p) {
        if shared {
            e.1 = e.1.saturating_sub(1);
        } else if e.0 == me {
            e.0 = 0;
        }
        if e.0 == 0 && e.1 == 0 {
            ctx.p.k32.srw.remove(&p);
        }
    }
    sched::notify(ctx);
    Ok(())
}

fn acquire_srw_exclusive(ctx: &mut ApiCtx) -> Result<()> {
    srw_acquire(ctx, false)
}
fn acquire_srw_shared(ctx: &mut ApiCtx) -> Result<()> {
    srw_acquire(ctx, true)
}
fn release_srw_exclusive(ctx: &mut ApiCtx) -> Result<()> {
    srw_release(ctx, false)
}
fn release_srw_shared(ctx: &mut ApiCtx) -> Result<()> {
    srw_release(ctx, true)
}
fn try_acquire_srw_exclusive(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let ok = srw_try(ctx, p, false);
    ctx.ret_bool(ok);
    Ok(())
}
fn try_acquire_srw_shared(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let ok = srw_try(ctx, p, true);
    ctx.ret_bool(ok);
    Ok(())
}

// ----- condition variables -----

/// The lock a condition-variable sleep releases and re-acquires.
#[derive(Clone, Copy)]
enum CvLock {
    Cs(u64),
    Srw(u64, bool),
}

/// Release `lock` completely; returns the recursion count to restore.
fn cv_release(ctx: &mut ApiCtx, lock: CvLock) -> Result<u64> {
    match lock {
        CvLock::Cs(cs) => {
            let rec = ctx.rd(cs + 12, 4)?;
            ctx.wr(cs + 12, 4, 0)?;
            ctx.wr(cs + 16, 8, 0)?;
            ctx.wr(cs + 8, 4, 0xFFFF_FFFF)?;
            Ok(rec)
        }
        CvLock::Srw(p, shared) => {
            let me = ctx.p.sched.cur_tid();
            if let Some(e) = ctx.p.k32.srw.get_mut(&p) {
                if shared {
                    e.1 = e.1.saturating_sub(1);
                } else if e.0 == me {
                    e.0 = 0;
                }
                if e.0 == 0 && e.1 == 0 {
                    ctx.p.k32.srw.remove(&p);
                }
            }
            Ok(0)
        }
    }
}

/// Try to re-acquire `lock`, restoring `rec` for critical sections.
fn cv_reacquire(ctx: &mut ApiCtx, lock: CvLock, rec: u64) -> Result<bool> {
    let me = ctx.p.sched.cur_tid();
    match lock {
        CvLock::Cs(cs) => {
            let owner = ctx.rd(cs + 16, 8)?;
            if owner == 0 {
                ctx.wr(cs + 16, 8, me as u64)?;
                ctx.wr(cs + 12, 4, rec.max(1))?;
                ctx.wr(cs + 8, 4, 0)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        CvLock::Srw(p, shared) => Ok(srw_try(ctx, p, shared)),
    }
}

/// Shared implementation of SleepConditionVariable{CS,SRW}.
/// wait_seen layout while parked: [phase, saved recursion, timed_out].
fn sleep_cv(ctx: &mut ApiCtx, cv: u64, lock: CvLock, ms: u32) -> Result<()> {
    let cur = ctx.p.sched.cur;
    let retry = sched::take_wait(ctx);
    let Some(deadline) = retry else {
        // first attempt: release the lock and start waiting
        let rec = cv_release(ctx, lock)?;
        sched::notify(ctx);
        ctx.p.k32.cv.entry(cv).or_default().waiters += 1;
        ctx.p.sched.threads[cur].wait_seen = vec![0, rec, 0];
        let deadline = sched::deadline_for(ms);
        ctx.block_retry(deadline);
        return Ok(());
    };
    let seen = ctx.p.sched.threads[cur].wait_seen.clone();
    let (phase, rec, timed_out) = (
        seen.first().copied().unwrap_or(0),
        seen.get(1).copied().unwrap_or(0),
        seen.get(2).copied().unwrap_or(0),
    );
    let st: &mut CvState = ctx.p.k32.cv.entry(cv).or_default();
    if phase == 0 {
        if st.tokens > 0 {
            st.tokens -= 1;
            st.waiters = st.waiters.saturating_sub(1);
            phase_reacquire(ctx, lock, rec, 0)?;
            return Ok(());
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            st.waiters = st.waiters.saturating_sub(1);
            phase_reacquire(ctx, lock, rec, 1)?;
            return Ok(());
        }
        ctx.p.sched.threads[cur].wait_seen = vec![0, rec, 0];
        ctx.block_retry(deadline);
        return Ok(());
    }
    // re-acquiring: phase 2 (signaled) or 3 (timed out)
    let _ = timed_out;
    if cv_reacquire(ctx, lock, rec)? {
        let ok = phase == 2;
        ctx.ret_bool(ok);
        if !ok {
            ctx.set_last_error(ERROR_TIMEOUT);
        }
        return Ok(());
    }
    ctx.p.sched.threads[cur].wait_seen = vec![phase, rec, 0];
    ctx.block_retry(None);
    Ok(())
}

/// Record the re-acquire phase (`timed` = 1 for a timeout, 0 for a wake).
fn phase_reacquire(ctx: &mut ApiCtx, lock: CvLock, rec: u64, timed: u64) -> Result<()> {
    let cur = ctx.p.sched.cur;
    let phase = if timed == 1 { 3 } else { 2 };
    if cv_reacquire(ctx, lock, rec)? {
        // finished immediately: report the outcome of this call
        ctx.ret_bool(phase == 2);
        if phase != 2 {
            ctx.set_last_error(ERROR_TIMEOUT);
        }
        return Ok(());
    }
    ctx.p.sched.threads[cur].wait_seen = vec![phase, rec, 0];
    ctx.block_retry(None);
    Ok(())
}

fn initialize_condition_variable(ctx: &mut ApiCtx) -> Result<()> {
    let cv = ctx.a(0);
    ctx.zero(cv, 8)?;
    ctx.p.k32.cv.remove(&cv);
    Ok(())
}

fn wake_condition_variable(ctx: &mut ApiCtx) -> Result<()> {
    let cv = ctx.a(0);
    let st = ctx.p.k32.cv.entry(cv).or_default();
    if st.waiters > st.tokens {
        st.tokens += 1;
    }
    sched::notify(ctx);
    Ok(())
}

fn wake_all_condition_variable(ctx: &mut ApiCtx) -> Result<()> {
    let cv = ctx.a(0);
    let st = ctx.p.k32.cv.entry(cv).or_default();
    st.tokens = st.waiters;
    sched::notify(ctx);
    Ok(())
}

fn sleep_condition_variable_cs(ctx: &mut ApiCtx) -> Result<()> {
    let (cv, cs, ms) = (ctx.a(0), ctx.a(1), ctx.au(2));
    sleep_cv(ctx, cv, CvLock::Cs(cs), ms)
}

fn sleep_condition_variable_srw(ctx: &mut ApiCtx) -> Result<()> {
    let (cv, srw, ms, flags) = (ctx.a(0), ctx.a(1), ctx.au(2), ctx.au(3));
    let shared = flags & 1 != 0;
    sleep_cv(ctx, cv, CvLock::Srw(srw, shared), ms)
}

// ----- address waits -----

fn wait_on_address(ctx: &mut ApiCtx) -> Result<()> {
    let retry = sched::take_wait(ctx);
    let (addr, cmp, size, ms) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.au(3));
    let deadline = match retry {
        Some(d) => d,
        None => sched::deadline_for(ms),
    };
    let n = size as u8;
    if !matches!(n, 1 | 2 | 4 | 8) {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    let now = ctx.rd(addr, n)?;
    let expected = ctx.rd(cmp, n)?;
    if now != expected {
        ctx.ret_bool(true);
        return Ok(());
    }
    if ms == 0 || deadline.is_some_and(|d| Instant::now() >= d) {
        ctx.set_last_error(ERROR_TIMEOUT);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.block_retry(deadline);
    Ok(())
}

fn wake_by_address(ctx: &mut ApiCtx) -> Result<()> {
    sched::notify(ctx);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "kernel32",
        "WaitForSingleObject" => wait_for_single_object,
        "WaitForSingleObjectEx" => wait_for_single_object_ex,
        "WaitForMultipleObjects" => wait_for_multiple_objects,
        "WaitForMultipleObjectsEx" => wait_for_multiple_objects_ex,
        "SignalObjectAndWait" => signal_object_and_wait,
        "Sleep" => sleep,
        "SleepEx" => sleep_ex,
        "SwitchToThread" => switch_to_thread,
        "CreateEventA" => create_event_a,
        "CreateEventW" => create_event_w,
        "OpenEventA" => open_event_a,
        "OpenEventW" => open_event_w,
        "SetEvent" => set_event,
        "ResetEvent" => reset_event,
        "PulseEvent" => pulse_event,
        "CreateMutexA" => create_mutex_a,
        "CreateMutexW" => create_mutex_w,
        "OpenMutexA" => open_mutex_a,
        "OpenMutexW" => open_mutex_w,
        "ReleaseMutex" => release_mutex,
        "CreateSemaphoreA" => create_semaphore_a,
        "CreateSemaphoreW" => create_semaphore_w,
        "OpenSemaphoreA" => open_semaphore_a,
        "OpenSemaphoreW" => open_semaphore_w,
        "ReleaseSemaphore" => release_semaphore,
        "InitializeCriticalSection" => initialize_critical_section,
        "InitializeCriticalSectionAndSpinCount" => initialize_critical_section_and_spin_count,
        "EnterCriticalSection" => enter_critical_section,
        "TryEnterCriticalSection" => try_enter_critical_section,
        "LeaveCriticalSection" => leave_critical_section,
        "DeleteCriticalSection" => delete_critical_section,
        "SetCriticalSectionSpinCount" => set_critical_section_spin_count,
        "CreateThread" => create_thread,
        "ExitThread" => exit_thread,
        "GetCurrentThread" => get_current_thread,
        "GetCurrentThreadId" => get_current_thread_id,
        "GetThreadId" => get_thread_id,
        "SuspendThread" => suspend_thread,
        "ResumeThread" => resume_thread,
        "TerminateThread" => terminate_thread,
        "GetExitCodeThread" => get_exit_code_thread,
        "SetThreadPriority" => set_thread_priority,
        "GetThreadPriority" => get_thread_priority,
        "TlsAlloc" => tls_alloc,
        "TlsFree" => tls_free,
        "TlsGetValue" => tls_get_value,
        "TlsSetValue" => tls_set_value,
        "FlsAlloc" => fls_alloc,
        "FlsFree" => fls_free,
        "FlsGetValue" => fls_get_value,
        "FlsSetValue" => fls_set_value,
        "InitOnceInitialize" => init_once_initialize,
        "InitOnceBeginInitialize" => init_once_begin,
        "InitOnceComplete" => init_once_complete,
        "InitOnceExecuteOnce" => init_once_execute_once,
        "InitializeSRWLock" => srw_init,
        "AcquireSRWLockExclusive" => acquire_srw_exclusive,
        "AcquireSRWLockShared" => acquire_srw_shared,
        "ReleaseSRWLockExclusive" => release_srw_exclusive,
        "ReleaseSRWLockShared" => release_srw_shared,
        "TryAcquireSRWLockExclusive" => try_acquire_srw_exclusive,
        "TryAcquireSRWLockShared" => try_acquire_srw_shared,
        "InitializeConditionVariable" => initialize_condition_variable,
        "WakeConditionVariable" => wake_condition_variable,
        "WakeAllConditionVariable" => wake_all_condition_variable,
        "SleepConditionVariableCS" => sleep_condition_variable_cs,
        "SleepConditionVariableSRW" => sleep_condition_variable_srw,
        "WaitOnAddress" => wait_on_address,
        "WakeByAddressSingle" => wake_by_address,
        "WakeByAddressAll" => wake_by_address,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_results_are_win32_values() {
        assert_eq!(WAIT_OBJECT_0, 0);
        assert_eq!(WAIT_TIMEOUT, 258);
        assert_eq!(WAIT_ABANDONED_0, 128);
    }
}
