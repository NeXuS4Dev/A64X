//! Green threads: a round-robin scheduler over saved CPU states.
//!
//! Every Win32 thread is a [`Thread`] with its own CPU state, continuation
//! frames, TLS/FLS slots and errno cell. Only one thread runs at a time;
//! switching swaps the CPU state the translator is running on. Switch points
//! are: blocking waits and sleeps, thread exit, and the end of every
//! translator round (preemption), so spin loops on shared memory make
//! progress as they do on Windows.
//!
//! Blocking is "retry": an adapter that cannot complete calls
//! [`ApiCtx::block_retry`](crate::ApiCtx::block_retry) without changing any
//! state. The thread is parked with the generation counter observed at that
//! moment and re-enters the same adapter once any synchronization object has
//! changed (or its deadline passed). When nothing can run and no deadline is
//! pending, the process has deadlocked and is terminated with a diagnostic.

use crate::cont::Frame;
use crate::handles::{Handles, Obj};
use crate::{gateway, ApiCtx, CONTINUATION_ID};
use a64x_core::state::CpuState;
use std::time::{Duration, Instant};

/// Thread id of the main thread.
pub(crate) const MAIN_TID: u32 = 0x100;

/// Scheduling state of one thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TState {
    /// Can run now.
    Runnable,
    /// Parked in a blocking adapter; runnable again when `gen` moves on or
    /// the deadline passes.
    Blocked { deadline: Option<Instant>, gen: u64 },
    /// Suspended by SuspendThread (or created with CREATE_SUSPENDED).
    Suspended,
    /// Terminated.
    Finished,
}

/// One Win32 thread.
pub(crate) struct Thread {
    /// Thread id (GetCurrentThreadId).
    pub tid: u32,
    /// Saved CPU state; `None` while this is the running thread.
    pub cpu: Option<Box<CpuState>>,
    /// Scheduling state.
    pub state: TState,
    /// Suspend count (ResumeThread decrements).
    pub suspend_count: u32,
    /// Exit code once finished.
    pub exit_code: Option<u64>,
    /// Continuation frames (callbacks in flight), innermost last.
    pub frames: Vec<Frame>,
    /// TLS slots (TlsAlloc/TlsGetValue/TlsSetValue).
    pub tls: Vec<u64>,
    /// FLS values by index.
    pub fls: Vec<u64>,
    /// Guest cell holding this thread's errno.
    pub errno_addr: u64,
    /// Set while the thread is parked inside a blocking adapter: the
    /// deadline of that call (inner `None` = wait forever).
    pub wait: Option<Option<Instant>>,
    /// SetThreadPriority value.
    pub priority: i32,
    /// Stack allocation in the VM arena: `(base, size)`; `(0, 0)` for the
    /// main thread, whose stack is the process stack.
    pub stack: (u64, u64),
    /// Values observed when a multi-part wait started (event pulse
    /// generations, condition sequence numbers, ...). Empty when not waiting.
    pub wait_seen: Vec<u64>,
    /// Frame-stack length at the start of the outermost structured exception
    /// operation in progress (see k32_seh).
    pub seh_base: Option<usize>,
    /// Nesting depth of structured exception operations in progress.
    pub seh_depth: u32,
    /// Scratch area (EXCEPTION_RECORD/CONTEXT/DISPATCHER_CONTEXT slots).
    pub seh_scratch: u64,
}

impl Thread {
    /// A thread with no pending work, in state `state`.
    pub(crate) fn new(tid: u32, state: TState, errno_addr: u64) -> Thread {
        Thread {
            tid,
            cpu: None,
            state,
            suspend_count: 0,
            exit_code: None,
            frames: Vec::new(),
            tls: Vec::new(),
            fls: Vec::new(),
            errno_addr,
            wait: None,
            priority: 0,
            stack: (0, 0),
            wait_seen: Vec::new(),
            seh_base: None,
            seh_depth: 0,
            seh_scratch: 0,
        }
    }
}

/// All threads plus scheduler bookkeeping.
pub(crate) struct Sched {
    /// Threads in creation order.
    pub threads: Vec<Thread>,
    /// Index of the running thread.
    pub cur: usize,
    /// Bumped whenever a synchronization object changes state.
    pub gen: u64,
    /// Exit code of the most recently finished thread.
    pub last_exit: u64,
    next_tid: u32,
}

impl Sched {
    /// The process starts with its main thread running.
    pub(crate) fn new(errno_addr: u64, handles: &mut Handles) -> Sched {
        handles.insert(Obj::Thread(MAIN_TID));
        let main = Thread::new(MAIN_TID, TState::Runnable, errno_addr);
        Sched {
            threads: vec![main],
            cur: 0,
            gen: 1,
            last_exit: 0,
            next_tid: MAIN_TID + 4,
        }
    }

    /// Guest address of the running thread's errno cell.
    pub(crate) fn cur_errno_addr(&self) -> u64 {
        self.threads[self.cur].errno_addr
    }

    /// Index of the thread with id `tid`.
    pub(crate) fn index_of(&self, tid: u32) -> Option<usize> {
        self.threads.iter().position(|t| t.tid == tid)
    }

    /// Threads that have not terminated.
    pub(crate) fn live(&self) -> usize {
        self.threads
            .iter()
            .filter(|t| t.state != TState::Finished)
            .count()
    }

    /// Thread id of the running thread.
    pub(crate) fn cur_tid(&self) -> u32 {
        self.threads[self.cur].tid
    }
}

fn runnable(t: &Thread, now: Instant, gen: u64) -> bool {
    match t.state {
        TState::Runnable => true,
        TState::Blocked { deadline, gen: g } => g != gen || deadline.is_some_and(|d| now >= d),
        TState::Suspended | TState::Finished => false,
    }
}

/// Make thread `i` the running thread, saving the current one.
fn switch_to(ctx: &mut ApiCtx, i: usize) {
    let cur = ctx.p.sched.cur;
    if i == cur {
        return;
    }
    let mut incoming = match ctx.p.sched.threads[i].cpu.take() {
        Some(c) => c,
        None => {
            ctx.fatal("internal error: switching to a thread without saved state".into());
            return;
        }
    };
    incoming.insn_count = ctx.state.insn_count;
    incoming.block_count = ctx.state.block_count;
    incoming.running = 1;
    std::mem::swap(ctx.state, &mut *incoming);
    ctx.p.sched.threads[cur].cpu = Some(incoming);
    ctx.p.sched.threads[i].state = TState::Runnable;
    ctx.p.sched.cur = i;
}

/// Pick the next thread to run after the current one blocked, yielded or
/// exited; sleeps for timers when nothing else can run; ends the process
/// when every thread has finished and terminates it on deadlock.
pub(crate) fn reschedule(ctx: &mut ApiCtx) {
    loop {
        let now = Instant::now();
        let n = ctx.p.sched.threads.len();
        let cur = ctx.p.sched.cur;
        let gen = ctx.p.sched.gen;
        for k in 1..=n {
            let i = (cur + k) % n;
            if runnable(&ctx.p.sched.threads[i], now, gen) {
                switch_to(ctx, i);
                return;
            }
        }
        let earliest = ctx
            .p
            .sched
            .threads
            .iter()
            .filter_map(|t| match t.state {
                TState::Blocked {
                    deadline: Some(d), ..
                } => Some(d),
                _ => None,
            })
            .min();
        match earliest {
            Some(d) => {
                let now = Instant::now();
                if d > now {
                    std::thread::sleep(d - now);
                }
            }
            None => break,
        }
    }
    if ctx.p.sched.live() == 0 {
        ctx.state.exit_code = ctx.p.sched.last_exit;
        ctx.state.exit_reason = a64x_core::ExitReason::Exited as u8;
        ctx.state.running = 0;
    } else {
        let stuck: Vec<String> = ctx
            .p
            .sched
            .threads
            .iter()
            .filter(|t| t.state != TState::Finished)
            .map(|t| format!("thread {:#x}", t.tid))
            .collect();
        ctx.fatal(format!(
            "deadlock: no thread can run ({})",
            stuck.join(", ")
        ));
    }
}

/// Preemptive round robin: give another runnable thread the CPU.
pub(crate) fn preempt(ctx: &mut ApiCtx) {
    let n = ctx.p.sched.threads.len();
    if n <= 1 {
        return;
    }
    let now = Instant::now();
    let cur = ctx.p.sched.cur;
    let gen = ctx.p.sched.gen;
    for k in 1..n {
        let i = (cur + k) % n;
        if runnable(&ctx.p.sched.threads[i], now, gen) {
            switch_to(ctx, i);
            return;
        }
    }
}

/// Park the running thread until a synchronization object changes or
/// `deadline` passes. Used via [`ApiCtx::block_retry`].
pub(crate) fn block_current(ctx: &mut ApiCtx, deadline: Option<Instant>) {
    let gen = ctx.p.sched.gen;
    let cur = ctx.p.sched.cur;
    let t = &mut ctx.p.sched.threads[cur];
    t.state = TState::Blocked { deadline, gen };
    t.wait = Some(deadline);
}

/// For a call being re-entered after blocking: its deadline (inner `None`
/// means wait forever). `None` for a fresh call. Clears the marker.
pub(crate) fn take_wait(ctx: &mut ApiCtx) -> Option<Option<Instant>> {
    let cur = ctx.p.sched.cur;
    ctx.p.sched.threads[cur].wait.take()
}

/// Deadline for a Win32 millisecond timeout (`INFINITE` = no deadline).
pub(crate) fn deadline_for(ms: u32) -> Option<Instant> {
    if ms == u32::MAX {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(ms as u64))
    }
}

/// Record that a synchronization object changed (wakes blocked waiters).
pub(crate) fn notify(ctx: &mut ApiCtx) {
    ctx.p.sched.gen = ctx.p.sched.gen.wrapping_add(1);
}

/// Create a thread that starts at `start` with argument `param`. Returns the
/// thread handle, or 0 when no stack memory is available.
pub(crate) fn spawn(
    ctx: &mut ApiCtx,
    start: u64,
    param: u64,
    stack_size: u64,
    suspended: bool,
) -> a64x_core::Result<u64> {
    let size = stack_size.max(0x1_0000).div_ceil(0x1_0000) * 0x1_0000;
    let Some(base) = ctx.p.vm.find_free(size, crate::vm::GRANULARITY) else {
        return Ok(0);
    };
    ctx.p.vm.reserve(
        base,
        size,
        crate::vm::PAGE_READWRITE,
        crate::vm::MEM_PRIVATE,
    );
    ctx.p.vm.commit(base, size, crate::vm::PAGE_READWRITE);
    ctx.zero(base, size)?;
    let errno_addr = ctx.p.statics.alloc(16, 16)?;
    let tid = ctx.p.sched.next_tid;
    ctx.p.sched.next_tid += 4;

    let mut cpu = Box::<CpuState>::default();
    cpu.mem_base = ctx.state.mem_base;
    cpu.mem_size = ctx.state.mem_size;
    cpu.running = 1;
    cpu.pc = start;
    cpu.x[0] = param;
    cpu.x[30] = gateway::addr_of(CONTINUATION_ID);
    cpu.sp = base + size - 16;
    let handle = ctx.p.handles.insert(Obj::Thread(tid));
    let state = if suspended {
        TState::Suspended
    } else {
        TState::Runnable
    };
    let mut t = Thread::new(tid, state, errno_addr);
    t.cpu = Some(cpu);
    t.suspend_count = suspended as u32;
    t.frames = vec![Frame::ThreadReturn];
    t.stack = (base, size);
    ctx.p.sched.threads.push(t);
    notify(ctx);
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_thread_is_running_and_has_a_handle() {
        let mut h = Handles::new();
        let s = Sched::new(0x8000, &mut h);
        assert_eq!(s.cur_tid(), MAIN_TID);
        let is_main = h
            .iter()
            .any(|(_, o)| matches!(*o.borrow(), Obj::Thread(MAIN_TID)));
        assert!(is_main);
        assert_eq!(s.live(), 1);
    }

    #[test]
    fn blocked_thread_wakes_on_generation_change() {
        let now = Instant::now();
        let t = Thread::new(
            4,
            TState::Blocked {
                deadline: None,
                gen: 5,
            },
            0,
        );
        assert!(!runnable(&t, now, 5));
        assert!(runnable(&t, now, 6));
    }
}
