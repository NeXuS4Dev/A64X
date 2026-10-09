//! Continuations: adapters that call back into guest code.
//!
//! Some Windows calls run guest functions before they return: `_initterm`
//! runs initializer tables, `exit` runs `atexit` handlers, `abort` runs the
//! SIGABRT handler, `InitOnceExecuteOnce` runs its callback, SEH runs filter
//! and finally blocks, and thread exit runs FLS destructors. The adapter does
//! not run the guest function itself. It pushes a [`Frame`] describing what
//! to do with the result, points the guest at the function with the return
//! address set to the internal `__continue` gateway, and returns. When the
//! function returns, the dispatcher enters `__continue`, which pops the frame
//! and continues the original Windows call.
//!
//! Frames are per thread, so a callback can block and other threads can run
//! in the meantime. Everything a frame needs (the caller's return address,
//! the table cursor, the pending result) is stored in the frame itself.

use crate::k32_seh::SehStep;
use crate::{gateway, ApiCtx, CONTINUATION_ID};
use a64x_core::{ExitReason, Result};

/// What to do after an `atexit` run completes.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AtexitEnd {
    /// `exit`: terminate the process with this code.
    Terminate(u64),
    /// `_cexit`: return `value` to the caller at `lr`.
    Return { lr: u64, value: u64 },
}

/// A pending continuation.
#[derive(Clone, Debug)]
pub(crate) enum Frame {
    /// The thread's start routine returns: the thread exits with x0.
    ThreadReturn,
    /// ExitThread/_endthreadex: FLS destructors for slots `next..` run
    /// first, then the thread ends with `code`.
    FlsCleanup { code: u64, next: usize },
    /// `atexit` handlers: `remaining` handlers (LIFO) are still to run.
    Atexit { remaining: usize, end: AtexitEnd },
    /// `_initterm`/`_initterm_e`: walk the table from `cur` up to `end`.
    /// With `checked`, a non-zero handler result stops the walk and is
    /// returned.
    InitTerm {
        lr: u64,
        cur: u64,
        end: u64,
        checked: bool,
    },
    /// SIGABRT handler returned: `abort` exits with code 3.
    Abort,
    /// InitOnceExecuteOnce callback returned for the InitOnce at `once`.
    InitOnce { lr: u64, once: u64 },
    /// An SEH filter, finally block or unhandled-exception filter returned.
    Seh(SehStep),
    /// A matherr handler returned: its `struct _exception` is at `ex`.
    MathErr { lr: u64, ex: u64, prev_errno: i32 },
    /// Return the callee's result unchanged to `lr`.
    Passthrough { lr: u64 },
}

/// Push a continuation frame onto the running thread.
pub(crate) fn push(ctx: &mut ApiCtx, f: Frame) {
    let cur = ctx.p.sched.cur;
    ctx.p.sched.threads[cur].frames.push(f);
}

/// Run guest function `func` with `args` (x0..), then resume with `frame`.
/// The adapter must return immediately after calling this.
pub(crate) fn call_guest(ctx: &mut ApiCtx, func: u64, args: &[u64], frame: Frame) {
    push(ctx, frame);
    for (i, a) in args.iter().take(8).enumerate() {
        ctx.state.x[i] = *a;
    }
    ctx.state.x[30] = gateway::addr_of(CONTINUATION_ID);
    ctx.state.pc = func;
    ctx.pc_set = true;
}

/// Complete the pending Windows call: `value` becomes the result and the
/// function returns to `lr`.
pub(crate) fn finish_value(ctx: &mut ApiCtx, lr: u64, value: u64) {
    ctx.state.x[0] = value;
    ctx.state.x[30] = lr;
}

/// End the process with `code` (no atexit processing, no CRT cleanup).
pub(crate) fn finish_process(ctx: &mut ApiCtx, code: u64) {
    ctx.state.exit_code = code & 0xFFFF_FFFF;
    ctx.state.exit_reason = ExitReason::Exited as u8;
    ctx.state.running = 0;
    ctx.pc_set = true;
    ctx.resched = false;
}

/// Run the `atexit` table (LIFO), flush the CRT streams, then finish with
/// `end`. Callbacks run one after another through continuation frames.
pub(crate) fn run_atexit(ctx: &mut ApiCtx, remaining: usize, end: AtexitEnd) -> Result<()> {
    if remaining == 0 {
        crate::stdio::flush_all(ctx)?;
        match end {
            AtexitEnd::Terminate(code) => finish_process(ctx, code),
            AtexitEnd::Return { lr, value } => finish_value(ctx, lr, value),
        }
        return Ok(());
    }
    let f = ctx.p.crt.atexit[remaining - 1];
    call_guest(
        ctx,
        f,
        &[],
        Frame::Atexit {
            remaining: remaining - 1,
            end,
        },
    );
    Ok(())
}

/// Walk an initializer table; `lr` is the caller's return address.
pub(crate) fn init_term_step(
    ctx: &mut ApiCtx,
    lr: u64,
    mut cur: u64,
    end: u64,
    checked: bool,
) -> Result<()> {
    while cur < end {
        let f = ctx.rd_ptr(cur)?;
        cur += 8;
        if f != 0 {
            call_guest(
                ctx,
                f,
                &[],
                Frame::InitTerm {
                    lr,
                    cur,
                    end,
                    checked,
                },
            );
            return Ok(());
        }
    }
    finish_value(ctx, lr, 0);
    Ok(())
}

/// Thread exit: run FLS destructors (from slot `next`), then end the thread.
pub(crate) fn fls_cleanup_step(ctx: &mut ApiCtx, code: u64, mut next: usize) -> Result<()> {
    let cur = ctx.p.sched.cur;
    while next < ctx.p.k32.fls_callbacks.len() {
        let idx = next;
        next += 1;
        let cb = ctx.p.k32.fls_callbacks[idx];
        let value = ctx.p.sched.threads[cur].fls.get(idx).copied().unwrap_or(0);
        if cb != 0 && value != 0 {
            if let Some(slot) = ctx.p.sched.threads[cur].fls.get_mut(idx) {
                *slot = 0;
            }
            call_guest(ctx, cb, &[value], Frame::FlsCleanup { code, next });
            return Ok(());
        }
    }
    finish_thread(ctx, code);
    Ok(())
}

/// Mark the running thread finished with `code` and hand the CPU to another
/// thread (or end the process when this was the last one).
pub(crate) fn finish_thread(ctx: &mut ApiCtx, code: u64) {
    let cur = ctx.p.sched.cur;
    let tid = ctx.p.sched.threads[cur].tid;
    crate::k32_sync::abandon_mutexes(ctx, tid);
    let t = &mut ctx.p.sched.threads[cur];
    t.state = crate::sched::TState::Finished;
    t.exit_code = Some(code & 0xFFFF_FFFF);
    t.frames.clear();
    ctx.p.sched.last_exit = code & 0xFFFF_FFFF;
    crate::sched::notify(ctx);
    ctx.resched = true;
}

/// ExitThread / _endthreadex on the running thread.
pub(crate) fn exit_thread(ctx: &mut ApiCtx, code: u64) -> Result<()> {
    let cur = ctx.p.sched.cur;
    ctx.p.sched.threads[cur].frames.clear();
    fls_cleanup_step(ctx, code, 0)
}

/// Pop the innermost frame of the running thread.
fn pop(ctx: &mut ApiCtx) -> Option<Frame> {
    let cur = ctx.p.sched.cur;
    ctx.p.sched.threads[cur].frames.pop()
}

/// Entry point of the internal `__continue` gateway: a guest callback has
/// returned (x0 holds its result) and the pending frame decides what
/// happens next.
pub(crate) fn resume_adapter(ctx: &mut ApiCtx) -> Result<()> {
    let value = ctx.a(0);
    let Some(frame) = pop(ctx) else {
        ctx.fatal(format!(
            "internal error: continuation without a frame at {:#x}",
            ctx.state.pc
        ));
        return Ok(());
    };
    match frame {
        Frame::ThreadReturn => exit_thread(ctx, value),
        Frame::FlsCleanup { code, next } => fls_cleanup_step(ctx, code, next),
        Frame::Atexit { remaining, end } => run_atexit(ctx, remaining, end),
        Frame::InitTerm {
            lr,
            cur,
            end,
            checked,
        } => {
            if checked && value != 0 {
                finish_value(ctx, lr, value);
                Ok(())
            } else {
                init_term_step(ctx, lr, cur, end, checked)
            }
        }
        Frame::Abort => {
            finish_process(ctx, 3);
            Ok(())
        }
        Frame::InitOnce { lr, once } => {
            crate::k32_sync::init_once_done(ctx, once, value != 0);
            let ok = (value != 0) as u64;
            finish_value(ctx, lr, ok);
            Ok(())
        }
        Frame::Seh(step) => crate::k32_seh::resume(ctx, step, value),
        Frame::MathErr { lr, ex, prev_errno } => {
            let bits = ctx.rd(ex + 32, 8)?;
            if value != 0 {
                ctx.set_errno(prev_errno);
            }
            finish_f64(ctx, lr, bits);
            Ok(())
        }
        Frame::Passthrough { lr } => {
            finish_value(ctx, lr, value);
            Ok(())
        }
    }
}

/// Complete the pending call with a double result (d0) returning to `lr`.
pub(crate) fn finish_f64(ctx: &mut ApiCtx, lr: u64, bits: u64) {
    ctx.state.v[0] = [bits, 0];
    ctx.state.x[30] = lr;
}
