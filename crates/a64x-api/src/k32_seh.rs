//! Structured exception handling: RaiseException, RtlUnwindEx, the context
//! and unwind primitives, SetUnhandledExceptionFilter, and the vcruntime
//! `__C_specific_handler` language handler.
//!
//! The dispatch is a two-phase walk over the frames, using the unwinder in
//! [`crate::unwind`]:
//!
//! * search phase: each frame with a language handler is offered the
//!   exception (`EXCEPTION_UNWINDING` clear); a handler answers
//!   ContinueExecution (the CONTEXT is restored), ContinueSearch (walk on) or
//!   unwinds by calling RtlUnwindEx itself;
//! * unwind phase: frames between the raise point and the target are
//!   unwound, offering each handler the unwinding notification (which runs
//!   `__finally` blocks), until the target frame is reached and execution
//!   resumes at the target IP with the given return value.
//!
//! Every guest callback (handlers, filters, finally blocks) runs through a
//! continuation frame ([`crate::cont`]), so the walk is resumable. All
//! structures the guest can observe (EXCEPTION_RECORD, CONTEXT,
//! DISPATCHER_CONTEXT, EXCEPTION_POINTERS) live in a per-thread scratch area
//! in the VM arena, one slot per nesting level.

use crate::cont::{self, Frame};
use crate::unwind::{self, NvPtrs, Regs, CONTEXT_FULL, CONTEXT_SIZE, CONTEXT_UNWOUND_TO_CALL};
use crate::vm::{GRANULARITY, MEM_PRIVATE, PAGE_READWRITE};
use crate::{gateway, reg, ApiCtx, ApiDef, CONTINUATION_ID};
use a64x_core::Result;

/// EXCEPTION_NONCONTINUABLE / EXCEPTION_UNWINDING / EXCEPTION_EXIT_UNWIND.
const EXCEPTION_UNWINDING: u32 = 0x2;
const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
/// EXCEPTION_EXECUTE_HANDLER and EXCEPTION_CONTINUE_SEARCH scope values.
const EXECUTE_HANDLER: u64 = 1;
/// EXCEPTION_CONTINUE_EXECUTION and EXCEPTION_CONTINUE_SEARCH dispositions.
const DISPOSITION_CONTINUE_EXECUTION: u64 = 0;
const DISPOSITION_CONTINUE_SEARCH: u64 = 1;
/// STATUS_UNWIND (used for RtlUnwindEx without a record).
const STATUS_UNWIND: u32 = 0xC000_0027;
/// Scratch slot layout (offsets within a slot).
const SLOT_SIZE: u64 = 0x1000;
const SLOT_REC: u64 = 0x000;
const SLOT_CTX: u64 = 0x100;
const SLOT_CTX2: u64 = 0x500;
const SLOT_DISP: u64 = 0x900;
const SLOT_EP: u64 = 0x980;
const MAX_NESTING: u32 = 16;
/// Frames examined in one walk before giving up.
const MAX_FRAMES: u32 = 4096;
/// EXCEPTION_RECORD and DISPATCHER_CONTEXT field offsets.
const REC_CODE: u64 = 0;
const REC_FLAGS: u64 = 4;
const REC_NPARAMS: u64 = 24;
const REC_INFO: u64 = 32;
const DISP_CONTROL_PC: u64 = 0;
const DISP_IMAGE: u64 = 8;
const DISP_ENTRY: u64 = 16;
const DISP_ESTABLISHER: u64 = 24;
const DISP_TARGET_PC: u64 = 32;
const DISP_CONTEXT: u64 = 40;
const DISP_LANGUAGE: u64 = 48;
const DISP_HANDLER_DATA: u64 = 56;
const DISP_SCOPE_INDEX: u64 = 72;
const DISP_UNWOUND: u64 = 76;
const DISP_NONVOL: u64 = 80;

/// What a structured exception operation is trying to do.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    /// Find a handler for the exception.
    Search,
    /// Unwind to `target` (establisher frame) and resume at `target_ip`.
    Unwind {
        target: u64,
        target_ip: u64,
        retval: u64,
    },
}

/// One exception operation (RaiseException or RtlUnwindEx) in progress.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Op {
    /// The phase.
    pub phase: Phase,
    /// EXCEPTION_RECORD (guest address).
    pub rec: u64,
    /// CONTEXT of the frame being examined (guest address).
    pub ctx: u64,
    /// Scratch CONTEXT for the caller of that frame.
    pub ctx2: u64,
    /// DISPATCHER_CONTEXT (guest address).
    pub disp: u64,
    /// EXCEPTION_POINTERS (guest address).
    pub ep: u64,
    /// Nesting level (scratch slot index).
    pub slot: u32,
    /// Frame-stack length when the operation started.
    pub frame_base: usize,
}

/// Continuation state of a language-handler call.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SehStep {
    /// A frame's language handler returned during the walk.
    Handler { op: Op },
    /// A `__C_specific_handler` filter returned (search phase, scope `scope`).
    Filter {
        op: Op,
        scope: u64,
        image: u64,
        table: u64,
        est: u64,
    },
    /// A `__finally` (termination) block returned; scan continues at `next`.
    Finally {
        op: Op,
        next: u64,
        image: u64,
        table: u64,
        pc: u64,
        count: u64,
        est: u64,
    },
    /// The unhandled-exception filter returned.
    Unhandled { op: Op },
}

/// Guest scratch area of the running thread (allocated on first use).
fn scratch_base(ctx: &mut ApiCtx) -> Result<u64> {
    let cur = ctx.p.sched.cur;
    let existing = ctx.p.sched.threads[cur].seh_scratch;
    if existing != 0 {
        return Ok(existing);
    }
    let size = MAX_NESTING as u64 * SLOT_SIZE;
    let Some(base) = ctx.p.vm.find_free(size, GRANULARITY) else {
        ctx.fatal("exception dispatch: no memory for scratch".into());
        return Ok(0);
    };
    ctx.p.vm.reserve(base, size, PAGE_READWRITE, MEM_PRIVATE);
    ctx.p.vm.commit(base, size, PAGE_READWRITE);
    ctx.zero(base, size)?;
    ctx.p.sched.threads[cur].seh_scratch = base;
    Ok(base)
}

/// Begin an operation: reserve a nesting slot and build its addresses.
fn begin(ctx: &mut ApiCtx, phase: Phase) -> Result<Option<Op>> {
    let cur = ctx.p.sched.cur;
    let slot = ctx.p.sched.threads[cur].seh_depth;
    if slot >= MAX_NESTING {
        ctx.fatal("exception dispatch nested too deeply".into());
        return Ok(None);
    }
    let base = scratch_base(ctx)? + slot as u64 * SLOT_SIZE;
    if slot == 0 {
        let len = ctx.p.sched.threads[cur].frames.len();
        ctx.p.sched.threads[cur].seh_base = Some(len);
    }
    let frame_base = ctx.p.sched.threads[cur].frames.len();
    ctx.p.sched.threads[cur].seh_depth = slot + 1;
    Ok(Some(Op {
        phase,
        rec: base + SLOT_REC,
        ctx: base + SLOT_CTX,
        ctx2: base + SLOT_CTX2,
        disp: base + SLOT_DISP,
        ep: base + SLOT_EP,
        slot,
        frame_base,
    }))
}

/// Finish an operation: drop its continuation frames and nesting level.
fn end(ctx: &mut ApiCtx, op: &Op, jumped: bool) {
    let cur = ctx.p.sched.cur;
    let t = &mut ctx.p.sched.threads[cur];
    let keep = if jumped {
        t.seh_base.unwrap_or(op.frame_base)
    } else {
        op.frame_base
    };
    t.frames.truncate(keep);
    t.seh_depth = op.slot;
    if op.slot == 0 || jumped {
        t.seh_base = None;
    }
}

/// Load registers into the running CPU state.
fn apply(ctx: &mut ApiCtx, r: &Regs) {
    ctx.state.x = r.x;
    ctx.state.sp = r.sp;
    ctx.state.pc = r.pc;
    ctx.state.v = r.v;
    ctx.state.fpcr = r.fpcr;
    ctx.state.fpsr = r.fpsr;
    ctx.pc_set = true;
}

/// The running thread's registers as a CONTEXT (pc = return address).
fn current_regs(ctx: &ApiCtx) -> Regs {
    let mut r = Regs {
        x: ctx.state.x,
        sp: ctx.state.sp,
        pc: ctx.state.x[30],
        v: ctx.state.v,
        fpcr: ctx.state.fpcr,
        fpsr: ctx.state.fpsr,
        flags: CONTEXT_FULL,
    };
    r.flags = CONTEXT_FULL;
    r
}

fn copy_context(ctx: &mut ApiCtx, src: u64, dst: u64) -> Result<()> {
    let data = ctx.bytes(src, CONTEXT_SIZE)?;
    ctx.put(dst, &data)
}

/// Write the EXCEPTION_RECORD fields the walker needs.
fn set_flags(ctx: &mut ApiCtx, rec: u64, flags: u32) -> Result<()> {
    ctx.wr(rec + REC_FLAGS, 4, flags as u64)
}

fn exception_code(ctx: &ApiCtx, rec: u64) -> Result<u32> {
    Ok(ctx.rd(rec + REC_CODE, 4)? as u32)
}

/// Walk the frames of `op` from the CONTEXT at `op.ctx`.
pub(crate) fn walk(ctx: &mut ApiCtx, op: Op) -> Result<()> {
    let mut steps = 0u32;
    loop {
        steps += 1;
        if steps > MAX_FRAMES {
            return fail_walk(ctx, &op, "exception dispatch: too many frames");
        }
        let regs = Regs::read(ctx.mem, op.ctx)?;
        let unwound = regs.flags & CONTEXT_UNWOUND_TO_CALL != 0;
        let lookup_pc = if unwound {
            regs.pc.wrapping_sub(4)
        } else {
            regs.pc
        };
        let mut caller = regs;
        let mut ptrs = NvPtrs::default();
        let uw = unwind::virtual_unwind(ctx.mem, &ctx.modules, &mut caller, lookup_pc, &mut ptrs)?;
        // the caller's CONTEXT is kept in ctx2 while this frame's handler runs
        caller.write(ctx.mem, op.ctx2)?;

        if let Phase::Unwind {
            target,
            target_ip,
            retval,
        } = op.phase
        {
            if uw.frame == target {
                // reached the target frame: resume there with its own registers
                let mut landing = regs;
                landing.pc = target_ip;
                landing.x[0] = retval;
                apply(ctx, &landing);
                end(ctx, &op, true);
                return Ok(());
            }
        }
        if uw.handler != 0 {
            let call_frame = uw.frame;
            fill_dispatcher(ctx, &op, regs.pc, unwound, &uw, call_frame)?;
            let mut rec_flags = ctx.rd(op.rec + REC_FLAGS, 4)? as u32;
            if matches!(op.phase, Phase::Unwind { .. }) {
                rec_flags |= EXCEPTION_UNWINDING;
            }
            set_flags(ctx, op.rec, rec_flags)?;
            cont::call_guest(
                ctx,
                uw.handler,
                &[op.rec, call_frame, op.ctx, op.disp],
                Frame::Seh(SehStep::Handler { op }),
            );
            return Ok(());
        }
        // no handler: continue with the caller, or stop when unwinding cannot
        // make progress (a frame without unwind data whose return address is
        // its own PC, as Windows rejects) or leaves the known code
        let no_progress = caller.pc == regs.pc && caller.sp == regs.sp;
        copy_context(ctx, op.ctx2, op.ctx)?;
        if caller.pc == 0 || no_progress || !unwind_is_known(ctx, caller.pc) {
            return end_of_stack(ctx, &op);
        }
    }
}

/// True when `pc` lies in a module we can unwind through.
fn unwind_is_known(ctx: &ApiCtx, pc: u64) -> bool {
    ctx.modules
        .iter()
        .any(|m| pc >= m.base && pc < m.base + m.size)
}

/// Reached the bottom of the stack without a handler.
fn end_of_stack(ctx: &mut ApiCtx, op: &Op) -> Result<()> {
    match op.phase {
        Phase::Search => unhandled(ctx, *op),
        Phase::Unwind { .. } => fail_walk(ctx, op, "RtlUnwindEx: target frame not found"),
    }
}

fn fail_walk(ctx: &mut ApiCtx, op: &Op, msg: &str) -> Result<()> {
    end(ctx, op, true);
    ctx.fatal(msg.to_string());
    Ok(())
}

/// Fill the DISPATCHER_CONTEXT for the handler of the frame at `op.ctx`.
fn fill_dispatcher(
    ctx: &mut ApiCtx,
    op: &Op,
    control_pc: u64,
    unwound: bool,
    uw: &unwind::Unwound,
    est: u64,
) -> Result<()> {
    let d = op.disp;
    ctx.wr(d + DISP_CONTROL_PC, 8, control_pc)?;
    ctx.wr(d + DISP_IMAGE, 8, uw.image_base)?;
    ctx.wr(d + DISP_ENTRY, 8, uw.entry)?;
    ctx.wr(d + DISP_ESTABLISHER, 8, est)?;
    let target = match op.phase {
        Phase::Unwind { target_ip, .. } => target_ip,
        Phase::Search => 0,
    };
    ctx.wr(d + DISP_TARGET_PC, 8, target)?;
    ctx.wr(d + DISP_CONTEXT, 8, op.ctx)?;
    ctx.wr(d + DISP_LANGUAGE, 8, uw.handler)?;
    ctx.wr(d + DISP_HANDLER_DATA, 8, uw.handler_data)?;
    ctx.wr(d + DISP_SCOPE_INDEX, 4, 0)?;
    ctx.wr(d + DISP_UNWOUND, 1, unwound as u64)?;
    ctx.wr(d + DISP_NONVOL, 8, 0)?;
    Ok(())
}

/// Resume a walk after a language handler returned `disposition`.
fn handler_returned(ctx: &mut ApiCtx, op: Op, disposition: u64) -> Result<()> {
    match op.phase {
        Phase::Search => {
            if disposition == 0 {
                // ContinueExecution: the handler may have changed the CONTEXT
                let r = Regs::read(ctx.mem, op.ctx)?;
                apply(ctx, &r);
                end(ctx, &op, false);
                Ok(())
            } else {
                // ContinueSearch / nested / collided: the caller's CONTEXT is in ctx2
                copy_context(ctx, op.ctx2, op.ctx)?;
                walk(ctx, op)
            }
        }
        Phase::Unwind { .. } => {
            copy_context(ctx, op.ctx2, op.ctx)?;
            walk(ctx, op)
        }
    }
}

/// No handler accepted the exception: run the unhandled-exception filter, or
/// terminate the process with the exception code.
fn unhandled(ctx: &mut ApiCtx, op: Op) -> Result<()> {
    let filter = ctx.p.k32.unhandled_filter;
    let code = exception_code(ctx, op.rec)?;
    if filter == 0 {
        end(ctx, &op, true);
        ctx.exit_message = Some(format!("unhandled exception {code:#010x}"));
        crate::cont::finish_process(ctx, code as u64);
        return Ok(());
    }
    ctx.wr(op.ep, 8, op.rec)?;
    ctx.wr(op.ep + 8, 8, op.ctx)?;
    cont::call_guest(ctx, filter, &[op.ep], Frame::Seh(SehStep::Unhandled { op }));
    Ok(())
}

/// Continue the `__C_specific_handler` scope scan (search phase) from `i`.
fn scan_search(
    ctx: &mut ApiCtx,
    op: Op,
    table: u64,
    image: u64,
    pc: u64,
    est: u64,
    from: u64,
) -> Result<()> {
    let count = ctx.rd(table, 4)?;
    let mut i = from;
    while i < count {
        let entry = table + 4 + 16 * i;
        let begin = ctx.rd(entry, 4)?;
        let end_rva = ctx.rd(entry + 4, 4)?;
        let handler = ctx.rd(entry + 8, 4)?;
        let target = ctx.rd(entry + 12, 4)?;
        let rel = pc.wrapping_sub(image);
        if rel >= begin && rel < end_rva && target != 0 {
            if handler == EXECUTE_HANDLER {
                return unwind_to_scope(ctx, op, image, target, est);
            }
            if handler == 0 {
                i += 1;
                continue;
            }
            // filter function: called with (EXCEPTION_POINTERS*, establisher frame)
            let filter = image + handler;
            cont::call_guest(
                ctx,
                filter,
                &[op.ep, est],
                Frame::Seh(SehStep::Filter {
                    op,
                    scope: i,
                    image,
                    table,
                    est,
                }),
            );
            return Ok(());
        }
        i += 1;
    }
    cont::finish_value(
        ctx,
        gateway::addr_of(CONTINUATION_ID),
        DISPOSITION_CONTINUE_SEARCH,
    );
    Ok(())
}

/// Start unwinding to the `__except` landing pad of scope `scope`.
fn unwind_to_scope(ctx: &mut ApiCtx, op: Op, image: u64, target_rva: u64, est: u64) -> Result<()> {
    // the handler's own CONTEXT is where the unwinding walk starts
    let Some(mut next) = begin(
        ctx,
        Phase::Unwind {
            target: est,
            target_ip: image + target_rva,
            retval: 0,
        },
    )?
    else {
        return Ok(());
    };
    next.rec = op.rec;
    copy_context(ctx, op.ctx, next.ctx)?;
    walk(ctx, next)
}

/// Continue the termination-handler scan (unwind phase) from `next`.
fn scan_finally(
    ctx: &mut ApiCtx,
    op: Op,
    image: u64,
    table: u64,
    pc: u64,
    count: u64,
    est: u64,
    mut next: u64,
) -> Result<()> {
    while next < count {
        let entry = table + 4 + 16 * next;
        let begin = ctx.rd(entry, 4)?;
        let end_rva = ctx.rd(entry + 4, 4)?;
        let handler = ctx.rd(entry + 8, 4)?;
        let target = ctx.rd(entry + 12, 4)?;
        next += 1;
        let rel = pc.wrapping_sub(image);
        if rel >= begin && rel < end_rva && target == 0 && handler != 0 {
            let f = image + handler;
            cont::call_guest(
                ctx,
                f,
                &[1, est],
                Frame::Seh(SehStep::Finally {
                    op,
                    next,
                    image,
                    table,
                    pc,
                    count,
                    est,
                }),
            );
            return Ok(());
        }
    }
    cont::finish_value(ctx, gateway::addr_of(CONTINUATION_ID), 1);
    Ok(())
}

/// Resume the walk-related frame steps.
pub(crate) fn resume(ctx: &mut ApiCtx, step: SehStep, value: u64) -> Result<()> {
    match step {
        SehStep::Handler { op } => handler_returned(ctx, op, value),
        SehStep::Filter {
            op,
            scope,
            image,
            table,
            est,
        } => {
            let v = value as u32 as i32 as i64;
            if v < 0 {
                // EXCEPTION_CONTINUE_EXECUTION
                cont::finish_value(
                    ctx,
                    gateway::addr_of(CONTINUATION_ID),
                    DISPOSITION_CONTINUE_EXECUTION,
                );
                return Ok(());
            }
            if v > 0 {
                let target_rva = ctx.rd(table + 4 + 16 * scope + 12, 4)?;
                return unwind_to_scope(ctx, op, image, target_rva, est);
            }
            let pc = filter_pc(ctx, op)?;
            scan_search(ctx, op, table, image, pc, est, scope + 1)
        }
        SehStep::Finally {
            op,
            next,
            image,
            table,
            pc,
            count,
            est,
        } => scan_finally(ctx, op, image, table, pc, count, est, next),
        SehStep::Unhandled { op } => {
            if value as u32 as i32 == -1 {
                // EXCEPTION_CONTINUE_EXECUTION
                let r = Regs::read(ctx.mem, op.ctx)?;
                apply(ctx, &r);
                end(ctx, &op, false);
                return Ok(());
            }
            let code = exception_code(ctx, op.rec)?;
            end(ctx, &op, true);
            ctx.exit_message = Some(format!("unhandled exception {code:#010x}"));
            cont::finish_process(ctx, code as u64);
            Ok(())
        }
    }
}

/// The control PC the scope scan uses for the frame at `op.disp`.
fn filter_pc(ctx: &ApiCtx, op: Op) -> Result<u64> {
    let control = ctx.rd(op.disp + DISP_CONTROL_PC, 8)?;
    let unwound = ctx.rd(op.disp + DISP_UNWOUND, 1)? != 0;
    Ok(if unwound {
        control.wrapping_sub(4)
    } else {
        control
    })
}

// ----- adapters -----

fn capture_context(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let r = current_regs(ctx);
    r.write(ctx.mem, p)?;
    Ok(())
}

fn rtl_lookup_function_entry(ctx: &mut ApiCtx) -> Result<()> {
    let (pc, base_out) = (ctx.a(0), ctx.a(1));
    match unwind::lookup(ctx.mem, &ctx.modules, pc)? {
        Some(f) => {
            if base_out != 0 {
                ctx.wr(base_out, 8, f.base)?;
            }
            ctx.ret(f.entry);
        }
        None => {
            if base_out != 0 {
                ctx.wr(base_out, 8, 0)?;
            }
            ctx.ret(0);
        }
    }
    Ok(())
}

/// RtlVirtualUnwind(type, imagebase, pc, fentry, ctx, handler_data, frame_ret, ctx_ptrs).
fn rtl_virtual_unwind(ctx: &mut ApiCtx) -> Result<()> {
    let (pc, cx, hd_out, frame_out, ptrs_out) = (ctx.a(2), ctx.a(4), ctx.a(5), ctx.a(6), ctx.a(7));
    let mut regs = Regs::read(ctx.mem, cx)?;
    let mut ptrs = NvPtrs::default();
    let uw = unwind::virtual_unwind(ctx.mem, &ctx.modules, &mut regs, pc, &mut ptrs)?;
    regs.write(ctx.mem, cx)?;
    if hd_out != 0 {
        ctx.wr(hd_out, 8, uw.handler_data)?;
    }
    if frame_out != 0 {
        ctx.wr(frame_out, 8, uw.frame)?;
    }
    if ptrs_out != 0 {
        for (i, a) in ptrs.a.iter().enumerate() {
            ctx.wr(ptrs_out + 8 * i as u64, 8, *a)?;
        }
    }
    ctx.ret(uw.handler);
    Ok(())
}

fn rtl_restore_context(ctx: &mut ApiCtx) -> Result<()> {
    let cx = ctx.a(0);
    let r = Regs::read(ctx.mem, cx)?;
    apply(ctx, &r);
    Ok(())
}

/// RaiseException(code, flags, nargs, args*).
fn raise_exception(ctx: &mut ApiCtx) -> Result<()> {
    let (code, flags, nargs, args) = (ctx.au(0), ctx.au(1), ctx.au(2).min(15), ctx.a(3));
    let Some(op) = begin(ctx, Phase::Search)? else {
        return Ok(());
    };
    let raise_pc = ctx.state.x[30];
    ctx.zero(op.rec, 0x98)?;
    ctx.wr(op.rec + REC_CODE, 4, code as u64)?;
    ctx.wr(op.rec + REC_FLAGS, 4, flags as u64)?;
    ctx.wr(op.rec + 16, 8, raise_pc)?;
    ctx.wr(op.rec + REC_NPARAMS, 4, nargs as u64)?;
    for i in 0..nargs as u64 {
        let v = ctx.rd(args + 8 * i, 8)?;
        ctx.wr(op.rec + REC_INFO + 8 * i, 8, v)?;
    }
    current_regs(ctx).write(ctx.mem, op.ctx)?;
    walk(ctx, op)
}

/// RtlUnwindEx(target_frame, target_ip, record, retval, context, history).
fn rtl_unwind_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (target, target_ip, rec_p, retval, cx) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.a(3), ctx.a(4));
    let Some(op) = begin(
        ctx,
        Phase::Unwind {
            target,
            target_ip,
            retval,
        },
    )?
    else {
        return Ok(());
    };
    if rec_p != 0 {
        copy_context_bytes(ctx, rec_p, op.rec, 0x98)?;
    } else {
        ctx.zero(op.rec, 0x98)?;
        ctx.wr(op.rec + REC_CODE, 4, STATUS_UNWIND as u64)?;
    }
    set_flags(ctx, op.rec, EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)?;
    if cx != 0 {
        copy_context(ctx, cx, op.ctx)?;
    } else {
        current_regs(ctx).write(ctx.mem, op.ctx)?;
    }
    walk(ctx, op)
}

fn copy_context_bytes(ctx: &mut ApiCtx, src: u64, dst: u64, n: u64) -> Result<()> {
    let data = ctx.bytes(src, n)?;
    ctx.put(dst, &data)
}

fn set_unhandled_exception_filter(ctx: &mut ApiCtx) -> Result<()> {
    let f = ctx.a(0);
    let prev = std::mem::replace(&mut ctx.p.k32.unhandled_filter, f);
    ctx.ret(prev);
    Ok(())
}

/// UnhandledExceptionFilter(EXCEPTION_POINTERS*): runs the installed filter.
fn unhandled_exception_filter(ctx: &mut ApiCtx) -> Result<()> {
    let ep = ctx.a(0);
    let f = ctx.p.k32.unhandled_filter;
    if f == 0 {
        ctx.ret_i32(0); // EXCEPTION_CONTINUE_SEARCH
        return Ok(());
    }
    let lr = ctx.state.x[30];
    cont::call_guest(ctx, f, &[ep], Frame::Passthrough { lr });
    Ok(())
}

/// __C_specific_handler(record, establisher, context, dispatcher_context).
fn c_specific_handler(ctx: &mut ApiCtx) -> Result<()> {
    let (rec, est, cx, disp) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.a(3));
    let flags = ctx.rd(rec + REC_FLAGS, 4)? as u32;
    let control = ctx.rd(disp + DISP_CONTROL_PC, 8)?;
    let image = ctx.rd(disp + DISP_IMAGE, 8)?;
    let table = ctx.rd(disp + DISP_HANDLER_DATA, 8)?;
    let unwound = ctx.rd(disp + DISP_UNWOUND, 1)? != 0;
    let pc = if unwound {
        control.wrapping_sub(4)
    } else {
        control
    };
    let count = ctx.rd(table, 4)?;
    let scope = ctx.rd(disp + DISP_SCOPE_INDEX, 4)?;
    // a placeholder op carrying what the continuation needs
    let op = Op {
        phase: Phase::Search,
        rec,
        ctx: cx,
        ctx2: 0,
        disp,
        ep: 0,
        slot: 0,
        frame_base: 0,
    };
    if flags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND) != 0 {
        return scan_finally(ctx, op, image, table, pc, count, est, scope);
    }
    // the filter needs an EXCEPTION_POINTERS: build it in the scratch area of this search
    let ep = scratch_ep(ctx, rec, cx)?;
    let op = Op { ep, ..op };
    scan_search(ctx, op, table, image, pc, est, scope)
}

/// EXCEPTION_POINTERS for filter calls made by `__C_specific_handler`.
fn scratch_ep(ctx: &mut ApiCtx, rec: u64, cx: u64) -> Result<u64> {
    let base = scratch_base(ctx)?;
    let cur = ctx.p.sched.cur;
    let depth = ctx.p.sched.threads[cur].seh_depth.max(1) - 1;
    let ep = base + depth as u64 * SLOT_SIZE + SLOT_EP;
    ctx.wr(ep, 8, rec)?;
    ctx.wr(ep + 8, 8, cx)?;
    Ok(ep)
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "vcruntime140",
        "__C_specific_handler" => c_specific_handler,
    );
    reg!(v, "kernel32",
        "RtlCaptureContext" => capture_context,
        "RtlLookupFunctionEntry" => rtl_lookup_function_entry,
        "RtlVirtualUnwind" => rtl_virtual_unwind,
        "RtlRestoreContext" => rtl_restore_context,
        "RtlUnwindEx" => rtl_unwind_ex,
        "RaiseException" => raise_exception,
        "SetUnhandledExceptionFilter" => set_unhandled_exception_filter,
        "UnhandledExceptionFilter" => unhandled_exception_filter,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_layout_fits_the_slot() {
        assert!(SLOT_EP + 16 <= SLOT_SIZE);
        assert!(SLOT_CTX + CONTEXT_SIZE <= SLOT_CTX2);
        assert!(SLOT_CTX2 + CONTEXT_SIZE <= SLOT_DISP);
        assert!(SLOT_DISP + 88 <= SLOT_EP);
    }

    #[test]
    fn dispatcher_offsets_match_the_abi() {
        assert_eq!(DISP_SCOPE_INDEX, 72);
        assert_eq!(DISP_UNWOUND, 76);
        assert_eq!(DISP_NONVOL, 80);
    }
}
