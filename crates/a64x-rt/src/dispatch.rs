//! The guest driver: dispatcher loop + run outcome.

use a64x_api::{gateway, ApiCtx, ApiLayer};
use a64x_core::state::ExitReason;
use a64x_xlat::Machine;

/// Why control flow left translated code, and what happened next.
#[derive(Debug)]
pub struct RunOutcome {
    /// Final reason the run stopped.
    pub reason: ExitReason,
    /// Guest-chosen exit code (ExitProcess / returning from the entry).
    pub exit_code: u64,
    /// Guest PC when the run stopped.
    pub pc: u64,
    /// Guest instructions retired (when counting is enabled).
    pub insn_count: u64,
    /// Blocks entered (when counting is enabled).
    pub block_count: u64,
    /// Blocks translated this run.
    pub blocks_translated: u64,
    /// API calls made through the gateway.
    pub api_calls: u64,
    /// Optional human-readable message.
    pub message: Option<String>,
    /// Trampoline entries (dispatcher rounds). With chaining, hot loops
    /// need only a handful of rounds regardless of iteration count —
    /// this is the direct evidence that native blocks stay in control.
    pub rounds: u64,
}

/// Translator budget per dispatcher round: chaining decrements it; at
/// zero the block returns so this loop regains control (API calls, trace,
/// preemption). Large enough that hot loops stay in native code.
const BUDGET_PER_ROUND: u64 = 1 << 22;

/// Everything a run needs besides the machine and the API layer.
pub struct RunConfig<'a> {
    /// Guest entry point.
    pub entry: u64,
    /// Command line the guest sees (GetCommandLineA/W, argv).
    pub cmdline: &'a [u8],
    /// Load address of the main image.
    pub image_base: u64,
    /// Loaded images (for unwinding, module handles and GetProcAddress).
    pub modules: &'a [a64x_api::ModuleInfo],
    /// Print one line per dispatcher round to stderr.
    pub trace: bool,
}

/// Run `entry` in `machine` until the guest stops. The image is described
/// by `image_base` only; use [`run_with`] to supply module information.
pub fn run(
    machine: &mut Machine,
    api: &ApiLayer,
    entry: u64,
    cmdline: &[u8],
    image_base: u64,
    trace: bool,
) -> RunOutcome {
    run_with(
        machine,
        api,
        &RunConfig {
            entry,
            cmdline,
            image_base,
            modules: &[],
            trace,
        },
    )
}

/// Run the guest described by `cfg` (see [`RunConfig`]).
pub fn run_with(machine: &mut Machine, api: &ApiLayer, cfg: &RunConfig) -> RunOutcome {
    let trace = cfg.trace;
    // decompose: every part borrows independently, ctx borrows the state
    // fields for the whole run while we only touch cache/trampoline.
    let (state, mem, cache, tramp) = machine.split_parts();
    let mut ctx = ApiCtx::new(state, mem);
    ctx.cmd_line = cfg.cmdline.to_vec();
    ctx.image_base = cfg.image_base;
    ctx.api = Some(api);
    ctx.modules = cfg.modules.to_vec();

    ctx.state.pc = cfg.entry;
    ctx.state.running = 1;
    ctx.state.exit_reason = ExitReason::Ok as u8;
    ctx.state.sp = crate::loader::initial_sp(ctx.mem.size());
    // Sentinel LR: returning from the entry point ends the process.
    ctx.state.x[30] = 0;

    let mut api_calls = 0u64;
    let mut rounds = 0u64;
    let mut message: Option<String> = None;
    let final_reason: ExitReason;

    loop {
        // -- API gateway branch: host-side API dispatch; no guest code runs
        // while we're here except callbacks an adapter starts.
        if let Some(id) = gateway::id_of(ctx.state.pc) {
            ctx.enter(ctx.state.pc);
            if let Err(e) = api.invoke(id, &mut ctx) {
                message = Some(format!("adapter {} failed: {e}", api.describe(id)));
                final_reason = ExitReason::Stopped;
                break;
            }
            ctx.post_call();
            api_calls += 1;
            if ctx.state.running == 0 {
                final_reason = ExitReason::from(ctx.state.exit_reason);
                if let Some(m) = ctx.exit_message.take() {
                    message = Some(m);
                }
                break;
            }
            continue;
        }

        // -- translated-code branch.
        if trace {
            eprintln!(
                "[a64x-trace] pc={:#x} x0={:x} x1={:x} blk={} gb={}",
                ctx.state.pc,
                ctx.state.x[0],
                ctx.state.x[1],
                ctx.state.block_count,
                cache.len()
            );
        }
        let pc = ctx.state.pc;
        let entry_res = cache.get_or_translate(ctx.mem, pc);
        match entry_res {
            Ok(block_entry) => {
                ctx.state.budget = BUDGET_PER_ROUND;
                unsafe {
                    tramp.call(ctx.state as *mut _, block_entry);
                }
                rounds += 1;
                match ExitReason::from(ctx.state.exit_reason) {
                    ExitReason::Ok => {
                        if ctx.state.pc == 0 {
                            // returning from the entry point: ExitProcess(eax)
                            ctx.state.exit_code = ctx.state.x[0] & 0xFFFF_FFFF;
                            final_reason = ExitReason::Exited;
                            break;
                        }
                        // round boundary: let other threads run
                        ctx.preempt();
                        if ctx.state.running == 0 {
                            final_reason = ExitReason::from(ctx.state.exit_reason);
                            if let Some(m) = ctx.exit_message.take() {
                                message = Some(m);
                            }
                            break;
                        }
                        continue;
                    }
                    ExitReason::Svc => {
                        message.get_or_insert_with(|| {
                            format!("guest executed SVC #{}, skipped", ctx.state.aux[0])
                        });
                        ctx.state.exit_reason = ExitReason::Ok as u8;
                        ctx.state.pc += 4;
                        continue;
                    }
                    r => {
                        message = Some(match r {
                            ExitReason::UnimplementedInsn => {
                                format!(
                                    "unimplemented guest instruction {:#010x} at {:#x}",
                                    ctx.state.aux[0], ctx.state.pc
                                )
                            }
                            ExitReason::MemoryFault => {
                                format!(
                                    "guest memory fault at {:#x} accessing {:#x}",
                                    ctx.state.pc, ctx.state.aux[1]
                                )
                            }
                            _ => format!("guest stopped: {r:?}"),
                        });
                        final_reason = r;
                        break;
                    }
                }
            }
            Err(e) => {
                message = Some(format!("dispatcher error: {e}"));
                final_reason = ExitReason::Stopped;
                break;
            }
        }
    }

    RunOutcome {
        reason: final_reason,
        exit_code: ctx.state.exit_code,
        pc: ctx.state.pc,
        insn_count: ctx.state.insn_count,
        block_count: ctx.state.block_count,
        blocks_translated: cache.stats.blocks_translated,
        api_calls,
        message,
        rounds,
    }
}
