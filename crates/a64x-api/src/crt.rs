//! UCRT runtime: startup, exit, signals, errno, heap, environment, argv,
//! error strings, file locks and miscellaneous utilities.

use crate::cont::{self, AtexitEnd};
use crate::{heap, reg, sched, shell32, ApiCtx, ApiDef};
use a64x_core::Result;
use std::collections::BTreeMap;

/// Signal numbers accepted by `signal` (UCRT).
const VALID_SIGNALS: [i32; 8] = [2, 4, 6, 8, 11, 15, 21, 22];
const SIGABRT: i32 = 22;
const SIG_DFL: u64 = 0;
const SIG_ERR: u64 = u64::MAX;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EAGAIN: i32 = 11;
const ERANGE: i32 = 34;
/// Exit status of a process terminated by an unhandled invalid parameter.
const FAST_FAIL_INVALID_PARAMETER: u64 = 0xC000_0409;

/// Number of `_sys_errlist` entries (errno values 0..=42).
pub(crate) const SYS_NERR: u32 = 43;

/// UCRT strerror texts for errno 0..=42.
const ERRLIST: [&str; 43] = [
    "No error",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted function call",
    "Input/output error",
    "No such device or address",
    "Arg list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Not enough space",
    "Permission denied",
    "Bad address",
    "Unknown error",
    "Resource device",
    "File exists",
    "Improper link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate I/O control operation",
    "Unknown error",
    "File too large",
    "No space left on device",
    "Invalid seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Domain error",
    "Result too large",
    "Unknown error",
    "Resource deadlock avoided",
    "Unknown error",
    "Filename too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Illegal byte sequence",
];

/// Message for an errno value (out-of-range values give "Unknown error").
pub(crate) fn strerror_text(e: i32) -> &'static str {
    if (0..SYS_NERR as i32).contains(&e) {
        ERRLIST[e as usize]
    } else {
        "Unknown error"
    }
}

/// CRT process state.
#[derive(Default)]
pub(crate) struct CrtState {
    /// `atexit` handlers in registration order (run in reverse).
    pub atexit: Vec<u64>,
    /// Signal handlers by signal number.
    pub signals: BTreeMap<i32, u64>,
    /// Invalid-parameter handler (0 = none).
    pub invalid_param: u64,
    /// `__setusermatherr` handler (0 = none).
    pub matherr: u64,
    /// `_set_new_mode` value.
    pub new_mode: u32,
    /// `_set_app_type` value.
    pub app_type: u32,
    /// Environment block cache: `(env version, array address)`.
    pub env_cache: Option<(u64, u64)>,
}

/// `_fmode` (guest int).
pub(crate) fn fmode(ctx: &mut ApiCtx) -> Result<u32> {
    let a = var_fmode(ctx)?;
    Ok(ctx.rd(a, 4)? as u32)
}

/// Address of `_fmode`.
pub(crate) fn var_fmode(ctx: &mut ApiCtx) -> Result<u64> {
    Ok(ctx.p.statics.var("_fmode", 16)?.0)
}

/// Address of `_commode`.
pub(crate) fn var_commode(ctx: &mut ApiCtx) -> Result<u64> {
    Ok(ctx.p.statics.var("_commode", 16)?.0)
}

/// Build (once) the guest `argc`/`argv` variables from the command line.
/// Returns `(argc address, argv address)`.
pub(crate) fn ensure_args(ctx: &mut ApiCtx) -> Result<(u64, u64)> {
    let (argc_a, first) = ctx.p.statics.var("__argc", 16)?;
    let (argv_a, _) = ctx.p.statics.var("__argv", 16)?;
    if first {
        let args = shell32::parse_command_line(&ctx.cmd_line);
        let mut ptrs = Vec::with_capacity(args.len() + 1);
        for a in &args {
            ptrs.push(ctx.intern_cstr(a)?);
        }
        ptrs.push(0);
        let arr = ctx.p.statics.alloc(8 * ptrs.len() as u64, 16)?;
        for (i, p) in ptrs.iter().enumerate() {
            ctx.wr(arr + 8 * i as u64, 8, *p)?;
        }
        ctx.wr(argc_a, 4, args.len() as u64)?;
        ctx.wr(argv_a, 8, arr)?;
    }
    Ok((argc_a, argv_a))
}

/// Guest `char**` environment array, rebuilt when the environment changed.
fn environ_var(ctx: &mut ApiCtx) -> Result<u64> {
    let (cell, _) = ctx.p.statics.var("_environ", 16)?;
    let version = ctx.p.env.version;
    let fresh = matches!(ctx.p.crt.env_cache, Some((v, _)) if v == version);
    if !fresh {
        let entries: Vec<String> = ctx.p.env.entries();
        let mut ptrs = Vec::with_capacity(entries.len() + 1);
        for e in &entries {
            ptrs.push(ctx.intern_cstr(e.as_bytes())?);
        }
        ptrs.push(0);
        let arr = ctx.p.statics.alloc(8 * ptrs.len() as u64, 16)?;
        for (i, p) in ptrs.iter().enumerate() {
            ctx.wr(arr + 8 * i as u64, 8, *p)?;
        }
        ctx.wr(cell, 8, arr)?;
        ctx.p.crt.env_cache = Some((version, arr));
    }
    Ok(cell)
}

/// Address of the `_sys_nerr` variable (43).
fn sys_nerr_var(ctx: &mut ApiCtx) -> Result<u64> {
    let (a, first) = ctx.p.statics.var("_sys_nerr", 16)?;
    if first {
        ctx.wr(a, 4, SYS_NERR as u64)?;
    }
    Ok(a)
}

/// Address of the `_sys_errlist` array of `char*`.
fn sys_errlist_var(ctx: &mut ApiCtx) -> Result<u64> {
    let (a, first) = ctx.p.statics.var("_sys_errlist", 16 * 8)?;
    if first {
        for e in 0..SYS_NERR as usize {
            let s = ctx.intern_cstr(ERRLIST[e].as_bytes())?;
            ctx.wr(a + 8 * e as u64, 8, s)?;
        }
    }
    Ok(a)
}

/// Heap allocation for the CRT (process heap), setting errno on failure.
fn crt_alloc(ctx: &mut ApiCtx, size: u64, align: u64) -> Result<u64> {
    let p = heap::alloc(ctx, 0, size.max(1), align, false)?;
    if p == 0 {
        ctx.set_errno(ENOMEM);
    }
    Ok(p)
}

fn malloc(ctx: &mut ApiCtx) -> Result<()> {
    let p = crt_alloc(ctx, ctx.a(0), 16)?;
    ctx.ret(p);
    Ok(())
}

fn calloc(ctx: &mut ApiCtx) -> Result<()> {
    let (n, sz) = (ctx.a(0), ctx.a(1));
    let Some(total) = n.checked_mul(sz) else {
        ctx.set_errno(ENOMEM);
        ctx.ret(0);
        return Ok(());
    };
    let p = heap::alloc(ctx, 0, total.max(1), 16, true)?;
    if p == 0 {
        ctx.set_errno(ENOMEM);
    }
    ctx.ret(p);
    Ok(())
}

fn free(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    if p != 0 {
        heap::free(ctx, 0, p);
    }
    Ok(())
}

fn realloc(ctx: &mut ApiCtx) -> Result<()> {
    let (p, n) = (ctx.a(0), ctx.a(1));
    if p != 0 && n == 0 {
        heap::free(ctx, 0, p);
        ctx.ret(0);
        return Ok(());
    }
    let r = heap::realloc(ctx, 0, p, n, 16, false)?;
    if r == 0 {
        ctx.set_errno(ENOMEM);
    }
    ctx.ret(r);
    Ok(())
}

fn aligned_malloc(ctx: &mut ApiCtx) -> Result<()> {
    let (n, align) = (ctx.a(0), ctx.a(1));
    if align == 0 || !align.is_power_of_two() {
        ctx.set_errno(EINVAL);
        ctx.ret(0);
        return Ok(());
    }
    let p = crt_alloc(ctx, n, align)?;
    ctx.ret(p);
    Ok(())
}

fn aligned_free(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    if p != 0 {
        heap::free(ctx, 0, p);
    }
    Ok(())
}

fn msize(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let n = heap::size_of(ctx, 0, p).unwrap_or(0);
    ctx.ret(n);
    Ok(())
}

fn set_new_mode(ctx: &mut ApiCtx) -> Result<()> {
    let m = ctx.au(0);
    if m > 1 {
        ctx.set_errno(EINVAL);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    let prev = ctx.p.crt.new_mode;
    ctx.p.crt.new_mode = m;
    ctx.ret(prev as u64);
    Ok(())
}

fn p_argc(ctx: &mut ApiCtx) -> Result<()> {
    let (a, _) = ensure_args(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn p_argv(ctx: &mut ApiCtx) -> Result<()> {
    let (_, a) = ensure_args(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn p_environ(ctx: &mut ApiCtx) -> Result<()> {
    let a = environ_var(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn getenv(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let value = ctx.p.env.get(&name).map(|v| v.to_string());
    match value {
        Some(v) => {
            let p = ctx.intern_cstr(v.as_bytes())?;
            ctx.ret(p);
        }
        None => ctx.ret(0),
    }
    Ok(())
}

fn putenv_s(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let value_p = ctx.a(1);
    if name.is_empty() || name.contains('=') {
        ctx.set_errno(EINVAL);
        ctx.ret_i32(EINVAL);
        return Ok(());
    }
    let value = if value_p == 0 {
        None
    } else {
        Some(ctx.cstr_string(value_p)?)
    };
    ctx.p.env.set(&name, value.as_deref());
    ctx.ret_i32(0);
    Ok(())
}

fn errno_addr(ctx: &mut ApiCtx) -> Result<()> {
    let a = ctx.p.sched.cur_errno_addr();
    ctx.ret(a);
    Ok(())
}

fn initterm(ctx: &mut ApiCtx) -> Result<()> {
    let lr = ctx.state.x[30];
    cont::init_term_step(ctx, lr, ctx.a(0), ctx.a(1), false)
}

fn initterm_e(ctx: &mut ApiCtx) -> Result<()> {
    let lr = ctx.state.x[30];
    cont::init_term_step(ctx, lr, ctx.a(0), ctx.a(1), true)
}

fn exit(ctx: &mut ApiCtx) -> Result<()> {
    let code = ctx.au(0) as u64;
    let n = ctx.p.crt.atexit.len();
    cont::run_atexit(ctx, n, AtexitEnd::Terminate(code))
}

fn cexit(ctx: &mut ApiCtx) -> Result<()> {
    let lr = ctx.state.x[30];
    let n = ctx.p.crt.atexit.len();
    cont::run_atexit(ctx, n, AtexitEnd::Return { lr, value: 0 })
}

fn exit_process_crt(ctx: &mut ApiCtx) -> Result<()> {
    let code = ctx.au(0) as u64;
    cont::finish_process(ctx, code);
    Ok(())
}

/// `abort`: run the SIGABRT handler (reset to default first) and exit with 3.
fn abort(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.p.crt.signals.get(&SIGABRT).copied().unwrap_or(SIG_DFL);
    if h == SIG_DFL || h == 1 || h == SIG_ERR {
        cont::finish_process(ctx, 3);
        return Ok(());
    }
    ctx.p.crt.signals.insert(SIGABRT, SIG_DFL);
    cont::call_guest(ctx, h, &[SIGABRT as u64], cont::Frame::Abort);
    Ok(())
}

fn signal(ctx: &mut ApiCtx) -> Result<()> {
    let sig = ctx.ai(0);
    let func = ctx.a(1);
    if !VALID_SIGNALS.contains(&sig) {
        ctx.set_errno(EINVAL);
        ctx.ret(SIG_ERR);
        return Ok(());
    }
    let prev = ctx.p.crt.signals.insert(sig, func).unwrap_or(SIG_DFL);
    ctx.ret(prev);
    Ok(())
}

fn atexit(ctx: &mut ApiCtx) -> Result<()> {
    let f = ctx.a(0);
    if f == 0 {
        ctx.set_errno(EINVAL);
        ctx.ret_i32(-1);
        return Ok(());
    }
    ctx.p.crt.atexit.push(f);
    ctx.ret_i32(0);
    Ok(())
}

fn set_invalid_parameter_handler(ctx: &mut ApiCtx) -> Result<()> {
    let new = ctx.a(0);
    let prev = std::mem::replace(&mut ctx.p.crt.invalid_param, new);
    ctx.ret(prev);
    Ok(())
}

fn set_app_type(ctx: &mut ApiCtx) -> Result<()> {
    ctx.p.crt.app_type = ctx.au(0);
    Ok(())
}

fn fpreset(ctx: &mut ApiCtx) -> Result<()> {
    ctx.state.fpcr = 0;
    ctx.state.fpsr = 0;
    Ok(())
}

fn configure_narrow_argv(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_i32(0);
    Ok(())
}

fn initialize_narrow_environment(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_i32(0);
    Ok(())
}

/// `_assert(message, file, line)`: report on stderr, then abort.
fn assert_fail(ctx: &mut ApiCtx) -> Result<()> {
    let msg = ctx.cstr_string(ctx.a(0))?;
    let file = ctx.cstr_string(ctx.a(1))?;
    let line = ctx.au(2);
    let text = format!("Assertion failed: {msg}, file {file}, line {line}\n");
    {
        use std::io::Write;
        let mut e = std::io::stderr().lock();
        let _ = e.write_all(text.as_bytes());
        let _ = e.flush();
    }
    abort(ctx)
}

fn strerror(ctx: &mut ApiCtx) -> Result<()> {
    let e = ctx.ai(0);
    let p = ctx.intern_cstr(strerror_text(e).as_bytes())?;
    ctx.ret(p);
    Ok(())
}

/// An invalid parameter was passed to a CRT function: the registered
/// invalid-parameter handler is called with the function name, and the
/// function then returns `ret`. Without a handler the process terminates
/// with the UCRT fast-fail status (STATUS_STACK_BUFFER_OVERRUN class).
pub(crate) fn invalid_parameter(ctx: &mut ApiCtx, func: &str, ret: u64) -> Result<()> {
    let handler = ctx.p.crt.invalid_param;
    if handler == 0 {
        ctx.exit_message = Some(format!("invalid parameter passed to {func}"));
        cont::finish_process(ctx, FAST_FAIL_INVALID_PARAMETER);
        return Ok(());
    }
    let units: Vec<u16> = func.encode_utf16().collect();
    let name = ctx.intern_wstr(&units)?;
    let lr = ctx.state.x[30];
    cont::call_guest(ctx, handler, &[0, name, 0, 0, 0], cont::Frame::InvalidParam { lr, ret });
    Ok(())
}

fn strerror_s(ctx: &mut ApiCtx) -> Result<()> {
    let (buf, size, e) = (ctx.a(0), ctx.a(1), ctx.ai(2));
    if buf == 0 || size == 0 {
        ctx.set_errno(EINVAL);
        return invalid_parameter(ctx, "strerror_s", EINVAL as u64);
    }
    let text = strerror_text(e).as_bytes();
    let fit = (size - 1).min(text.len() as u64);
    ctx.put(buf, &text[..fit as usize])?;
    ctx.wr(buf + fit, 1, 0)?;
    if fit < text.len() as u64 {
        ctx.ret_i32(ERANGE);
    } else {
        ctx.ret_i32(0);
    }
    Ok(())
}

fn sys_nerr(ctx: &mut ApiCtx) -> Result<()> {
    let a = sys_nerr_var(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn sys_errlist(ctx: &mut ApiCtx) -> Result<()> {
    let a = sys_errlist_var(ctx)?;
    ctx.ret(a);
    Ok(())
}

/// `_beginthreadex(security, stack, start, arg, initflag, thrdaddr)`.
fn beginthreadex(ctx: &mut ApiCtx) -> Result<()> {
    let (stack, start, arg, flags, out) = (ctx.a(1), ctx.a(2), ctx.a(3), ctx.au(4), ctx.a(5));
    let h = sched::spawn(ctx, start, arg, stack, flags & 4 != 0)?;
    if h == 0 {
        ctx.set_errno(EAGAIN);
        ctx.ret(0);
        return Ok(());
    }
    if out != 0 {
        let tid = ctx.p.sched.threads.last().map(|t| t.tid).unwrap_or(0);
        ctx.wr(out, 4, tid as u64)?;
    }
    ctx.ret(h);
    Ok(())
}

fn endthreadex(ctx: &mut ApiCtx) -> Result<()> {
    let code = ctx.au(0) as u64;
    cont::exit_thread(ctx, code)
}

/// `_lock_file(FILE*)`: recursive per-stream lock; blocks while another
/// thread holds it.
fn lock_file(ctx: &mut ApiCtx) -> Result<()> {
    let _ = sched::take_wait(ctx);
    let stream = ctx.a(0);
    let me = ctx.p.sched.cur_tid();
    let owner = ctx
        .p
        .stdio
        .streams
        .get(&stream)
        .map(|s| s.lock_owner)
        .unwrap_or(0);
    if owner != 0 && owner != me {
        ctx.block_retry(None);
        return Ok(());
    }
    if let Some(s) = ctx.p.stdio.streams.get_mut(&stream) {
        s.lock_owner = me;
        s.lock_count += 1;
    }
    Ok(())
}

fn unlock_file(ctx: &mut ApiCtx) -> Result<()> {
    let stream = ctx.a(0);
    let me = ctx.p.sched.cur_tid();
    let mut released = false;
    if let Some(s) = ctx.p.stdio.streams.get_mut(&stream) {
        if s.lock_owner == me && s.lock_count > 0 {
            s.lock_count -= 1;
            if s.lock_count == 0 {
                s.lock_owner = 0;
                released = true;
            }
        }
    }
    if released {
        sched::notify(ctx);
    }
    Ok(())
}

/// `rand_s(unsigned int* randomValue)`: 32 bits from the host CSPRNG-seeded
/// hash state (std's RandomState is seeded from the operating system).
fn rand_s(ctx: &mut ApiCtx) -> Result<()> {
    use std::hash::{BuildHasher, Hasher};
    let out = ctx.a(0);
    if out == 0 {
        ctx.ret_i32(EINVAL);
        return Ok(());
    }
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(ctx.state.insn_count);
    let v = h.finish() as u32;
    ctx.wr(out, 4, v as u64)?;
    ctx.ret_i32(0);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "ucrtbase",
        "_initialize_narrow_environment" => initialize_narrow_environment,
        "malloc" => malloc,
        "calloc" => calloc,
        "free" => free,
        "realloc" => realloc,
        "_aligned_malloc" => aligned_malloc,
        "_aligned_free" => aligned_free,
        "_msize" => msize,
        "_set_new_mode" => set_new_mode,
        "__p___argc" => p_argc,
        "__p___argv" => p_argv,
        "__p__environ" => p_environ,
        "getenv" => getenv,
        "_putenv_s" => putenv_s,
        "_errno" => errno_addr,
        "_initterm" => initterm,
        "_initterm_e" => initterm_e,
        "exit" => exit,
        "_cexit" => cexit,
        "_exit" => exit_process_crt,
        "abort" => abort,
        "signal" => signal,
        "_crt_atexit" => atexit,
        "atexit" => atexit,
        "_set_invalid_parameter_handler" => set_invalid_parameter_handler,
        "_set_app_type" => set_app_type,
        "_fpreset" => fpreset,
        "_configure_narrow_argv" => configure_narrow_argv,
        "_assert" => assert_fail,
        "strerror" => strerror,
        "strerror_s" => strerror_s,
        "__sys_nerr" => sys_nerr,
        "__sys_errlist" => sys_errlist,
        "_beginthreadex" => beginthreadex,
        "_endthreadex" => endthreadex,
        "_lock_file" => lock_file,
        "_unlock_file" => unlock_file,
        "rand_s" => rand_s,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_table_matches_ucrt_entries() {
        assert_eq!(strerror_text(0), "No error");
        assert_eq!(strerror_text(2), "No such file or directory");
        assert_eq!(strerror_text(15), "Unknown error");
        assert_eq!(strerror_text(42), "Illegal byte sequence");
        assert_eq!(strerror_text(43), "Unknown error");
        assert_eq!(strerror_text(-1), "Unknown error");
        assert_eq!(ERRLIST.len() as u32, SYS_NERR);
    }
}
