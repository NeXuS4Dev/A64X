//! KERNEL32 process-level functions: process exit, last error, command line,
//! environment, module handles, handle management, code pages and misc.
//!
//! The Kernel32 state (code pages, FLS/TLS usage, filters, synchronization
//! side tables, file mappings, named objects) lives in [`K32State`].

use crate::cont;
use crate::handles::{Obj, ObjRef};
use crate::k32_info::FILETIME_EPOCH_DIFF;
use crate::{heap, reg, ApiCtx, ApiDef};
use a64x_core::Result;
use std::collections::BTreeMap;
use std::time::Instant;

/// STILL_ACTIVE.
pub(crate) const STILL_ACTIVE: u32 = 259;
/// ERROR_INVALID_HANDLE.
pub(crate) const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_INVALID_PARAMETER.
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_INSUFFICIENT_BUFFER.
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// ERROR_MOD_NOT_FOUND.
pub(crate) const ERROR_MOD_NOT_FOUND: u32 = 126;
/// ERROR_PROC_NOT_FOUND.
pub(crate) const ERROR_PROC_NOT_FOUND: u32 = 127;
/// ERROR_ENVVAR_NOT_FOUND.
pub(crate) const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
/// The pseudo handle of the current process (GetCurrentProcess).
pub(crate) const PSEUDO_PROCESS: u64 = u64::MAX;
/// The pseudo handle of the current thread (GetCurrentThread).
pub(crate) const PSEUDO_THREAD: u64 = u64::MAX - 1;
/// INVALID_HANDLE_VALUE.
pub(crate) const INVALID_HANDLE: u64 = u64::MAX;
/// Base of the module handles returned for system DLLs.
const DLL_HANDLE_BASE: u64 = 0x7FFD_0000_0000;
/// Stride between module handles.
const DLL_HANDLE_STRIDE: u64 = 0x10_0000;

/// State of one `InitOnce` object.
#[derive(Clone, Copy)]
pub(crate) enum InitState {
    /// Being initialized by thread `tid`.
    Running(u32),
    /// Initialized.
    Done,
}

/// State of one condition variable.
#[derive(Clone, Copy, Default)]
pub(crate) struct CvState {
    /// Wakeups not yet consumed by a waiter.
    pub tokens: u64,
    /// Threads currently waiting.
    pub waiters: u64,
}

/// A file mapping object.
pub(crate) struct Mapping {
    /// Size in bytes.
    pub size: u64,
    /// Guest block holding the contents (0 until first mapped).
    pub base: u64,
    /// Number of live views.
    pub views: u32,
    /// Backing file path (None = anonymous, paged by memory).
    pub file: Option<String>,
    /// PAGE_* protection the mapping was created with.
    pub protect: u32,
}

/// Kernel32 process state.
pub(crate) struct K32State {
    /// Console input code page.
    pub cp_in: u32,
    /// Console output code page.
    pub cp_out: u32,
    /// SetUnhandledExceptionFilter handler (0 = none).
    pub unhandled_filter: u64,
    /// SetErrorMode value.
    pub error_mode: u32,
    /// FLS callbacks by index (0 = none).
    pub fls_callbacks: Vec<u64>,
    /// FLS index allocation.
    pub fls_used: Vec<bool>,
    /// TLS index allocation (TLS_MINIMUM_AVAILABLE = 64).
    pub tls_used: Vec<bool>,
    /// Handle of the process heap.
    pub process_heap: u64,
    /// Console modes for stdin/stdout/stderr.
    pub console_modes: [u32; 3],
    /// Console control handlers.
    pub ctrl_handlers: Vec<u64>,
    /// InitOnce objects by address.
    pub init_once: BTreeMap<u64, InitState>,
    /// SRW locks by address: (writer tid, reader count).
    pub srw: BTreeMap<u64, (u32, u32)>,
    /// Condition variables by address.
    pub cv: BTreeMap<u64, CvState>,
    /// File mapping objects.
    pub mappings: Vec<Mapping>,
    /// Named kernel objects.
    pub names: BTreeMap<String, ObjRef>,
    /// Module handles handed out for system DLLs.
    pub dll_handles: Vec<String>,
    /// Time origin for GetTickCount and QueryPerformanceCounter.
    pub start: Instant,
    /// GlobalLock counts by handle.
    pub global_locks: BTreeMap<u64, u32>,
    /// Mapped views: view address -> mapping index.
    pub views: BTreeMap<u64, usize>,
}

impl Default for K32State {
    fn default() -> Self {
        K32State {
            cp_in: 437,
            cp_out: 437,
            unhandled_filter: 0,
            error_mode: 0,
            fls_callbacks: Vec::new(),
            fls_used: Vec::new(),
            tls_used: vec![false; 64],
            process_heap: 0,
            console_modes: [0x7, 0x3, 0x3],
            ctrl_handlers: Vec::new(),
            init_once: BTreeMap::new(),
            srw: BTreeMap::new(),
            cv: BTreeMap::new(),
            mappings: Vec::new(),
            names: BTreeMap::new(),
            dll_handles: Vec::new(),
            start: Instant::now(),
            global_locks: BTreeMap::new(),
            views: BTreeMap::new(),
        }
    }
}

/// Write `s` (ANSI bytes) into the guest buffer with the Win32 size rules:
/// returns the length without the NUL when it fits, or the required size
/// (with NUL) when the buffer is too small.
pub(crate) fn copy_ansi_out(ctx: &mut ApiCtx, buf: u64, size: u64, s: &[u8]) -> Result<u64> {
    let need = s.len() as u64 + 1;
    if buf == 0 || size < need {
        return Ok(need);
    }
    let mut data = s.to_vec();
    data.push(0);
    ctx.put(buf, &data)?;
    Ok(s.len() as u64)
}

/// Wide counterpart of [`copy_ansi_out`] (sizes in UTF-16 units).
pub(crate) fn copy_wide_out(ctx: &mut ApiCtx, buf: u64, size: u64, s: &[u16]) -> Result<u64> {
    let need = s.len() as u64 + 1;
    if buf == 0 || size < need {
        return Ok(need);
    }
    ctx.put_wide(buf, s)?;
    ctx.wr(buf + 2 * s.len() as u64, 2, 0)?;
    Ok(s.len() as u64)
}

fn get_last_error(ctx: &mut ApiCtx) -> Result<()> {
    let e = ctx.last_error();
    ctx.ret(e as u64);
    Ok(())
}

fn set_last_error(ctx: &mut ApiCtx) -> Result<()> {
    let e = ctx.au(0);
    ctx.set_last_error(e);
    Ok(())
}

fn exit_process(ctx: &mut ApiCtx) -> Result<()> {
    let code = ctx.au(0) as u64;
    cont::finish_process(ctx, code);
    Ok(())
}

fn terminate_process(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let code = ctx.au(1) as u64;
    if h == PSEUDO_PROCESS {
        cont::finish_process(ctx, code);
        return Ok(());
    }
    ctx.set_last_error(ERROR_INVALID_HANDLE);
    ctx.ret_bool(false);
    Ok(())
}

fn get_current_process(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(PSEUDO_PROCESS);
    Ok(())
}

fn get_current_process_id(ctx: &mut ApiCtx) -> Result<()> {
    let pid = ctx.p.pid as u64;
    ctx.ret(pid);
    Ok(())
}

fn get_exit_code_process(ctx: &mut ApiCtx) -> Result<()> {
    let (h, out) = (ctx.a(0), ctx.a(1));
    if h != PSEUDO_PROCESS {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.wr(out, 4, STILL_ACTIVE as u64)?;
    ctx.ret_bool(true);
    Ok(())
}

fn get_command_line_a(ctx: &mut ApiCtx) -> Result<()> {
    let cmd = ctx.cmd_line.clone();
    let p = ctx.intern_cstr(&cmd[..cmd.iter().position(|b| *b == 0).unwrap_or(cmd.len())])?;
    ctx.ret(p);
    Ok(())
}

fn get_command_line_w(ctx: &mut ApiCtx) -> Result<()> {
    let text = String::from_utf8_lossy(&ctx.cmd_line.clone()).into_owned();
    let units: Vec<u16> = text.trim_end_matches('\0').encode_utf16().collect();
    let p = ctx.intern_wstr(&units)?;
    ctx.ret(p);
    Ok(())
}

/// STARTUPINFO (cb = 104 on 64-bit Windows).
fn get_startup_info(ctx: &mut ApiCtx, wide: bool) -> Result<()> {
    let _ = wide;
    let p = ctx.a(0);
    ctx.zero(p, 104)?;
    ctx.wr(p, 4, 104)?;
    ctx.wr(p + 64, 2, 10)?; // wShowWindow = SW_SHOWDEFAULT
    Ok(())
}

fn get_startup_info_a(ctx: &mut ApiCtx) -> Result<()> {
    get_startup_info(ctx, false)
}

fn get_startup_info_w(ctx: &mut ApiCtx) -> Result<()> {
    get_startup_info(ctx, true)
}

fn get_environment_variable_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let (buf, size) = (ctx.a(1), ctx.a(2));
    match ctx.p.env.get(&name).map(|v| v.as_bytes().to_vec()) {
        Some(v) => {
            let r = copy_ansi_out(ctx, buf, size, &v)?;
            ctx.ret(r);
        }
        None => {
            ctx.set_last_error(ERROR_ENVVAR_NOT_FOUND);
            ctx.ret(0);
        }
    }
    Ok(())
}

fn get_environment_variable_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.wstr_string(ctx.a(0))?;
    let (buf, size) = (ctx.a(1), ctx.a(2));
    match ctx
        .p
        .env
        .get(&name)
        .map(|v| v.encode_utf16().collect::<Vec<u16>>())
    {
        Some(v) => {
            let r = copy_wide_out(ctx, buf, size, &v)?;
            ctx.ret(r);
        }
        None => {
            ctx.set_last_error(ERROR_ENVVAR_NOT_FOUND);
            ctx.ret(0);
        }
    }
    Ok(())
}

fn set_environment_variable_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let vp = ctx.a(1);
    let value = if vp == 0 {
        None
    } else {
        Some(ctx.cstr_string(vp)?)
    };
    if name.is_empty() || name.contains('=') {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.env.set(&name, value.as_deref());
    ctx.ret_bool(true);
    Ok(())
}

fn set_environment_variable_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.wstr_string(ctx.a(0))?;
    let vp = ctx.a(1);
    let value = if vp == 0 {
        None
    } else {
        Some(ctx.wstr_string(vp)?)
    };
    if name.is_empty() || name.contains('=') {
        ctx.set_last_error(ERROR_INVALID_PARAMETER);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.env.set(&name, value.as_deref());
    ctx.ret_bool(true);
    Ok(())
}

/// Replace `%NAME%` references with environment values; unknown names are
/// kept verbatim (as Windows does).
fn expand(env: &crate::env::Env, src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                match env.get(name) {
                    Some(v) if !name.is_empty() => out.push_str(v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
            None => {
                out.push_str(&rest[i..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn expand_environment_strings_a(ctx: &mut ApiCtx) -> Result<()> {
    let src = ctx.cstr_string(ctx.a(0))?;
    let text = expand(&ctx.p.env, &src);
    let (buf, size) = (ctx.a(1), ctx.a(2));
    let r = copy_ansi_out(ctx, buf, size, text.as_bytes())?;
    ctx.ret(r);
    Ok(())
}

fn expand_environment_strings_w(ctx: &mut ApiCtx) -> Result<()> {
    let src = ctx.wstr_string(ctx.a(0))?;
    let text = expand(&ctx.p.env, &src);
    let units: Vec<u16> = text.encode_utf16().collect();
    let (buf, size) = (ctx.a(1), ctx.a(2));
    let r = copy_wide_out(ctx, buf, size, &units)?;
    ctx.ret(r);
    Ok(())
}

/// Environment block: `NAME=value\0...\0\0`, allocated on the process heap.
fn environment_block(ctx: &mut ApiCtx, wide: bool) -> Result<()> {
    let entries = ctx.p.env.entries();
    let mut units: Vec<u16> = Vec::new();
    for e in &entries {
        if wide {
            units.extend(e.encode_utf16());
        } else {
            units.extend(e.bytes().map(|b| b as u16));
        }
        units.push(0);
    }
    units.push(0);
    let bytes = if wide { 2 } else { 1 } * units.len() as u64;
    let p = heap::alloc(ctx, 0, bytes, 16, false)?;
    if p == 0 {
        ctx.set_last_error(8);
        ctx.ret(0);
        return Ok(());
    }
    if wide {
        ctx.put_wide(p, &units)?;
    } else {
        let narrow: Vec<u8> = units.iter().map(|u| *u as u8).collect();
        ctx.put(p, &narrow)?;
    }
    ctx.ret(p);
    Ok(())
}

fn get_environment_strings_w(ctx: &mut ApiCtx) -> Result<()> {
    environment_block(ctx, true)
}

fn get_environment_strings_a(ctx: &mut ApiCtx) -> Result<()> {
    environment_block(ctx, false)
}

fn free_environment_strings(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let ok = heap::free(ctx, 0, p);
    ctx.ret_bool(ok);
    Ok(())
}

/// Base name of a module path, lower-cased, without the `.exe` extension.
fn module_key(path: &str) -> String {
    let base = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(|s| s.to_string())
        .unwrap_or(base)
}

/// Module handle for a system DLL name (allocated on first use).
fn dll_handle(ctx: &mut ApiCtx, name: &str) -> u64 {
    let key = name.to_ascii_lowercase();
    let idx = match ctx.p.k32.dll_handles.iter().position(|n| *n == key) {
        Some(i) => i,
        None => {
            ctx.p.k32.dll_handles.push(key);
            ctx.p.k32.dll_handles.len() - 1
        }
    };
    DLL_HANDLE_BASE + idx as u64 * DLL_HANDLE_STRIDE
}

/// DLL name behind a module handle from [`dll_handle`].
fn dll_of_handle(ctx: &ApiCtx, h: u64) -> Option<String> {
    if h < DLL_HANDLE_BASE {
        return None;
    }
    let idx = ((h - DLL_HANDLE_BASE) / DLL_HANDLE_STRIDE) as usize;
    ctx.p.k32.dll_handles.get(idx).cloned()
}

/// Names of the DLLs whose exports this runtime provides.
fn is_hosted_dll(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let n = n.strip_suffix(".dll").unwrap_or(&n).to_string();
    matches!(
        n.as_str(),
        "kernel32" | "kernelbase" | "ntdll" | "ucrtbase" | "msvcrt" | "vcruntime140" | "shell32"
    ) || n.starts_with("api-ms-win-")
        || n.starts_with("ext-ms-win-")
        || n.starts_with("vcruntime140")
}

fn get_module_handle_common(ctx: &mut ApiCtx, name: Option<String>) -> Result<()> {
    let Some(name) = name else {
        let base = ctx.image_base;
        ctx.ret(base);
        return Ok(());
    };
    let key = module_key(&name);
    if let Some(m) = ctx.modules.first() {
        if module_key(&m.path) == key {
            let base = m.base;
            ctx.ret(base);
            return Ok(());
        }
    }
    if is_hosted_dll(&name) {
        let h = dll_handle(ctx, &name);
        ctx.ret(h);
        return Ok(());
    }
    ctx.set_last_error(ERROR_MOD_NOT_FOUND);
    ctx.ret(0);
    Ok(())
}

fn get_module_handle_a(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let name = if p == 0 {
        None
    } else {
        Some(ctx.cstr_string(p)?)
    };
    get_module_handle_common(ctx, name)
}

fn get_module_handle_w(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let name = if p == 0 {
        None
    } else {
        Some(ctx.wstr_string(p)?)
    };
    get_module_handle_common(ctx, name)
}

fn module_path(ctx: &ApiCtx, h: u64) -> Option<String> {
    if h == 0 || h == ctx.image_base {
        return Some(
            ctx.modules
                .first()
                .map(|m| m.path.clone())
                .unwrap_or_else(|| "guest.exe".to_string()),
        );
    }
    if let Some(m) = ctx.modules.iter().find(|m| m.base == h) {
        return Some(m.path.clone());
    }
    dll_of_handle(ctx, h).map(|n| format!("C:\\Windows\\System32\\{n}.dll"))
}

fn get_module_file_name_common(
    ctx: &mut ApiCtx,
    h: u64,
    buf: u64,
    size: u64,
    wide: bool,
) -> Result<()> {
    let Some(path) = module_path(ctx, h) else {
        ctx.set_last_error(ERROR_MOD_NOT_FOUND);
        ctx.ret(0);
        return Ok(());
    };
    let win = path.replace('/', "\\");
    if wide {
        let units: Vec<u16> = win.encode_utf16().collect();
        if buf != 0 && size as usize <= units.len() {
            // truncated: copy what fits and report ERROR_INSUFFICIENT_BUFFER
            let fit = size as usize;
            ctx.put_wide(buf, &units[..fit])?;
            ctx.set_last_error(ERROR_INSUFFICIENT_BUFFER);
            ctx.ret(size);
            return Ok(());
        }
        let r = copy_wide_out(ctx, buf, size, &units)?;
        ctx.ret(r);
    } else {
        let bytes = win.as_bytes().to_vec();
        if buf != 0 && size as usize <= bytes.len() {
            let fit = size as usize;
            ctx.put(buf, &bytes[..fit])?;
            ctx.set_last_error(ERROR_INSUFFICIENT_BUFFER);
            ctx.ret(size);
            return Ok(());
        }
        let r = copy_ansi_out(ctx, buf, size, &bytes)?;
        ctx.ret(r);
    }
    Ok(())
}

fn get_module_file_name_a(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, size) = (ctx.a(0), ctx.a(1), ctx.a(2));
    get_module_file_name_common(ctx, h, buf, size, false)
}

fn get_module_file_name_w(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, size) = (ctx.a(0), ctx.a(1), ctx.a(2));
    get_module_file_name_common(ctx, h, buf, size, true)
}

fn load_library_common(ctx: &mut ApiCtx, name: String) -> Result<()> {
    if module_key(&name)
        == module_key(
            &ctx.modules
                .first()
                .map(|m| m.path.clone())
                .unwrap_or_default(),
        )
    {
        let base = ctx.image_base;
        ctx.ret(base);
        return Ok(());
    }
    if is_hosted_dll(&name) {
        let h = dll_handle(ctx, &name);
        ctx.ret(h);
        return Ok(());
    }
    ctx.set_last_error(ERROR_MOD_NOT_FOUND);
    ctx.ret(0);
    Ok(())
}

fn load_library_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    load_library_common(ctx, name)
}

fn load_library_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.wstr_string(ctx.a(0))?;
    load_library_common(ctx, name)
}

fn free_library(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_bool(true);
    Ok(())
}

fn get_proc_address(ctx: &mut ApiCtx) -> Result<()> {
    let (h, name_p) = (ctx.a(0), ctx.a(1));
    if name_p < 0x10000 {
        // ordinal imports are not provided by the hosted DLLs
        ctx.set_last_error(ERROR_PROC_NOT_FOUND);
        ctx.ret(0);
        return Ok(());
    }
    let name = ctx.cstr_string(name_p)?;
    if h == ctx.image_base
        || (h == 0 && ctx.modules.is_empty())
        || ctx.modules.iter().any(|m| m.base == h)
    {
        let hit = ctx
            .modules
            .iter()
            .find(|m| m.base == h || (h == ctx.image_base && m.base == ctx.image_base))
            .and_then(|m| {
                m.exports
                    .iter()
                    .find(|(n, _)| n == &name)
                    .map(|(_, va)| *va)
            });
        match hit {
            Some(va) => ctx.ret(va),
            None => {
                ctx.set_last_error(ERROR_PROC_NOT_FOUND);
                ctx.ret(0);
            }
        }
        return Ok(());
    }
    let Some(dll) = dll_of_handle(ctx, h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret(0);
        return Ok(());
    };
    let found = ctx.api.and_then(|api| api.resolve(&dll, &name));
    match found {
        Some(id) => {
            let addr = crate::gateway::addr_of(id);
            ctx.ret(addr);
        }
        None => {
            ctx.set_last_error(ERROR_PROC_NOT_FOUND);
            ctx.ret(0);
        }
    }
    Ok(())
}

fn close_handle(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    if h == PSEUDO_THREAD || h == PSEUDO_PROCESS {
        ctx.ret_bool(true);
        return Ok(());
    }
    match ctx.p.handles.close(h) {
        Some(_) => ctx.ret_bool(true),
        None => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn duplicate_handle(ctx: &mut ApiCtx) -> Result<()> {
    // (src_proc, src, dst_proc, dst*, access, inherit, options)
    let (src_proc, src, dst_proc, dst_ptr, options) =
        (ctx.a(0), ctx.a(1), ctx.a(2), ctx.a(3), ctx.au(6));
    if src_proc != PSEUDO_PROCESS || dst_proc != PSEUDO_PROCESS {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    }
    let new = if src == PSEUDO_THREAD {
        let tid = ctx.p.sched.cur_tid();
        ctx.p.handles.insert(Obj::Thread(tid))
    } else if src == PSEUDO_PROCESS {
        ctx.p.handles.insert(Obj::Thread(0))
    } else {
        match ctx.p.handles.get(src) {
            Some(r) => ctx.p.handles.insert_ref(r),
            None => {
                ctx.set_last_error(ERROR_INVALID_HANDLE);
                ctx.ret_bool(false);
                return Ok(());
            }
        }
    };
    if options & 1 != 0 && src != PSEUDO_THREAD && src != PSEUDO_PROCESS {
        ctx.p.handles.close(src);
    }
    if dst_ptr != 0 {
        ctx.wr(dst_ptr, 8, new)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn get_std_handle(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.au(0);
    let idx = match n {
        0xFFFF_FFF6 => 0,
        0xFFFF_FFF5 => 1,
        0xFFFF_FFF4 => 2,
        _ => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret(INVALID_HANDLE);
            return Ok(());
        }
    };
    let h = ctx.p.handles.std_handle(idx);
    ctx.ret(h);
    Ok(())
}

fn set_std_handle(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.au(0);
    let h = ctx.a(1);
    let idx = match n {
        0xFFFF_FFF6 => 0,
        0xFFFF_FFF5 => 1,
        0xFFFF_FFF4 => 2,
        _ => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER);
            ctx.ret_bool(false);
            return Ok(());
        }
    };
    ctx.p.handles.set_std_handle(idx, h);
    ctx.ret_bool(true);
    Ok(())
}

fn set_console_ctrl_handler(ctx: &mut ApiCtx) -> Result<()> {
    let (f, add) = (ctx.a(0), ctx.au(1) != 0);
    if add {
        ctx.p.k32.ctrl_handlers.push(f);
    } else {
        ctx.p.k32.ctrl_handlers.retain(|h| *h != f);
    }
    ctx.ret_bool(true);
    Ok(())
}

fn is_debugger_present(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_bool(false);
    Ok(())
}

fn output_debug_string_common(text: String) {
    use std::io::Write;
    let mut e = std::io::stderr().lock();
    let _ = e.write_all(text.as_bytes());
    let _ = e.flush();
}

fn output_debug_string_a(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.cstr_string(ctx.a(0))?;
    output_debug_string_common(s);
    Ok(())
}

fn output_debug_string_w(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.wstr_string(ctx.a(0))?;
    output_debug_string_common(s);
    Ok(())
}

fn debug_break(ctx: &mut ApiCtx) -> Result<()> {
    // STATUS_BREAKPOINT with no debugger attached terminates the process.
    cont::finish_process(ctx, 0x8000_0003);
    Ok(())
}

fn set_error_mode(ctx: &mut ApiCtx) -> Result<()> {
    let new = ctx.au(0);
    let prev = std::mem::replace(&mut ctx.p.k32.error_mode, new);
    ctx.ret(prev as u64);
    Ok(())
}

fn get_error_mode(ctx: &mut ApiCtx) -> Result<()> {
    let m = ctx.p.k32.error_mode;
    ctx.ret(m as u64);
    Ok(())
}

fn flush_instruction_cache(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret_bool(true);
    Ok(())
}

fn get_console_window(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(0);
    Ok(())
}

fn get_acp(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(1252);
    Ok(())
}

fn get_oemcp(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(437);
    Ok(())
}

fn is_valid_code_page(ctx: &mut ApiCtx) -> Result<()> {
    let cp = ctx.au(0);
    ctx.ret_bool(crate::k32_file::valid_code_page(cp));
    Ok(())
}

fn get_user_default_lcid(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(0x409);
    Ok(())
}

fn lstrlen_a(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let n = if p == 0 { 0 } else { ctx.cstr(p)?.len() };
    ctx.ret_i32(n as i32);
    Ok(())
}

fn lstrlen_w(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    let n = if p == 0 { 0 } else { ctx.wstr(p)?.len() };
    ctx.ret_i32(n as i32);
    Ok(())
}

/// FILETIME of "now" (100-ns intervals since 1601-01-01 UTC).
pub(crate) fn filetime_now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    FILETIME_EPOCH_DIFF + d.as_secs() * 10_000_000 + (d.subsec_nanos() / 100) as u64
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "kernel32",
        "GetLastError" => get_last_error,
        "SetLastError" => set_last_error,
        "ExitProcess" => exit_process,
        "TerminateProcess" => terminate_process,
        "GetCurrentProcess" => get_current_process,
        "GetCurrentProcessId" => get_current_process_id,
        "GetExitCodeProcess" => get_exit_code_process,
        "GetCommandLineA" => get_command_line_a,
        "GetCommandLineW" => get_command_line_w,
        "GetStartupInfoA" => get_startup_info_a,
        "GetStartupInfoW" => get_startup_info_w,
        "GetEnvironmentVariableA" => get_environment_variable_a,
        "GetEnvironmentVariableW" => get_environment_variable_w,
        "SetEnvironmentVariableA" => set_environment_variable_a,
        "SetEnvironmentVariableW" => set_environment_variable_w,
        "ExpandEnvironmentStringsA" => expand_environment_strings_a,
        "ExpandEnvironmentStringsW" => expand_environment_strings_w,
        "GetEnvironmentStringsA" => get_environment_strings_a,
        "GetEnvironmentStringsW" => get_environment_strings_w,
        "FreeEnvironmentStringsA" => free_environment_strings,
        "FreeEnvironmentStringsW" => free_environment_strings,
        "GetModuleHandleA" => get_module_handle_a,
        "GetModuleHandleW" => get_module_handle_w,
        "GetModuleFileNameA" => get_module_file_name_a,
        "GetModuleFileNameW" => get_module_file_name_w,
        "LoadLibraryA" => load_library_a,
        "LoadLibraryW" => load_library_w,
        "FreeLibrary" => free_library,
        "GetProcAddress" => get_proc_address,
        "CloseHandle" => close_handle,
        "DuplicateHandle" => duplicate_handle,
        "GetStdHandle" => get_std_handle,
        "SetStdHandle" => set_std_handle,
        "SetConsoleCtrlHandler" => set_console_ctrl_handler,
        "IsDebuggerPresent" => is_debugger_present,
        "OutputDebugStringA" => output_debug_string_a,
        "OutputDebugStringW" => output_debug_string_w,
        "DebugBreak" => debug_break,
        "SetErrorMode" => set_error_mode,
        "GetErrorMode" => get_error_mode,
        "FlushInstructionCache" => flush_instruction_cache,
        "GetConsoleWindow" => get_console_window,
        "GetACP" => get_acp,
        "GetOEMCP" => get_oemcp,
        "IsValidCodePage" => is_valid_code_page,
        "GetUserDefaultLCID" => get_user_default_lcid,
        "lstrlenA" => lstrlen_a,
        "lstrlenW" => lstrlen_w,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_keeps_unknown_names() {
        let env = crate::env::Env::from_host();
        let mut e = env;
        e.set("A64X_TEST_VAR", Some("hello"));
        assert_eq!(expand(&e, "x=%A64X_TEST_VAR%!"), "x=hello!");
        assert_eq!(expand(&e, "%NOPE_NOT_SET%"), "%NOPE_NOT_SET%");
        assert_eq!(expand(&e, "100%"), "100%");
    }

    #[test]
    fn module_keys_ignore_case_and_extension() {
        assert_eq!(module_key("C:\\x\\Guest.EXE"), "guest");
        assert_eq!(module_key("/tmp/guest"), "guest");
    }
}
