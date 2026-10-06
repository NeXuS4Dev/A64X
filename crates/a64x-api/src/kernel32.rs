//! kernel32 adapters — real native implementations (no emulation).

use crate::{arg, read_cstr, read_wstr, ret, win_shared, write_stdout, ApiCtx, ApiDef};
use a64x_core::Result;
use std::io::{Read, Write};

macro_rules! api {
    ($name:expr, $f:ident) => {
        ApiDef { dll: "kernel32", name: $name, f: $f }
    };
}

/// Table of kernel32 adapters (registered by [`crate::ApiLayer`]).
pub(crate) static TABLE: &[ApiDef] = &[
    api!("ExitProcess", exit_process),
    api!("TerminateProcess", terminate_process),
    api!("GetLastError", get_last_error),
    api!("SetLastError", set_last_error),
    api!("GetStdHandle", get_std_handle),
    api!("SetStdHandle", set_std_handle),
    api!("WriteFile", write_file),
    api!("WriteConsoleA", write_console_a),
    api!("WriteConsoleW", write_console_w),
    api!("ReadFile", read_file),
    api!("CloseHandle", close_handle),
    api!("CreateFileA", create_file_a),
    api!("CreateFileW", create_file_w),
    api!("GetCommandLineA", get_command_line_a),
    api!("GetCommandLineW", get_command_line_w),
    api!("GetModuleHandleA", get_module_handle),
    api!("GetModuleHandleW", get_module_handle),
    api!("GetModuleHandleExW", get_module_handle),
    api!("LoadLibraryA", load_library),
    api!("LoadLibraryW", load_library),
    api!("LoadLibraryExW", load_library),
    api!("GetProcAddress", get_proc_address),
    api!("FreeLibrary", success_one),
    api!("GetProcessHeap", get_process_heap),
    api!("HeapAlloc", heap_alloc),
    api!("HeapFree", heap_free),
    api!("HeapReAlloc", heap_realloc),
    api!("HeapSize", heap_size),
    api!("VirtualAlloc", virtual_alloc),
    api!("VirtualFree", success_one),
    api!("Sleep", sleep),
    api!("GetTickCount", get_tick_count),
    api!("GetTickCount64", get_tick_count),
    api!("QueryPerformanceCounter", query_performance_counter),
    api!("QueryPerformanceFrequency", query_performance_frequency),
    api!("GetSystemTimeAsFileTime", get_system_time_as_file_time),
    api!("IsProcessorFeaturePresent", success_one),
    api!("IsDebuggerPresent", success_zero),
    api!("GetCurrentProcess", get_current_process),
    api!("GetCurrentProcessId", get_current_process_id),
    api!("GetCurrentThreadId", get_current_thread_id),
    api!("FlushFileBuffers", success_one),
    api!("GetConsoleMode", get_console_mode),
    api!("SetConsoleMode", set_console_mode),
    api!("GetFileType", get_file_type),
    api!("InitializeCriticalSection", success_void),
    api!("EnterCriticalSection", success_void),
    api!("LeaveCriticalSection", success_void),
    api!("DeleteCriticalSection", success_void),
    api!("TlsAlloc", tls_alloc),
    api!("TlsGetValue", tls_get_value),
    api!("TlsSetValue", tls_set_value),
    api!("TlsFree", success_one),
    api!("SetUnhandledExceptionFilter", success_zero),
    api!("UnhandledExceptionFilter", success_one),
    api!("RaiseException", raise_exception),
    api!("GetStartupInfoA", get_startup_info_a),
    api!("GetStartupInfoW", get_startup_info_w),
    api!("GetEnvironmentVariableA", get_environment_variable_a),
    api!("GetEnvironmentVariableW", get_environment_variable_w),
    api!("MultiByteToWideChar", multi_byte_to_wide_char),
    api!("WideCharToMultiByte", wide_char_to_multi_byte),
];

fn io_err(e: std::io::Error) -> a64x_core::Error {
    a64x_core::Error::Host(format!("host io: {e}"))
}

fn success_one(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 1);
    Ok(())
}
fn success_zero(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 0);
    Ok(())
}
fn success_void(ctx: &mut ApiCtx) -> Result<()> {
    let _ = ctx;
    Ok(())
}

fn exit_process(ctx: &mut ApiCtx) -> Result<()> {
    ctx.state.exit_code = arg(ctx.state, 0);
    ctx.state.exit_reason = a64x_core::ExitReason::Exited as u8;
    ctx.state.running = 0;
    Ok(())
}

fn terminate_process(ctx: &mut ApiCtx) -> Result<()> {
    ctx.state.exit_code = arg(ctx.state, 1);
    ctx.state.exit_reason = a64x_core::ExitReason::Exited as u8;
    ctx.state.running = 0;
    Ok(())
}

fn get_last_error(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, ctx.state.last_error);
    Ok(())
}

fn set_last_error(ctx: &mut ApiCtx) -> Result<()> {
    ctx.state.last_error = arg(ctx.state, 0);
    Ok(())
}

fn get_std_handle(ctx: &mut ApiCtx) -> Result<()> {
    let n = arg(ctx.state, 0) as u32;
    let h = match n.wrapping_neg() {
        10 => win_shared::H_STDIN,
        11 => win_shared::H_STDOUT,
        12 => win_shared::H_STDERR,
        _ => u64::MAX,
    };
    ret(ctx.state, h);
    Ok(())
}

fn set_std_handle(ctx: &mut ApiCtx) -> Result<()> {
    success_one(ctx)
}

fn console_write(ctx: &mut ApiCtx, h: u64, buf: u64, len: u64) -> Result<u64> {
    let bytes = ctx.mem.slice(buf, len)?.to_vec();
    match h {
        win_shared::H_STDOUT => {
            write_stdout(&bytes);
            Ok(len)
        }
        win_shared::H_STDERR => {
            crate::write_stderr(&bytes);
            Ok(len)
        }
        _ => {
            if let Some(f) = file_of(ctx, h) {
                let n = f.write(&bytes).unwrap_or(0) as u64;
                let _ = f.flush();
                Ok(n)
            } else {
                ctx.state.last_error = 6; // ERROR_INVALID_HANDLE
                Ok(0)
            }
        }
    }
}

fn write_file(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, len, written) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2), arg(ctx.state, 3));
    let n = console_write(ctx, h, buf, len)?;
    if written != 0 {
        ctx.mem.write_int(written, 4, n.min(0xFFFF_FFFF))?;
    }
    ret(ctx.state, (n == len || n != 0) as u64);
    Ok(())
}

fn write_console_a(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, len, written) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2), arg(ctx.state, 3));
    let n = console_write(ctx, h, buf, len)?;
    if written != 0 {
        ctx.mem.write_int(written, 4, n)?;
    }
    ret(ctx.state, 1);
    Ok(())
}

fn write_console_w(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, len, written) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2), arg(ctx.state, 3));
    let units = ctx.mem.slice(buf, len * 2)?.to_vec();
    let s: Vec<u16> = units.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let text = String::from_utf16_lossy(&s);
    let bytes = text.as_bytes().to_vec();
    match h {
        win_shared::H_STDERR => crate::write_stderr(&bytes),
        _ => write_stdout(&bytes),
    }
    if written != 0 {
        ctx.mem.write_int(written, 4, len)?;
    }
    ret(ctx.state, 1);
    Ok(())
}

fn read_file(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, len, read_out) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2), arg(ctx.state, 3));
    let n: u64 = if h == win_shared::H_STDIN {
        let mut tmp = vec![0u8; (len as usize).min(1 << 20)];
        let got = std::io::stdin().lock().read(&mut tmp).map_err(io_err)? as u64;
        ctx.mem.write(buf, &tmp[..got as usize])?;
        got
    } else if let Some(f) = file_of(ctx, h) {
        let mut tmp = vec![0u8; (len as usize).min(1 << 24)];
        let got = f.read(&mut tmp).map_err(io_err)? as u64;
        ctx.mem.write(buf, &tmp[..got as usize])?;
        got
    } else {
        ctx.state.last_error = 6;
        ret(ctx.state, 0);
        return Ok(());
    };
    if read_out != 0 {
        ctx.mem.write_int(read_out, 4, n)?;
    }
    ret(ctx.state, 1);
    Ok(())
}

fn file_of<'a>(ctx: &'a mut ApiCtx, h: u64) -> Option<&'a mut std::fs::File> {
    let idx = ctx.handles.iter().position(|slot| slot.0 == h)?;
    let Some((_, crate::Handle::File(f))) = ctx.handles.get_mut(idx) else { return None };
    Some(f)
}

fn open_with_disposition(path: &str, access: u32, disposition: u32) -> std::io::Result<std::fs::File> {
    // GENERIC_READ 0x80000000 / GENERIC_WRITE 0x40000000
    let want_read = access & 0x8000_0000 != 0 || access == 0;
    let want_write = access & 0x4000_0000 != 0;
    let mut o = std::fs::OpenOptions::new();
    match disposition {
        1 => {
            o.create_new(true).write(true);
        } // CREATE_NEW
        2 => {
            o.create(true).truncate(true).write(true).read(true);
        } // CREATE_ALWAYS
        3 => {
            o.read(want_read).write(want_write);
        } // OPEN_EXISTING
        4 => {
            o.create(true).read(true).write(want_write || want_read);
        } // OPEN_ALWAYS
        5 => {
            o.truncate(true).write(true).read(true);
        } // TRUNCATE_EXISTING
        _ => {
            o.read(want_read).write(want_write);
        }
    }
    o.open(path)
}

fn create_file_common(ctx: &mut ApiCtx, name: &str) -> Result<()> {
    let (access, _share, _sec, disposition, _flags, _template) =
        (arg(ctx.state, 1) as u32, arg(ctx.state, 2), arg(ctx.state, 3), arg(ctx.state, 4) as u32, arg(ctx.state, 5), arg(ctx.state, 6));
    match open_with_disposition(name, access, disposition) {
        Ok(f) => {
            let h = ctx.next_file_handle;
            ctx.next_file_handle += 1;
            ctx.handles.push((h, crate::Handle::File(f)));
            ret(ctx.state, h);
        }
        Err(e) => {
            ctx.state.last_error = e.raw_os_error().unwrap_or(2) as u64;
            ret(ctx.state, u64::MAX); // INVALID_HANDLE_VALUE
        }
    }
    Ok(())
}

fn create_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = read_cstr(ctx, arg(ctx.state, 0), 4096);
    let name = String::from_utf8_lossy(&name).into_owned();
    create_file_common(ctx, &name)
}

fn create_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = read_wstr(ctx, arg(ctx.state, 0), 4096);
    create_file_common(ctx, &name)
}

fn close_handle(ctx: &mut ApiCtx) -> Result<()> {
    let h = arg(ctx.state, 0);
    if h >= 0x30 {
        if let Some(idx) = ctx.handles.iter().position(|slot| slot.0 == h) {
            ctx.handles.swap_remove(idx);
        }
    }
    ret(ctx.state, 1);
    Ok(())
}

fn get_command_line_a(ctx: &mut ApiCtx) -> Result<()> {
    let addr = win_shared::STRINGS_BASE;
    let bytes = ctx.cmd_line.clone();
    ctx.mem.write_cstr(addr, &bytes)?;
    ret(ctx.state, addr);
    Ok(())
}

fn get_command_line_w(ctx: &mut ApiCtx) -> Result<()> {
    let addr = win_shared::STRINGS_BASE;
    let text = String::from_utf8_lossy(&ctx.cmd_line).into_owned();
    let units: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    ctx.mem.write(addr, &bytes)?;
    ret(ctx.state, addr);
    Ok(())
}

fn get_module_handle(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, ctx.image_base);
    Ok(())
}

fn load_library(ctx: &mut ApiCtx) -> Result<()> {
    let a = arg(ctx.state, 0);
    let name_bytes = read_cstr(ctx, a, 256);
    let name = String::from_utf8_lossy(&name_bytes).to_ascii_lowercase();
    let known = ["kernel32", "msvcrt", "ucrtbase", "vcruntime140", "vcruntime140_1", "api-ms-win"];
    if known.iter().any(|k| name.contains(k)) || name.is_empty() {
        // pseudo HMODULE; identifies nothing the guest should dereference
        ret(ctx.state, a64x_core::memory::GATEWAY_BASE | 0xF000_0000);
    } else {
        ctx.state.last_error = 126; // ERROR_MOD_NOT_FOUND
        ret(ctx.state, 0);
    }
    Ok(())
}

fn get_proc_address(ctx: &mut ApiCtx) -> Result<()> {
    let name_ptr = arg(ctx.state, 1);
    if name_ptr < 0x1_0000 {
        // ordinal — unsupported in the portable layer
        ctx.state.last_error = 127;
        ret(ctx.state, 0);
        return Ok(());
    }
    let name = read_cstr(ctx, name_ptr, 256);
    let name = String::from_utf8_lossy(&name).into_owned();
    let hit = ctx.api.and_then(|api| {
        ["kernel32", "msvcrt", "ucrtbase"]
            .iter()
            .find_map(|dll| api.resolve(dll, &name).map(crate::gateway::addr_of))
    });
    match hit {
        Some(addr) => ret(ctx.state, addr),
        None => {
            ctx.state.last_error = 127;
            ret(ctx.state, 0);
        }
    }
    Ok(())
}

fn get_process_heap(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 0x1); // pseudo heap handle
    Ok(())
}

fn heap_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let flags = arg(ctx.state, 1);
    let size = arg(ctx.state, 2);
    let addr = ctx.alloc_heap(size, 8);
    if flags & 0x8 != 0 {
        // HEAP_ZERO_MEMORY
        ctx.mem.zero(addr, size)?;
    }
    ret(ctx.state, addr);
    Ok(())
}

fn heap_realloc(ctx: &mut ApiCtx) -> Result<()> {
    let old = arg(ctx.state, 2);
    let size = arg(ctx.state, 3);
    let new_addr = ctx.alloc_heap(size, 8);
    // conservative copy: 64 KiB max or the new size, whichever smaller
    let n = size.min(1 << 16);
    if n > 0 {
        let mut tmp = vec![0u8; n as usize];
        let _ = ctx.mem.read(old, &mut tmp);
        let _ = ctx.mem.write(new_addr, &tmp);
    }
    ret(ctx.state, new_addr);
    Ok(())
}

fn heap_free(ctx: &mut ApiCtx) -> Result<()> {
    success_one(ctx)
}

fn heap_size(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 1 << 16);
    Ok(())
}

fn virtual_alloc(ctx: &mut ApiCtx) -> Result<()> {
    let size = arg(ctx.state, 1).max(1).min(ctx.mem.size() / 4);
    let alloc_type = arg(ctx.state, 2);
    if alloc_type & 0x2000 != 0 && arg(ctx.state, 0) != 0 {
        // MEM_RESERVE|COMMIT at a specific address
        let addr = arg(ctx.state, 0);
        let _ = ctx.mem.zero(addr, size);
        ret(ctx.state, addr);
    } else {
        let addr = ctx.alloc_heap((size + 0xFFF) & !0xFFF, 0x1000);
        ret(ctx.state, addr);
    }
    Ok(())
}

fn sleep(ctx: &mut ApiCtx) -> Result<()> {
    let ms = arg(ctx.state, 0).min(10_000);
    std::thread::sleep(core::time::Duration::from_millis(ms));
    Ok(())
}

fn millis_start() -> &'static std::time::Instant {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START.get_or_init(std::time::Instant::now)
}

fn get_tick_count(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, millis_start().elapsed().as_millis() as u64);
    Ok(())
}

fn query_performance_counter(ctx: &mut ApiCtx) -> Result<()> {
    let ctr_ptr = arg(ctx.state, 0);
    let v = millis_start().elapsed().as_nanos() as u64 / 100 * 10; // ~10MHz
    ctx.mem.write_int(ctr_ptr, 8, v)?;
    ret(ctx.state, 1);
    Ok(())
}

fn query_performance_frequency(ctx: &mut ApiCtx) -> Result<()> {
    let freq_ptr = arg(ctx.state, 0);
    ctx.mem.write_int(freq_ptr, 8, 10_000_000)?;
    ret(ctx.state, 1);
    Ok(())
}

fn get_system_time_as_file_time(ctx: &mut ApiCtx) -> Result<()> {
    let out_ptr = arg(ctx.state, 0);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    // FILETIME = 100-ns intervals since 1601-01-01 (11644473600s offset)
    let ft = (now.as_secs() + 11_644_473_600) * 10_000_000 + (now.subsec_nanos() / 100) as u64;
    ctx.mem.write_int(out_ptr, 8, ft)?;
    Ok(())
}

fn get_current_process(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, u64::MAX); // pseudo handle
    Ok(())
}
fn get_current_process_id(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 4242);
    Ok(())
}
fn get_current_thread_id(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 7);
    Ok(())
}

fn get_console_mode(ctx: &mut ApiCtx) -> Result<()> {
    let out = arg(ctx.state, 1);
    if out != 0 {
        ctx.mem.write_int(out, 4, 3)?;
    }
    ret(ctx.state, 1);
    Ok(())
}
fn set_console_mode(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 1);
    Ok(())
}

fn get_file_type(ctx: &mut ApiCtx) -> Result<()> {
    let h = arg(ctx.state, 0);
    let t = match h {
        win_shared::H_STDIN | win_shared::H_STDOUT | win_shared::H_STDERR => 2, // FILE_TYPE_CHAR
        _ => {
            if file_of(ctx, h).is_some() {
                1 // FILE_TYPE_DISK
            } else {
                0
            }
        }
    };
    ret(ctx.state, t);
    Ok(())
}

fn tls_alloc(ctx: &mut ApiCtx) -> Result<()> {
    if ctx.tls_used >= 64 {
        ret(ctx.state, u32::MAX as u64);
    } else {
        let i = ctx.tls_used as usize;
        ctx.tls[i] = 0;
        ctx.tls_used += 1;
        ret(ctx.state, i as u64);
    }
    Ok(())
}
fn tls_get_value(ctx: &mut ApiCtx) -> Result<()> {
    let i = arg(ctx.state, 0) as usize;
    ret(ctx.state, ctx.tls.get(i).copied().unwrap_or(0));
    Ok(())
}
fn tls_set_value(ctx: &mut ApiCtx) -> Result<()> {
    let i = arg(ctx.state, 0) as usize;
    if i < 64 {
        ctx.tls[i] = arg(ctx.state, 1);
    }
    ret(ctx.state, 1);
    Ok(())
}

fn raise_exception(ctx: &mut ApiCtx) -> Result<()> {
    let code = arg(ctx.state, 0);
    ctx.state.exit_code = code;
    ctx.state.exit_reason = a64x_core::ExitReason::Exited as u8;
    ctx.state.running = 0;
    ctx.exit_message = Some(format!("guest raised exception {code:#x}"));
    Ok(())
}

fn get_startup_info_a(ctx: &mut ApiCtx) -> Result<()> {
    let p = arg(ctx.state, 0);
    ctx.mem.zero(p, 68)?;
    ctx.mem.write_int(p, 4, 68)?;
    Ok(())
}
fn get_startup_info_w(ctx: &mut ApiCtx) -> Result<()> {
    let p = arg(ctx.state, 0);
    ctx.mem.zero(p, 104)?;
    ctx.mem.write_int(p, 4, 104)?;
    Ok(())
}

fn get_environment_variable_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = read_cstr(ctx, arg(ctx.state, 0), 256);
    let name = String::from_utf8_lossy(&name).into_owned();
    let buf = arg(ctx.state, 1);
    let size = arg(ctx.state, 2);
    let val = std::env::var(&name).unwrap_or_default();
    let need = val.len() as u64 + 1;
    if buf != 0 && need <= size {
        ctx.mem.write_cstr(buf, val.as_bytes())?;
    }
    ret(ctx.state, if val.is_empty() { 0 } else { need - 1 });
    if val.is_empty() {
        ctx.state.last_error = 203; // ERROR_ENVVAR_NOT_FOUND
    }
    Ok(())
}

fn get_environment_variable_w(ctx: &mut ApiCtx) -> Result<()> {
    success_zero(ctx)
}

fn multi_byte_to_wide_char(ctx: &mut ApiCtx) -> Result<()> {
    let (_cp, _flags, src, src_len, dst, dst_cap) = (
        arg(ctx.state, 0),
        arg(ctx.state, 1),
        arg(ctx.state, 2),
        arg(ctx.state, 3) as i32,
        arg(ctx.state, 4),
        arg(ctx.state, 5) as i32,
    );
    let bytes = if src_len < 0 {
        read_cstr(ctx, src, 1 << 16)
    } else {
        ctx.mem.slice(src, src_len.max(0) as u64)?.to_vec()
    };
    let units: Vec<u16> = String::from_utf8_lossy(&bytes).encode_utf16().collect();
    let with_term = if src_len < 0 { units.len() as i32 + 1 } else { units.len() as i32 };
    if dst == 0 || dst_cap == 0 {
        ret(ctx.state, with_term as u64);
        return Ok(());
    }
    let n = (units.len() as i32).min(dst_cap);
    let mut out = Vec::with_capacity((n as usize + 1) * 2);
    for u in units.iter().take(n as usize) {
        out.extend_from_slice(&u.to_le_bytes());
    }
    if src_len < 0 && (n as usize) > units.len().saturating_sub(0) {
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    ctx.mem.write(dst, &out)?;
    ret(ctx.state, with_term as u64);
    Ok(())
}

fn wide_char_to_multi_byte(ctx: &mut ApiCtx) -> Result<()> {
    let (_cp, _flags, src, src_len, dst, dst_cap) = (
        arg(ctx.state, 0),
        arg(ctx.state, 1),
        arg(ctx.state, 2),
        arg(ctx.state, 3) as i32,
        arg(ctx.state, 4),
        arg(ctx.state, 5) as i32,
    );
    let units = ctx.mem.read_wstr(src, if src_len < 0 { 1 << 16 } else { src_len as usize })?;
    let s = String::from_utf16_lossy(&units);
    let bytes = s.as_bytes();
    let need = if src_len < 0 { bytes.len() as i32 + 1 } else { bytes.len() as i32 };
    if dst == 0 || dst_cap == 0 {
        ret(ctx.state, need as u64);
        return Ok(());
    }
    let n = (bytes.len() as i32).min(dst_cap);
    ctx.mem.write(dst, &bytes[..n as usize])?;
    if src_len < 0 && (n as usize) < dst_cap as usize {
        ctx.mem.write_int(dst + n as u64, 1, 0)?;
    }
    ret(ctx.state, need as u64);
    Ok(())
}
