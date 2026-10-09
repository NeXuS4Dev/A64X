//! KERNEL32 file, directory, console and code-page functions.

use crate::handles::{FileObj, Obj};
use crate::k32_info::unix_to_filetime;
use crate::kernel32::{copy_ansi_out, copy_wide_out, ERROR_INVALID_HANDLE, INVALID_HANDLE};
use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;
use std::io::{Read, Seek, SeekFrom, Write};

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u64 = 0xFFFF_FFFF;
const FILE_TYPE_DISK: u64 = 1;
const FILE_TYPE_CHAR: u64 = 2;

/// Code pages this runtime recognizes.
const CODE_PAGES: [u32; 18] = [
    437, 850, 852, 855, 866, 874, 932, 936, 949, 950, 1200, 1201, 1250, 1251, 1252, 1253, 65001,
    20127,
];

/// True for code pages `SetConsoleCP`/`IsValidCodePage` accept.
pub(crate) fn valid_code_page(cp: u32) -> bool {
    CODE_PAGES.contains(&cp)
}

/// Win32 error code for a host I/O error.
pub(crate) fn win_error_of(e: &std::io::Error) -> u32 {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => 2,
        PermissionDenied => 5,
        AlreadyExists => 183,
        InvalidInput => 87,
        DirectoryNotEmpty => 145,
        _ => match e.raw_os_error() {
            Some(n) if n > 0 => n as u32,
            _ => 1,
        },
    }
}

/// Windows path to host path (separators only; drive letters are kept).
fn host_path(p: &str) -> String {
    p.replace('\\', "/")
}

fn cwd_string() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().replace('/', "\\"))
        .unwrap_or_else(|_| "C:\\".to_string())
}

/// Absolute Windows path for `p` (relative paths are taken from the cwd).
fn full_path(p: &str) -> String {
    let is_abs =
        p.starts_with('\\') || p.starts_with('/') || (p.len() >= 2 && p.as_bytes()[1] == b':');
    let joined = if is_abs {
        p.to_string()
    } else {
        format!("{}\\{}", cwd_string(), p)
    };
    let mut parts: Vec<&str> = Vec::new();
    for comp in joined.split(['\\', '/']) {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    parts.join("\\")
}

fn set_last(ctx: &mut ApiCtx, e: &std::io::Error) {
    ctx.set_last_error(win_error_of(e));
}

fn create_file(ctx: &mut ApiCtx, name: String, access: u32, disp: u32) -> Result<u64> {
    let upper = name.to_ascii_uppercase();
    if upper == "CONIN$" || upper == "CONOUT$" {
        let idx = if upper == "CONIN$" { 0 } else { 1 };
        ctx.set_last_error(0);
        return Ok(ctx.p.handles.insert(Obj::Console(idx)));
    }
    let path = host_path(&name);
    let existed = std::path::Path::new(&path).exists();
    let readable = access & GENERIC_READ != 0 || access == 0;
    let writable = access & GENERIC_WRITE != 0;
    let mut o = std::fs::OpenOptions::new();
    o.read(readable);
    o.write(writable);
    match disp {
        CREATE_NEW => {
            o.create_new(true);
        }
        CREATE_ALWAYS => {
            o.create(true).truncate(true);
        }
        OPEN_EXISTING => {}
        OPEN_ALWAYS => {
            o.create(true);
        }
        TRUNCATE_EXISTING => {
            o.truncate(true);
        }
        _ => {
            ctx.set_last_error(ERROR_INVALID_PARAMETER_CODE);
            return Ok(INVALID_HANDLE);
        }
    }
    match o.open(&path) {
        Ok(file) => {
            // CREATE_ALWAYS and OPEN_ALWAYS succeed on an existing file but report it
            let already = existed && (disp == CREATE_ALWAYS || disp == OPEN_ALWAYS);
            ctx.set_last_error(if already { 183 } else { 0 });
            Ok(ctx.p.handles.insert(Obj::File(FileObj {
                file,
                path: name,
                readable,
                writable,
            })))
        }
        Err(e) => {
            set_last(ctx, &e);
            Ok(INVALID_HANDLE)
        }
    }
}

const ERROR_INVALID_PARAMETER_CODE: u32 = 87;

fn create_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let (access, disp) = (ctx.au(1), ctx.au(4));
    let h = create_file(ctx, name, access, disp)?;
    ctx.ret(h);
    Ok(())
}

fn create_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.wstr_string(ctx.a(0))?;
    let (access, disp) = (ctx.au(1), ctx.au(4));
    let h = create_file(ctx, name, access, disp)?;
    ctx.ret(h);
    Ok(())
}

/// Read up to `n` bytes from a handle (file or console stdin).
fn read_handle(ctx: &mut ApiCtx, h: u64, n: usize) -> Result<Option<Vec<u8>>> {
    let Some(obj) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        return Ok(None);
    };
    let mut buf = vec![0u8; n];
    let r: std::result::Result<usize, u32> = {
        let mut o = obj.borrow_mut();
        match &mut *o {
            Obj::File(f) if !f.readable => Err(5),
            Obj::File(f) => f.file.read(&mut buf).map_err(|e| win_error_of(&e)),
            Obj::Console(0) => std::io::stdin()
                .lock()
                .read(&mut buf)
                .map_err(|e| win_error_of(&e)),
            _ => Err(ERROR_INVALID_HANDLE),
        }
    };
    match r {
        Ok(k) => {
            buf.truncate(k);
            Ok(Some(buf))
        }
        Err(e) => {
            ctx.set_last_error(e);
            Ok(None)
        }
    }
}

fn read_file(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as usize, ctx.a(3));
    match read_handle(ctx, h, n)? {
        Some(data) => {
            ctx.put(buf, &data)?;
            if out != 0 {
                ctx.wr(out, 4, data.len() as u64)?;
            }
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

/// Write bytes to a handle: files, or the console streams (no translation).
fn write_handle(ctx: &mut ApiCtx, h: u64, data: &[u8]) -> Result<bool> {
    let Some(obj) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        return Ok(false);
    };
    let r: std::result::Result<(), u32> = {
        let mut o = obj.borrow_mut();
        match &mut *o {
            Obj::File(f) if !f.writable => Err(5),
            Obj::File(f) => f.file.write_all(data).map_err(|e| win_error_of(&e)),
            Obj::Console(1) => {
                let mut out = std::io::stdout().lock();
                out.write_all(data)
                    .and_then(|_| out.flush())
                    .map_err(|e| win_error_of(&e))
            }
            Obj::Console(2) => {
                let mut e = std::io::stderr().lock();
                e.write_all(data)
                    .and_then(|_| e.flush())
                    .map_err(|e| win_error_of(&e))
            }
            _ => Err(ERROR_INVALID_HANDLE),
        }
    };
    match r {
        Ok(()) => Ok(true),
        Err(e) => {
            ctx.set_last_error(e);
            Ok(false)
        }
    }
}

fn write_file(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as u64, ctx.a(3));
    let data = ctx.bytes(buf, n)?;
    let ok = write_handle(ctx, h, &data)?;
    if ok && out != 0 {
        ctx.wr(out, 4, n)?;
    }
    ctx.ret_bool(ok);
    Ok(())
}

fn write_console_a(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as u64, ctx.a(3));
    let data = ctx.bytes(buf, n)?;
    let ok = write_handle(ctx, h, &data)?;
    if ok && out != 0 {
        ctx.wr(out, 4, n)?;
    }
    ctx.ret_bool(ok);
    Ok(())
}

fn write_console_w(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as u64, ctx.a(3));
    let units = ctx.wide_units(buf, n)?;
    let text = String::from_utf16_lossy(&units);
    let ok = write_handle(ctx, h, text.as_bytes())?;
    if ok && out != 0 {
        ctx.wr(out, 4, n)?;
    }
    ctx.ret_bool(ok);
    Ok(())
}

fn read_console_a(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as usize, ctx.a(3));
    match read_handle(ctx, h, n)? {
        Some(data) => {
            ctx.put(buf, &data)?;
            if out != 0 {
                ctx.wr(out, 4, data.len() as u64)?;
            }
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

fn read_console_w(ctx: &mut ApiCtx) -> Result<()> {
    let (h, buf, n, out) = (ctx.a(0), ctx.a(1), ctx.au(2) as usize, ctx.a(3));
    match read_handle(ctx, h, n)? {
        Some(data) => {
            let units: Vec<u16> = String::from_utf8_lossy(&data).encode_utf16().collect();
            ctx.put_wide(buf, &units)?;
            if out != 0 {
                ctx.wr(out, 4, units.len() as u64)?;
            }
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

/// Run `f` on the host file of handle `h`.
fn with_file<T>(
    ctx: &mut ApiCtx,
    h: u64,
    f: impl FnOnce(&mut std::fs::File) -> std::io::Result<T>,
) -> Result<Option<T>> {
    let Some(obj) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        return Ok(None);
    };
    let r: std::result::Result<T, u32> = {
        let mut o = obj.borrow_mut();
        match &mut *o {
            Obj::File(fo) => f(&mut fo.file).map_err(|e| win_error_of(&e)),
            _ => Err(ERROR_INVALID_HANDLE),
        }
    };
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            ctx.set_last_error(e);
            Ok(None)
        }
    }
}

fn get_file_size_ex_inner(ctx: &mut ApiCtx, h: u64) -> Result<Option<u64>> {
    with_file(ctx, h, |f| f.metadata().map(|m| m.len()))
}

fn get_file_size(ctx: &mut ApiCtx) -> Result<()> {
    let (h, hi) = (ctx.a(0), ctx.a(1));
    match get_file_size_ex_inner(ctx, h)? {
        Some(sz) => {
            if hi != 0 {
                ctx.wr(hi, 4, sz >> 32)?;
            }
            ctx.ret(sz & 0xFFFF_FFFF);
        }
        None => ctx.ret(0xFFFF_FFFF),
    }
    Ok(())
}

fn get_file_size_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (h, out) = (ctx.a(0), ctx.a(1));
    match get_file_size_ex_inner(ctx, h)? {
        Some(sz) => {
            ctx.wr(out, 8, sz)?;
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

/// Seek a file handle; `method` 0 = begin, 1 = current, 2 = end.
fn seek_handle(ctx: &mut ApiCtx, h: u64, dist: i64, method: u32) -> Result<Option<u64>> {
    let from = match method {
        0 => SeekFrom::Start(dist.max(0) as u64),
        1 => SeekFrom::Current(dist),
        _ => SeekFrom::End(dist),
    };
    with_file(ctx, h, |f| f.seek(from))
}

fn set_file_pointer(ctx: &mut ApiCtx) -> Result<()> {
    let (h, lo, hi_p, method) = (ctx.a(0), ctx.au(1), ctx.a(2), ctx.au(3));
    // With a high-part pointer the distance is 64-bit; otherwise it is a
    // signed 32-bit distance.
    let dist = if hi_p != 0 {
        let hi = ctx.rd(hi_p, 4)? as u32 as i32 as i64;
        (hi << 32) | (lo as i64 & 0xFFFF_FFFF)
    } else {
        lo as i32 as i64
    };
    match seek_handle(ctx, h, dist, method)? {
        Some(pos) => {
            if hi_p != 0 {
                ctx.wr(hi_p, 4, pos >> 32)?;
            }
            ctx.ret(pos & 0xFFFF_FFFF);
        }
        None => ctx.ret(INVALID_SET_FILE_POINTER),
    }
    Ok(())
}

fn set_file_pointer_ex(ctx: &mut ApiCtx) -> Result<()> {
    let (h, dist, out, method) = (ctx.a(0), ctx.ai64(1), ctx.a(2), ctx.au(3));
    match seek_handle(ctx, h, dist, method)? {
        Some(pos) => {
            if out != 0 {
                ctx.wr(out, 8, pos)?;
            }
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

fn set_end_of_file(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let r = with_file(ctx, h, |f| {
        let pos = f.stream_position()?;
        f.set_len(pos)?;
        Ok(())
    })?;
    ctx.ret_bool(r.is_some());
    Ok(())
}

fn flush_file_buffers(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let is_console = ctx
        .p
        .handles
        .get(h)
        .map(|o| matches!(*o.borrow(), Obj::Console(_)))
        .unwrap_or(false);
    if is_console {
        let _ = std::io::stdout().flush();
        ctx.ret_bool(true);
        return Ok(());
    }
    let r = with_file(ctx, h, |f| f.sync_all())?;
    ctx.ret_bool(r.is_some());
    Ok(())
}

fn get_file_type(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let t = match ctx.p.handles.get(h).map(|o| match &*o.borrow() {
        Obj::Console(_) => FILE_TYPE_CHAR,
        Obj::File(_) => FILE_TYPE_DISK,
        _ => 0,
    }) {
        Some(t) => t,
        None => 0,
    };
    ctx.ret(t);
    Ok(())
}

fn get_file_time(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let (c, a, w) = (ctx.a(1), ctx.a(2), ctx.a(3));
    let mtime = with_file(ctx, h, |f| f.metadata().and_then(|m| m.modified()))?;
    match mtime {
        Some(t) => {
            let ft = unix_to_filetime(t);
            for p in [c, a, w] {
                if p != 0 {
                    ctx.wr(p, 8, ft)?;
                }
            }
            ctx.ret_bool(true);
        }
        None => ctx.ret_bool(false),
    }
    Ok(())
}

fn attributes_of(path: &str) -> Option<u32> {
    let meta = std::fs::metadata(host_path(path)).ok()?;
    let mut a = if meta.is_dir() {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        0
    };
    if meta.permissions().readonly() {
        a |= FILE_ATTRIBUTE_READONLY;
    }
    if a == 0 {
        a = FILE_ATTRIBUTE_NORMAL;
    }
    Some(a)
}

fn get_file_attributes_common(ctx: &mut ApiCtx, name: String) -> Result<()> {
    match attributes_of(&name) {
        Some(a) => ctx.ret(a as u64),
        None => {
            ctx.set_last_error(2);
            ctx.ret(INVALID_FILE_ATTRIBUTES);
        }
    }
    Ok(())
}

fn get_file_attributes_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(0))?;
    get_file_attributes_common(ctx, n)
}

fn get_file_attributes_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(0))?;
    get_file_attributes_common(ctx, n)
}

fn bool_result(ctx: &mut ApiCtx, r: std::io::Result<()>) -> Result<()> {
    match r {
        Ok(()) => ctx.ret_bool(true),
        Err(e) => {
            set_last(ctx, &e);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn delete_file(ctx: &mut ApiCtx, name: String) -> Result<()> {
    let r = std::fs::remove_file(host_path(&name));
    bool_result(ctx, r)
}

fn delete_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(0))?;
    delete_file(ctx, n)
}

fn delete_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(0))?;
    delete_file(ctx, n)
}

fn create_directory(ctx: &mut ApiCtx, name: String) -> Result<()> {
    let r = std::fs::create_dir(host_path(&name));
    bool_result(ctx, r)
}

fn create_directory_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(0))?;
    create_directory(ctx, n)
}

fn create_directory_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(0))?;
    create_directory(ctx, n)
}

fn remove_directory(ctx: &mut ApiCtx, name: String) -> Result<()> {
    let r = std::fs::remove_dir(host_path(&name));
    bool_result(ctx, r)
}

fn remove_directory_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(0))?;
    remove_directory(ctx, n)
}

fn remove_directory_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(0))?;
    remove_directory(ctx, n)
}

fn get_current_directory_a(ctx: &mut ApiCtx) -> Result<()> {
    let (size, buf) = (ctx.a(0), ctx.a(1));
    let cwd = cwd_string();
    let r = copy_ansi_out(ctx, buf, size, cwd.as_bytes())?;
    ctx.ret(r);
    Ok(())
}

fn get_current_directory_w(ctx: &mut ApiCtx) -> Result<()> {
    let (size, buf) = (ctx.a(0), ctx.a(1));
    let units: Vec<u16> = cwd_string().encode_utf16().collect();
    let r = copy_wide_out(ctx, buf, size, &units)?;
    ctx.ret(r);
    Ok(())
}

fn set_current_directory(ctx: &mut ApiCtx, name: String) -> Result<()> {
    let r = std::env::set_current_dir(host_path(&name));
    bool_result(ctx, r)
}

fn set_current_directory_a(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_string(ctx.a(0))?;
    set_current_directory(ctx, n)
}

fn set_current_directory_w(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.wstr_string(ctx.a(0))?;
    set_current_directory(ctx, n)
}

/// GetFullPathName core: returns the full path and the file-name offset.
fn full_path_name(
    ctx: &mut ApiCtx,
    name: &str,
    size: u64,
    buf: u64,
    part: u64,
    wide: bool,
) -> Result<()> {
    let full = full_path(name);
    let len = if wide {
        full.encode_utf16().count()
    } else {
        full.len()
    } as u64;
    let r = if wide {
        let units: Vec<u16> = full.encode_utf16().collect();
        copy_wide_out(ctx, buf, size, &units)?
    } else {
        copy_ansi_out(ctx, buf, size, full.as_bytes())?
    };
    // success: the buffer holds the path; the file part follows the last separator
    if part != 0 && buf != 0 && size > len {
        match full.rfind('\\').map(|i| i + 1) {
            Some(off) => {
                let unit = if wide { 2 } else { 1 };
                let chars_before = if wide {
                    full[..off].encode_utf16().count()
                } else {
                    off
                } as u64;
                ctx.wr(part, 8, buf + chars_before * unit)?;
            }
            None => ctx.wr(part, 8, 0)?,
        }
    }
    ctx.ret(r);
    Ok(())
}

fn get_full_path_name_a(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.cstr_string(ctx.a(0))?;
    let (size, buf, part) = (ctx.a(1), ctx.a(2), ctx.a(3));
    full_path_name(ctx, &name, size, buf, part, false)
}

fn get_full_path_name_w(ctx: &mut ApiCtx) -> Result<()> {
    let name = ctx.wstr_string(ctx.a(0))?;
    let (size, buf, part) = (ctx.a(1), ctx.a(2), ctx.a(3));
    full_path_name(ctx, &name, size, buf, part, true)
}

fn get_temp_path_common(ctx: &mut ApiCtx, wide: bool) -> Result<()> {
    let (size, buf) = (ctx.a(0), ctx.a(1));
    let mut t = std::env::temp_dir().to_string_lossy().replace('/', "\\");
    if !t.ends_with('\\') {
        t.push('\\');
    }
    let r = if wide {
        let units: Vec<u16> = t.encode_utf16().collect();
        copy_wide_out(ctx, buf, size, &units)?
    } else {
        copy_ansi_out(ctx, buf, size, t.as_bytes())?
    };
    ctx.ret(r);
    Ok(())
}

fn get_temp_path_a(ctx: &mut ApiCtx) -> Result<()> {
    get_temp_path_common(ctx, false)
}

fn get_temp_path_w(ctx: &mut ApiCtx) -> Result<()> {
    get_temp_path_common(ctx, true)
}

fn move_file_common(ctx: &mut ApiCtx, from: String, to: String) -> Result<()> {
    let r = std::fs::rename(host_path(&from), host_path(&to));
    bool_result(ctx, r)
}

fn move_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let (f, t) = (ctx.cstr_string(ctx.a(0))?, ctx.cstr_string(ctx.a(1))?);
    move_file_common(ctx, f, t)
}

fn move_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let (f, t) = (ctx.wstr_string(ctx.a(0))?, ctx.wstr_string(ctx.a(1))?);
    move_file_common(ctx, f, t)
}

fn copy_file_common(
    ctx: &mut ApiCtx,
    from: String,
    to: String,
    fail_if_exists: bool,
) -> Result<()> {
    let dst = host_path(&to);
    if fail_if_exists && std::path::Path::new(&dst).exists() {
        ctx.set_last_error(80);
        ctx.ret_bool(false);
        return Ok(());
    }
    let r = std::fs::copy(host_path(&from), dst).map(|_| ());
    bool_result(ctx, r)
}

fn copy_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let (f, t) = (ctx.cstr_string(ctx.a(0))?, ctx.cstr_string(ctx.a(1))?);
    let fail = ctx.au(2) != 0;
    copy_file_common(ctx, f, t, fail)
}

fn copy_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let (f, t) = (ctx.wstr_string(ctx.a(0))?, ctx.wstr_string(ctx.a(1))?);
    let fail = ctx.au(2) != 0;
    copy_file_common(ctx, f, t, fail)
}

/// Shell-style wildcard match (`*`, `?`), case-insensitive.
fn wildcard_match(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Write one WIN32_FIND_DATA record (ANSI or wide name).
fn write_find_data(ctx: &mut ApiCtx, out: u64, name: &str, path: &str, wide: bool) -> Result<()> {
    ctx.zero(out, if wide { 592 } else { 320 })?;
    let meta = std::fs::metadata(path).ok();
    let (attr, size, mtime) = match &meta {
        Some(m) => {
            let a = if m.is_dir() {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            (a, m.len(), m.modified().ok())
        }
        None => (FILE_ATTRIBUTE_NORMAL, 0, None),
    };
    ctx.wr(out, 4, attr as u64)?;
    if let Some(t) = mtime {
        let ft = unix_to_filetime(t);
        ctx.wr(out + 4, 8, ft)?;
        ctx.wr(out + 12, 8, ft)?;
        ctx.wr(out + 20, 8, ft)?;
    }
    ctx.wr(out + 28, 4, size >> 32)?;
    ctx.wr(out + 32, 4, size & 0xFFFF_FFFF)?;
    if wide {
        let units: Vec<u16> = name.encode_utf16().take(259).collect();
        ctx.put_wide(out + 44, &units)?;
    } else {
        let bytes: Vec<u8> = name.bytes().take(259).collect();
        ctx.put(out + 44, &bytes)?;
    }
    Ok(())
}

/// Shared FindFirstFile logic for both encodings.
fn find_first(ctx: &mut ApiCtx, pattern: String, out: u64, wide: bool) -> Result<()> {
    let host = host_path(&pattern);
    let (dir, mask) = match host.rfind('/') {
        Some(i) => (host[..i].to_string(), host[i + 1..].to_string()),
        None => (".".to_string(), host.clone()),
    };
    let dir = if dir.is_empty() { "/".to_string() } else { dir };
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) => {
            set_last(ctx, &e);
            ctx.ret(INVALID_HANDLE);
            return Ok(());
        }
    };
    let mut names: Vec<String> = vec![".".to_string(), "..".to_string()];
    for entry in rd.flatten() {
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    let names: Vec<String> = names
        .into_iter()
        .filter(|n| wildcard_match(&mask, n))
        .collect();
    if names.is_empty() {
        ctx.set_last_error(18);
        ctx.ret(INVALID_HANDLE);
        return Ok(());
    }
    let first = names[0].clone();
    let path = format!("{dir}/{first}");
    write_find_data(ctx, out, &first, &path, wide)?;
    let h = ctx.p.handles.insert(Obj::Find {
        dir: dir.clone(),
        entries: names,
        next: 1,
    });
    ctx.set_last_error(0);
    ctx.ret(h);
    Ok(())
}

fn find_first_file_a(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.cstr_string(ctx.a(0))?;
    let out = ctx.a(1);
    find_first(ctx, p, out, false)
}

fn find_first_file_w(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.wstr_string(ctx.a(0))?;
    let out = ctx.a(1);
    find_first(ctx, p, out, true)
}

fn find_next_common(ctx: &mut ApiCtx, wide: bool) -> Result<()> {
    let (h, out) = (ctx.a(0), ctx.a(1));
    let Some(obj) = ctx.p.handles.get(h) else {
        ctx.set_last_error(ERROR_INVALID_HANDLE);
        ctx.ret_bool(false);
        return Ok(());
    };
    let next = {
        let mut o = obj.borrow_mut();
        match &mut *o {
            Obj::Find { dir, entries, next } => {
                if *next < entries.len() {
                    let n = entries[*next].clone();
                    *next += 1;
                    Some((dir.clone(), n))
                } else {
                    None
                }
            }
            _ => None,
        }
    };
    let Some((dir, name)) = next else {
        ctx.set_last_error(18);
        ctx.ret_bool(false);
        return Ok(());
    };
    let path = format!("{dir}/{name}");
    write_find_data(ctx, out, &name, &path, wide)?;
    ctx.ret_bool(true);
    Ok(())
}

fn find_next_file_a(ctx: &mut ApiCtx) -> Result<()> {
    find_next_common(ctx, false)
}

fn find_next_file_w(ctx: &mut ApiCtx) -> Result<()> {
    find_next_common(ctx, true)
}

fn find_close(ctx: &mut ApiCtx) -> Result<()> {
    let h = ctx.a(0);
    let existed = ctx.p.handles.close(h).is_some();
    ctx.ret_bool(existed);
    Ok(())
}

/// GetStdHandle-independent console mode of a console handle.
fn console_index(ctx: &ApiCtx, h: u64) -> Option<usize> {
    match ctx.p.handles.get(h).map(|o| match &*o.borrow() {
        Obj::Console(i) => Some(*i as usize),
        _ => None,
    }) {
        Some(Some(i)) => Some(i),
        _ => None,
    }
}

fn get_console_mode(ctx: &mut ApiCtx) -> Result<()> {
    let (h, out) = (ctx.a(0), ctx.a(1));
    match console_index(ctx, h) {
        Some(i) => {
            let m = ctx.p.k32.console_modes[i];
            ctx.wr(out, 4, m as u64)?;
            ctx.ret_bool(true);
        }
        None => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn set_console_mode(ctx: &mut ApiCtx) -> Result<()> {
    let (h, m) = (ctx.a(0), ctx.au(1));
    match console_index(ctx, h) {
        Some(i) => {
            ctx.p.k32.console_modes[i] = m;
            ctx.ret_bool(true);
        }
        None => {
            ctx.set_last_error(ERROR_INVALID_HANDLE);
            ctx.ret_bool(false);
        }
    }
    Ok(())
}

fn get_console_cp(ctx: &mut ApiCtx) -> Result<()> {
    let cp = ctx.p.k32.cp_in;
    ctx.ret(cp as u64);
    Ok(())
}

fn get_console_output_cp(ctx: &mut ApiCtx) -> Result<()> {
    let cp = ctx.p.k32.cp_out;
    ctx.ret(cp as u64);
    Ok(())
}

fn set_console_cp(ctx: &mut ApiCtx) -> Result<()> {
    let cp = ctx.au(0);
    if !valid_code_page(cp) {
        ctx.set_last_error(ERROR_INVALID_PARAMETER_CODE);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.k32.cp_in = cp;
    ctx.ret_bool(true);
    Ok(())
}

fn set_console_output_cp(ctx: &mut ApiCtx) -> Result<()> {
    let cp = ctx.au(0);
    if !valid_code_page(cp) {
        ctx.set_last_error(ERROR_INVALID_PARAMETER_CODE);
        ctx.ret_bool(false);
        return Ok(());
    }
    ctx.p.k32.cp_out = cp;
    ctx.ret_bool(true);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "kernel32",
        "CreateFileA" => create_file_a,
        "CreateFileW" => create_file_w,
        "ReadFile" => read_file,
        "WriteFile" => write_file,
        "WriteConsoleA" => write_console_a,
        "WriteConsoleW" => write_console_w,
        "ReadConsoleA" => read_console_a,
        "ReadConsoleW" => read_console_w,
        "GetFileSize" => get_file_size,
        "GetFileSizeEx" => get_file_size_ex,
        "SetFilePointer" => set_file_pointer,
        "SetFilePointerEx" => set_file_pointer_ex,
        "SetEndOfFile" => set_end_of_file,
        "FlushFileBuffers" => flush_file_buffers,
        "GetFileType" => get_file_type,
        "GetFileTime" => get_file_time,
        "GetFileAttributesA" => get_file_attributes_a,
        "GetFileAttributesW" => get_file_attributes_w,
        "DeleteFileA" => delete_file_a,
        "DeleteFileW" => delete_file_w,
        "CreateDirectoryA" => create_directory_a,
        "CreateDirectoryW" => create_directory_w,
        "RemoveDirectoryA" => remove_directory_a,
        "RemoveDirectoryW" => remove_directory_w,
        "GetCurrentDirectoryA" => get_current_directory_a,
        "GetCurrentDirectoryW" => get_current_directory_w,
        "SetCurrentDirectoryA" => set_current_directory_a,
        "SetCurrentDirectoryW" => set_current_directory_w,
        "GetFullPathNameA" => get_full_path_name_a,
        "GetFullPathNameW" => get_full_path_name_w,
        "GetTempPathA" => get_temp_path_a,
        "GetTempPathW" => get_temp_path_w,
        "MoveFileA" => move_file_a,
        "MoveFileW" => move_file_w,
        "CopyFileA" => copy_file_a,
        "CopyFileW" => copy_file_w,
        "FindFirstFileA" => find_first_file_a,
        "FindFirstFileW" => find_first_file_w,
        "FindNextFileA" => find_next_file_a,
        "FindNextFileW" => find_next_file_w,
        "FindClose" => find_close,
        "GetConsoleMode" => get_console_mode,
        "SetConsoleMode" => set_console_mode,
        "GetConsoleCP" => get_console_cp,
        "GetConsoleOutputCP" => get_console_output_cp,
        "SetConsoleCP" => set_console_cp,
        "SetConsoleOutputCP" => set_console_output_cp,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*.TXT", "readme.txt"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "abbc"));
        assert!(wildcard_match("*.*", "x.y"));
    }

    #[test]
    fn full_paths_normalize() {
        let p = full_path("C:\\a\\b\\..\\c.txt");
        assert_eq!(p, "C:\\a\\c.txt");
    }

    #[test]
    fn code_pages() {
        assert!(valid_code_page(65001));
        assert!(!valid_code_page(12345));
    }
}
