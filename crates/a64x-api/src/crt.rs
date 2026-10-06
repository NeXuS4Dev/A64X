//! CRT adapters (msvcrt / ucrtbase) — real native implementations.

use crate::{arg, read_cstr, ret, win_shared, write_stdout, ApiCtx, ApiDef};
use a64x_core::Result;

macro_rules! api {
    ($name:expr, $f:ident) => {
        ApiDef { dll: "msvcrt", name: $name, f: $f }
    };
    (ucrt, $name:expr, $f:ident) => {
        ApiDef { dll: "ucrtbase", name: $name, f: $f }
    };
}

/// Table of CRT adapters.
pub(crate) static TABLE: &[ApiDef] = &[
    api!("puts", puts),
    api!("putchar", putchar),
    api!("_putch", putchar),
    api!("printf", printf),
    api!("fprintf", fprintf),
    api!("exit", exit),
    api!("_exit", exit),
    api!("abort", abort),
    api!("malloc", malloc),
    api!("calloc", calloc),
    api!("realloc", realloc_crt),
    api!("free", free),
    api!("memset", memset_),
    api!("memcpy", memcpy_),
    api!("memmove", memmove_),
    api!("memcmp", memcmp_),
    api!("strlen", strlen_),
    api!("strnlen", strnlen_),
    api!("strcmp", strcmp_),
    api!("strncmp", strncmp_),
    api!("_stricmp", stricmp_),
    api!("strcpy", strcpy_),
    api!("strncpy", strncpy_),
    api!("strdup", strdup_),
    api!("_strdup", strdup_),
    api!("tolower", tolower_),
    api!("toupper", toupper_),
    api!("isspace", isspace_),
    api!("isdigit", isdigit_),
    api!("isalpha", isalpha_),
    api!("atoi", atoi),
    api!("atol", atoi),
    api!("abs", abs_),
    api!("fflush", ok_zero),
    api!("__acrt_iob_func", acrt_iob_func),
    // UCRT startup / printf plumbing
    api!(ucrt, "__stdio_common_vfprintf", stdio_common_vfprintf),
    api!(ucrt, "__stdio_common_vfwprintf", stdio_common_vfprintf),
    api!(ucrt, "puts", puts),
    api!(ucrt, "putchar", putchar),
    api!(ucrt, "malloc", malloc),
    api!(ucrt, "calloc", calloc),
    api!(ucrt, "realloc", realloc_crt),
    api!(ucrt, "free", free),
    api!(ucrt, "exit", exit),
    api!(ucrt, "_exit", exit),
    api!(ucrt, "abort", abort),
    api!(ucrt, "memset", memset_),
    api!(ucrt, "memcpy", memcpy_),
    api!(ucrt, "memmove", memmove_),
    api!(ucrt, "memcmp", memcmp_),
    api!(ucrt, "strlen", strlen_),
    api!(ucrt, "strcmp", strcmp_),
    api!(ucrt, "strcpy", strcpy_),
    api!(ucrt, "_initialize_narrow_environment", ok_zero),
    api!(ucrt, "_configure_narrow_argv", ok_zero),
    api!(ucrt, "_set_new_mode", ok_zero),
    api!(ucrt, "_configthreadlocale", ok_zero),
    api!(ucrt, "_initterm", ok_zero),
    api!(ucrt, "_initterm_e", ok_zero),
    api!(ucrt, "_seh_filter_exe", seh_filter_exe),
    api!(ucrt, "__setusermatherr", ok_zero),
    api!(ucrt, "_get_initial_narrow_environment", get_initial_narrow_env),
    api!(ucrt, "__p__acmdln", p_acmdln),
    api!(ucrt, "__p___argv", p_argv),
    api!(ucrt, "__p___argc", p_argc),
    api!(ucrt, "getchar", getchar),
];

fn ok_zero(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, 0);
    Ok(())
}

fn puts(ctx: &mut ApiCtx) -> Result<()> {
    let s = read_cstr(ctx, arg(ctx.state, 0), 1 << 20);
    write_stdout(&s);
    write_stdout(b"\n");
    ret(ctx.state, 0);
    Ok(())
}

fn putchar(ctx: &mut ApiCtx) -> Result<()> {
    let c = arg(ctx.state, 0) as u8;
    write_stdout(&[c]);
    ret(ctx.state, c as u64);
    Ok(())
}

fn getchar(ctx: &mut ApiCtx) -> Result<()> {
    use std::io::Read;
    let mut b = [0u8; 1];
    let n = std::io::stdin().lock().read(&mut b).unwrap_or(0);
    ret(ctx.state, if n == 0 { u64::MAX } else { b[0] as u64 });
    Ok(())
}

fn exit_(ctx: &mut ApiCtx, code: u64) {
    ctx.state.exit_code = code;
    ctx.state.exit_reason = a64x_core::ExitReason::Exited as u8;
    ctx.state.running = 0;
}

fn exit(ctx: &mut ApiCtx) -> Result<()> {
    exit_(ctx, arg(ctx.state, 0));
    Ok(())
}

fn abort(ctx: &mut ApiCtx) -> Result<()> {
    exit_(ctx, 134);
    Ok(())
}

fn malloc(ctx: &mut ApiCtx) -> Result<()> {
    let size = arg(ctx.state, 0);
    let addr = ctx.alloc_heap(size.max(1), 16);
    ret(ctx.state, addr);
    Ok(())
}

fn calloc(ctx: &mut ApiCtx) -> Result<()> {
    let n = arg(ctx.state, 0).max(1);
    let sz = arg(ctx.state, 1).max(1);
    let size = n.saturating_mul(sz);
    let addr = ctx.alloc_heap(size, 16);
    ctx.mem.zero(addr, size.min(1 << 24))?;
    ret(ctx.state, addr);
    Ok(())
}

fn realloc_crt(ctx: &mut ApiCtx) -> Result<()> {
    let old = arg(ctx.state, 0);
    let size = arg(ctx.state, 1).max(1);
    if old == 0 {
        let addr = ctx.alloc_heap(size, 16);
        ret(ctx.state, addr);
        return Ok(());
    }
    let new_addr = ctx.alloc_heap(size, 16);
    let n = size.min(1 << 24);
    let mut tmp = vec![0u8; n as usize];
    let _ = ctx.mem.read(old, &mut tmp);
    let _ = ctx.mem.write(new_addr, &tmp);
    ret(ctx.state, new_addr);
    Ok(())
}

fn free(_ctx: &mut ApiCtx) -> Result<()> {
    Ok(())
}

fn memset_(ctx: &mut ApiCtx) -> Result<()> {
    let (dst, val, len) = (arg(ctx.state, 0), arg(ctx.state, 1) as u8, arg(ctx.state, 2));
    let p = ctx.mem.slice_mut(dst, len)?;
    p.fill(val);
    ret(ctx.state, dst);
    Ok(())
}

fn memcpy_(ctx: &mut ApiCtx) -> Result<()> {
    let (dst, src, len) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2));
    let tmp = ctx.mem.slice(src, len)?.to_vec();
    ctx.mem.write(dst, &tmp)?;
    ret(ctx.state, dst);
    Ok(())
}

fn memmove_(ctx: &mut ApiCtx) -> Result<()> {
    memcpy_(ctx)
}

fn memcmp_(ctx: &mut ApiCtx) -> Result<()> {
    let (a, b, len) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2));
    let la = ctx.mem.slice(a, len)?.to_vec();
    let lb = ctx.mem.slice(b, len)?.to_vec();
    let d = la.iter().zip(lb.iter()).find(|(x, y)| x != y).map(|(x, y)| *x as i64 - *y as i64).unwrap_or(0);
    ret(ctx.state, d as u64);
    Ok(())
}

fn strlen_(ctx: &mut ApiCtx) -> Result<()> {
    let s = read_cstr(ctx, arg(ctx.state, 0), 1 << 20);
    ret(ctx.state, s.len() as u64);
    Ok(())
}

fn strnlen_(ctx: &mut ApiCtx) -> Result<()> {
    let max = arg(ctx.state, 1) as usize;
    let s = read_cstr(ctx, arg(ctx.state, 0), max.min(1 << 20));
    ret(ctx.state, s.len().min(max) as u64);
    Ok(())
}

fn strcmp_(ctx: &mut ApiCtx) -> Result<()> {
    let a = read_cstr(ctx, arg(ctx.state, 0), 1 << 20);
    let b = read_cstr(ctx, arg(ctx.state, 1), 1 << 20);
    let d = match a.cmp(&b) {
        core::cmp::Ordering::Less => -1i64,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    };
    ret(ctx.state, d as u64);
    Ok(())
}

fn strncmp_(ctx: &mut ApiCtx) -> Result<()> {
    let n = arg(ctx.state, 2) as usize;
    let a = read_cstr(ctx, arg(ctx.state, 0), n + 1);
    let b = read_cstr(ctx, arg(ctx.state, 1), n + 1);
    let (a, b) = (&a[..a.len().min(n)], &b[..b.len().min(n)]);
    let d = match a.cmp(b) {
        core::cmp::Ordering::Less => -1i64,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    };
    ret(ctx.state, d as u64);
    Ok(())
}

fn stricmp_(ctx: &mut ApiCtx) -> Result<()> {
    let a: Vec<u8> = read_cstr(ctx, arg(ctx.state, 0), 1 << 20).iter().map(u8::to_ascii_lowercase).collect();
    let b: Vec<u8> = read_cstr(ctx, arg(ctx.state, 1), 1 << 20).iter().map(u8::to_ascii_lowercase).collect();
    let d = match a.cmp(&b) {
        core::cmp::Ordering::Less => -1i64,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    };
    ret(ctx.state, d as u64);
    Ok(())
}

fn strcpy_(ctx: &mut ApiCtx) -> Result<()> {
    let (dst, src) = (arg(ctx.state, 0), arg(ctx.state, 1));
    let s = read_cstr(ctx, src, 1 << 20);
    ctx.mem.write_cstr(dst, &s)?;
    ret(ctx.state, dst);
    Ok(())
}

fn strncpy_(ctx: &mut ApiCtx) -> Result<()> {
    let (dst, src, n) = (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2) as usize);
    let mut s = read_cstr(ctx, src, n + 1);
    s.truncate(n);
    s.resize(n, 0);
    ctx.mem.write(dst, &s)?;
    ret(ctx.state, dst);
    Ok(())
}

fn strdup_(ctx: &mut ApiCtx) -> Result<()> {
    let s = read_cstr(ctx, arg(ctx.state, 0), 1 << 20);
    let addr = ctx.alloc_heap(s.len() as u64 + 1, 1);
    ctx.mem.write_cstr(addr, &s)?;
    ret(ctx.state, addr);
    Ok(())
}

fn tolower_(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, (arg(ctx.state, 0) as u8 as char).to_ascii_lowercase() as u64);
    Ok(())
}
fn toupper_(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, (arg(ctx.state, 0) as u8 as char).to_ascii_uppercase() as u64);
    Ok(())
}
fn isspace_(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, (arg(ctx.state, 0) as u8 as char).is_ascii_whitespace() as u64);
    Ok(())
}
fn isdigit_(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, (arg(ctx.state, 0) as u8 as char).is_ascii_digit() as u64);
    Ok(())
}
fn isalpha_(ctx: &mut ApiCtx) -> Result<()> {
    ret(ctx.state, (arg(ctx.state, 0) as u8 as char).is_ascii_alphabetic() as u64);
    Ok(())
}

fn atoi(ctx: &mut ApiCtx) -> Result<()> {
    let s = read_cstr(ctx, arg(ctx.state, 0), 1 << 16);
    let text = String::from_utf8_lossy(&s);
    let v: i64 = text.trim().parse().unwrap_or_else(|_| {
        // partial parse: leading digits with sign
        let t = text.trim_start();
        let (sign, t) = match t.strip_prefix('-') {
            Some(r) => (-1i64, r),
            None => (1, t.strip_prefix('+').unwrap_or(t)),
        };
        let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
        sign * digits.parse::<i64>().unwrap_or(0)
    });
    ret(ctx.state, v as u64);
    Ok(())
}

fn abs_(ctx: &mut ApiCtx) -> Result<()> {
    let v = arg(ctx.state, 0) as i32;
    ret(ctx.state, (v as i64).unsigned_abs());
    Ok(())
}

fn acrt_iob_func(ctx: &mut ApiCtx) -> Result<()> {
    // fake FILE* for stdin/stdout/stderr
    let fd = arg(ctx.state, 0).min(2);
    ret(ctx.state, win_shared::H_STDIN + fd);
    Ok(())
}

fn p_acmdln(ctx: &mut ApiCtx) -> Result<()> {
    // char** pointing to the command line string
    let slot = win_shared::STRINGS_BASE + 0x100;
    ctx.mem.write_int(slot, 8, win_shared::STRINGS_BASE)?;
    ret(ctx.state, slot);
    Ok(())
}

fn p_argv(ctx: &mut ApiCtx) -> Result<()> {
    let base = win_shared::STRINGS_BASE + 0x200;
    ctx.mem.write_int(base, 8, win_shared::STRINGS_BASE)?; // argv[0]
    ctx.mem.write_int(base + 8, 8, 0)?; // terminator
    ret(ctx.state, base);
    Ok(())
}

fn p_argc(ctx: &mut ApiCtx) -> Result<()> {
    let slot = win_shared::STRINGS_BASE + 0x300;
    ctx.mem.write_int(slot, 4, 1)?;
    ret(ctx.state, slot);
    Ok(())
}

fn get_initial_narrow_env(ctx: &mut ApiCtx) -> Result<()> {
    let base = win_shared::STRINGS_BASE + 0x400;
    ctx.mem.write_int(base, 8, 0)?; // empty env: {NULL}
    ret(ctx.state, base);
    Ok(())
}

fn seh_filter_exe(ctx: &mut ApiCtx) -> Result<()> {
    let code = arg(ctx.state, 0);
    ret(ctx.state, 1); // EXCEPTION_EXECUTE_HANDLER-ish
    ctx.exit_message = Some(format!("SEH filter invoked, code {code:#x}"));
    Ok(())
}

// -----------------------------------------------------------------------
// printf family
// -----------------------------------------------------------------------

/// Fetch vararg #k (0-based): registers x1..x7 hold the first 7 varargs
/// (x0 is the format), beyond that the guest stack carries them.
fn vararg(ctx: &ApiCtx, k: usize) -> u64 {
    if k + 1 < 8 {
        ctx.state.x[k + 1]
    } else {
        let addr = ctx.state.sp + 8 * (k as u64 + 1 - 8);
        ctx.mem.read_int(addr, 8).unwrap_or(0)
    }
}

/// Minimal C-format walker: %s %d %i %u %x %X %c %p %ld %lu %lld %llu %%.
fn format_into(ctx: &ApiCtx, fmt_addr: u64, mut next: impl FnMut(&ApiCtx) -> u64) -> String {
    let fmt = read_cstr(ctx, fmt_addr, 1 << 20);
    let text = String::from_utf8_lossy(&fmt).into_owned();
    let mut out = String::with_capacity(text.len() + 32);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            break;
        }
        // flags / width — consume and largely ignore (padding lgtm later)
        let mut width = String::new();
        let mut longs = 0;
        let mut plus = false;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    plus = true;
                    i += 1;
                }
                b'-' | b'0' | b' ' | b'#' => {
                    i += 1;
                }
                b'0'..=b'9' => {
                    width.push(bytes[i] as char);
                    i += 1;
                }
                b'.' => {
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                b'l' => {
                    longs += 1;
                    i += 1;
                }
                b'z' | b'h' | b'I' => {
                    if bytes[i] == b'I' && bytes.get(i + 1..i + 3) == Some(b"64") {
                        i += 3;
                        longs = 2;
                    } else {
                        i += 1;
                    }
                }
                _ => break,
            }
        }
        if i >= bytes.len() {
            break;
        }
        let w: usize = width.parse().unwrap_or(0);
        let spec = bytes[i];
        i += 1;
        let pad = |s: String, w: usize| -> String {
            if s.len() < w {
                format!("{:>width$}", s, width = w)
            } else {
                s
            }
        };
        match spec {
            b'%' => out.push('%'),
            b'c' => {
                let v = next(ctx) as u8;
                out.push(v as char);
            }
            b's' => {
                let addr = next(ctx);
                let s = read_cstr(ctx, addr, 1 << 20);
                out.push_str(&String::from_utf8_lossy(&s));
            }
            b'd' | b'i' => {
                let v = next(ctx);
                let s = if longs > 0 { format!("{}", v as i64) } else { format!("{}", v as u32 as i32) };
                let s = if plus && !s.starts_with('-') { format!("+{s}") } else { s };
                out.push_str(&pad(s, w));
            }
            b'u' => {
                let v = next(ctx);
                let s = if longs > 0 { format!("{v}") } else { format!("{}", v as u32) };
                out.push_str(&pad(s, w));
            }
            b'x' => {
                let v = next(ctx);
                let s = if longs > 0 { format!("{v:x}") } else { format!("{:x}", v as u32) };
                out.push_str(&pad(s, w));
            }
            b'X' => {
                let v = next(ctx);
                let s = if longs > 0 { format!("{v:X}") } else { format!("{:X}", v as u32) };
                out.push_str(&pad(s, w));
            }
            b'p' => {
                let v = next(ctx);
                out.push_str(&format!("{v:#018X}"));
            }
            b'n' => {
                let _ = next(ctx);
            }
            _ => {
                out.push('%');
                out.push(spec as char);
            }
        }
    }
    out
}

fn printf(ctx: &mut ApiCtx) -> Result<()> {
    let mut k = 0usize;
    let s = format_into(ctx, arg(ctx.state, 0), |c| {
        let v = vararg(c, k);
        k += 1;
        v
    });
    write_stdout(s.as_bytes());
    ret(ctx.state, s.len() as u64);
    Ok(())
}

fn fprintf(ctx: &mut ApiCtx) -> Result<()> {
    let stream = arg(ctx.state, 0);
    let mut k = 0usize;
    let s = format_into(ctx, arg(ctx.state, 1), |c| {
        let v = vararg(c, k + 1);
        k += 1;
        v
    });
    if stream == win_shared::H_STDERR {
        crate::write_stderr(s.as_bytes());
    } else {
        write_stdout(s.as_bytes());
    }
    ret(ctx.state, s.len() as u64);
    Ok(())
}

/// UCRT `__stdio_common_vfprintf(options, stream, fmt, locale, args)`.
/// On Windows/ARM64 `va_list` is simply a pointer into the stack argument
/// area; consume 64-bit slots from it.
fn stdio_common_vfprintf(ctx: &mut ApiCtx) -> Result<()> {
    let (_options, stream, fmt, _locale, mut args) =
        (arg(ctx.state, 0), arg(ctx.state, 1), arg(ctx.state, 2), arg(ctx.state, 3), arg(ctx.state, 4));
    let out = format_into(ctx, fmt, |c| {
        let v = c.mem.read_int(args, 8).unwrap_or(0);
        args += 8;
        v
    });
    if stream == win_shared::H_STDERR {
        crate::write_stderr(out.as_bytes());
    } else {
        write_stdout(out.as_bytes());
    }
    ret(ctx.state, out.len() as u64);
    Ok(())
}
