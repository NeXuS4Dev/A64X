//! C stdio: FILE objects, buffering, descriptors and text-mode translation.
//!
//! A `FILE*` is the guest address of a 48-byte object. The standard streams
//! live in the static area (so `__acrt_iob_func` can hand them out); other
//! streams are allocated from the process heap and released by `fclose`.
//! The host state of each stream is kept in [`Stream`], keyed by that
//! address. Disk streams buffer reads and writes (4 KiB, `setvbuf` changes
//! the mode but the user buffer itself is not used); console streams are
//! write-through so output interleaves with other host output correctly.
//! Text mode translates LF to CRLF on write and CRLF to LF on read.

use crate::format::{self, Args, OPT_STD_SNPRINTF};
use crate::k32_file;
use crate::{heap, reg, ApiCtx};
use a64x_core::Result;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

/// Size of the guest FILE object.
pub(crate) const FILE_SIZE: u64 = 0x30;
/// `EOF`.
pub(crate) const EOF: i64 = -1;
/// `_O_TEXT`.
pub(crate) const O_TEXT: u32 = 0x4000;
/// `_O_BINARY`.
pub(crate) const O_BINARY: u32 = 0x8000;
/// Default stream buffer size.
const BUF: usize = 4096;

/// Host side of a stream.
pub(crate) enum Kind {
    /// Console stream (0 = stdin, 1 = stdout, 2 = stderr).
    Console(u8),
    /// Disk file.
    Disk(std::fs::File),
}

/// State of one open stream.
pub(crate) struct Stream {
    pub kind: Kind,
    pub fd: i32,
    pub readable: bool,
    pub writable: bool,
    pub binary: bool,
    pub append: bool,
    pub eof: bool,
    pub err: bool,
    /// Raw bytes read from the host but not yet consumed.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Translated bytes waiting to be written.
    wbuf: Vec<u8>,
    /// 0 = unbuffered, 1 = line buffered, 2 = fully buffered.
    pub bufmode: u8,
    /// One character pushed back by ungetc/ungetwc.
    unget: Option<u8>,
    /// Thread holding the stream lock (0 = free) and its recursion count.
    pub lock_owner: u32,
    pub lock_count: u32,
}

impl Stream {
    fn new(kind: Kind, fd: i32, readable: bool, writable: bool, binary: bool) -> Stream {
        Stream {
            kind,
            fd,
            readable,
            writable,
            binary,
            append: false,
            eof: false,
            err: false,
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
            bufmode: 2,
            unget: None,
            lock_owner: 0,
            lock_count: 0,
        }
    }

    fn is_console(&self) -> bool {
        matches!(self.kind, Kind::Console(_))
    }
}

/// All open streams and descriptors of the process.
pub(crate) struct Stdio {
    /// Streams by FILE address.
    pub streams: BTreeMap<u64, Stream>,
    /// Descriptor number to FILE address.
    fds: BTreeMap<i32, u64>,
    /// `_setmode` values per descriptor.
    pub fd_modes: BTreeMap<i32, u32>,
    next_fd: i32,
    /// FILE addresses of stdin, stdout, stderr.
    pub std: [u64; 3],
}

impl Stdio {
    /// The three console streams over the given static FILE objects.
    pub(crate) fn new(std: [u64; 3]) -> Stdio {
        let mut streams = BTreeMap::new();
        let mut fds = BTreeMap::new();
        for i in 0..3u8 {
            let mut s = Stream::new(Kind::Console(i), i as i32, i == 0, i != 0, false);
            s.bufmode = if i == 2 { 0 } else { 1 };
            streams.insert(std[i as usize], s);
            fds.insert(i as i32, std[i as usize]);
        }
        let mut fd_modes = BTreeMap::new();
        for i in 0..3 {
            fd_modes.insert(i, O_TEXT);
        }
        Stdio {
            streams,
            fds,
            fd_modes,
            next_fd: 3,
            std,
        }
    }
}

/// `errno` for a host I/O error.
pub(crate) fn errno_of(e: &std::io::Error) -> i32 {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => 2,
        PermissionDenied => 13,
        AlreadyExists => 17,
        InvalidInput => 22,
        _ => match e.raw_os_error() {
            Some(n) if n > 0 && n < 43 => n,
            _ => 5,
        },
    }
}

/// Parse an fopen mode. Returns `(readable, writable, append, binary,
/// create_new, truncate, create, plus)`.
pub(crate) fn parse_mode(
    mode: &str,
    fmode: u32,
) -> Option<(bool, bool, bool, bool, bool, bool, bool, bool)> {
    let mut chars = mode.chars();
    let base = chars.next()?;
    let mut plus = false;
    let mut binary = fmode & O_BINARY != 0;
    let mut excl = false;
    for c in chars {
        match c {
            '+' => plus = true,
            'b' => binary = true,
            't' => binary = false,
            'x' => excl = true,
            'c' | 'n' | 'S' | 'R' | 'T' | 'D' | ',' | ' ' => {}
            _ => {}
        }
    }
    let (r, w, a, create, trunc) = match base {
        'r' => (true, plus, false, false, false),
        'w' => (plus, true, false, true, true),
        'a' => (plus, true, true, true, false),
        _ => return None,
    };
    Some((r, w, a, binary, excl, trunc, create, plus))
}

/// Open a host file for a stream and register it. Returns the FILE address.
pub(crate) fn open_stream(ctx: &mut ApiCtx, path: &str, mode: &str) -> Result<Option<u64>> {
    let fmode = crate::crt::fmode(ctx)?;
    let Some((r, w, a, binary, excl, trunc, create, _plus)) = parse_mode(mode, fmode) else {
        ctx.set_errno(22);
        return Ok(None);
    };
    let mut o = std::fs::OpenOptions::new();
    o.read(r).write(w || a).append(a);
    if excl {
        o.create_new(true);
    } else if create {
        o.create(true);
    }
    if trunc {
        o.truncate(true);
    }
    let file = match o.open(path) {
        Ok(f) => f,
        Err(e) => {
            ctx.set_errno(errno_of(&e));
            ctx.set_last_error(k32_file::win_error_of(&e));
            return Ok(None);
        }
    };
    let Some(addr) = heap::alloc(ctx, 0, FILE_SIZE, 16, true)
        .ok()
        .filter(|a| *a != 0)
    else {
        ctx.set_errno(12);
        return Ok(None);
    };
    let fd = ctx.p.stdio.next_fd;
    ctx.p.stdio.next_fd += 1;
    let mut s = Stream::new(Kind::Disk(file), fd, r, w || a, binary);
    s.append = a;
    ctx.p.stdio.streams.insert(addr, s);
    ctx.p.stdio.fds.insert(fd, addr);
    ctx.p
        .stdio
        .fd_modes
        .insert(fd, if binary { O_BINARY } else { O_TEXT });
    Ok(Some(addr))
}

/// Flush and close the stream at `addr`. Returns `Ok(false)` if `addr` is not
/// an open stream.
pub(crate) fn close(ctx: &mut ApiCtx, addr: u64) -> Result<Option<i32>> {
    if !ctx.p.stdio.streams.contains_key(&addr) {
        return Ok(None);
    }
    let flushed = flush_stream(ctx, addr)?;
    let is_std = ctx.p.stdio.std.contains(&addr);
    if let Some(s) = ctx.p.stdio.streams.remove(&addr) {
        ctx.p.stdio.fds.remove(&s.fd);
        ctx.p.stdio.fd_modes.remove(&s.fd);
        if !is_std {
            heap::free(ctx, 0, addr);
        }
    }
    Ok(Some(if flushed { 0 } else { EOF as i32 }))
}

/// Write out the write buffer of the stream at `addr`.
pub(crate) fn flush_stream(ctx: &mut ApiCtx, addr: u64) -> Result<bool> {
    let err = {
        let Some(s) = ctx.p.stdio.streams.get_mut(&addr) else {
            return Ok(false);
        };
        if s.wbuf.is_empty() {
            return Ok(true);
        }
        let data = std::mem::take(&mut s.wbuf);
        match &mut s.kind {
            Kind::Console(i) => {
                let r = if *i == 2 {
                    let mut e = std::io::stderr().lock();
                    e.write_all(&data).and_then(|_| e.flush())
                } else {
                    let mut o = std::io::stdout().lock();
                    o.write_all(&data).and_then(|_| o.flush())
                };
                r.err().map(|e| errno_of(&e))
            }
            Kind::Disk(f) => match f.write_all(&data) {
                Ok(()) => None,
                Err(e) => {
                    s.err = true;
                    Some(errno_of(&e))
                }
            },
        }
    };
    match err {
        Some(e) => {
            ctx.set_errno(e);
            Ok(false)
        }
        None => Ok(true),
    }
}

/// Flush every writable stream (exit processing).
pub(crate) fn flush_all(ctx: &mut ApiCtx) -> Result<()> {
    let addrs: Vec<u64> = ctx.p.stdio.streams.keys().copied().collect();
    for a in addrs {
        flush_stream(ctx, a)?;
    }
    Ok(())
}

/// Write raw bytes to the stream (translating LF to CRLF in text mode).
/// Returns the number of input bytes accepted, or `None` on error.
pub(crate) fn write_bytes(ctx: &mut ApiCtx, addr: u64, data: &[u8]) -> Result<Option<usize>> {
    let bad = {
        let Some(s) = ctx.p.stdio.streams.get_mut(&addr) else {
            ctx.set_errno(9);
            return Ok(None);
        };
        if !s.writable {
            s.err = true;
            true
        } else {
            let text = !s.binary && !s.is_console();
            let console = s.is_console();
            let bufmode = s.bufmode;
            let target = &mut s.wbuf;
            if text {
                for &b in data {
                    if b == b'\n' {
                        target.push(b'\r');
                    }
                    target.push(b);
                }
            } else {
                target.extend_from_slice(data);
            }
            let must_flush = target.len() >= BUF
                || bufmode == 0
                || (bufmode == 1 && data.contains(&b'\n'))
                || console;
            if !must_flush {
                return Ok(Some(data.len()));
            }
            false
        }
    };
    if bad {
        ctx.set_errno(9);
        return Ok(None);
    }
    flush_stream(ctx, addr)?;
    Ok(Some(data.len()))
}

/// Refill the raw read buffer. Returns false at end of file.
fn refill(ctx: &mut ApiCtx, addr: u64) -> Result<bool> {
    let (ok, err) = {
        let Some(s) = ctx.p.stdio.streams.get_mut(&addr) else {
            return Ok(false);
        };
        if s.rpos < s.rbuf.len() {
            return Ok(true);
        }
        s.rbuf.clear();
        s.rpos = 0;
        let mut buf = vec![0u8; BUF];
        let r = match &mut s.kind {
            // Console input is read as the host delivers it.
            Kind::Console(_) => std::io::stdin().lock().read(&mut buf),
            Kind::Disk(f) => f.read(&mut buf),
        };
        match r {
            Ok(0) => {
                s.eof = true;
                (false, None)
            }
            Ok(n) => {
                buf.truncate(n);
                s.rbuf = buf;
                (true, None)
            }
            Err(e) => {
                s.err = true;
                s.eof = true;
                (false, Some(errno_of(&e)))
            }
        }
    };
    if let Some(e) = err {
        ctx.set_errno(e);
    }
    Ok(ok)
}

/// Next character of the stream, translating CRLF to LF in text mode.
pub(crate) fn getc(ctx: &mut ApiCtx, addr: u64) -> Result<Option<u8>> {
    let (unget, readable, binary) = match ctx.p.stdio.streams.get_mut(&addr) {
        Some(s) => {
            if let Some(b) = s.unget.take() {
                return Ok(Some(b));
            }
            if !s.readable {
                s.err = true;
            }
            (None::<u8>, s.readable, s.binary || s.is_console())
        }
        None => {
            ctx.set_errno(9);
            return Ok(None);
        }
    };
    let _ = unget;
    if !readable {
        ctx.set_errno(9);
        return Ok(None);
    }
    if !refill(ctx, addr)? {
        return Ok(None);
    }
    let b = {
        let s = ctx.p.stdio.streams.get_mut(&addr).expect("stream");
        let b = s.rbuf[s.rpos];
        s.rpos += 1;
        b
    };
    if !binary && b == b'\r' {
        // CRLF reads as LF; a lone CR is returned as is.
        if !refill(ctx, addr)? {
            return Ok(Some(b'\r'));
        }
        let s = ctx.p.stdio.streams.get_mut(&addr).expect("stream");
        if s.rbuf[s.rpos] == b'\n' {
            s.rpos += 1;
            return Ok(Some(b'\n'));
        }
    }
    Ok(Some(b))
}

/// Push back one character (C requires one).
pub(crate) fn ungetc(ctx: &mut ApiCtx, addr: u64, c: u8) -> bool {
    match ctx.p.stdio.streams.get_mut(&addr) {
        Some(s) if s.readable && s.unget.is_none() => {
            s.unget = Some(c);
            s.eof = false;
            true
        }
        _ => false,
    }
}

/// Read up to `n` bytes (translated) from the stream.
pub(crate) fn read_bytes(ctx: &mut ApiCtx, addr: u64, n: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n.min(BUF));
    while out.len() < n {
        match getc(ctx, addr)? {
            Some(b) => out.push(b),
            None => break,
        }
    }
    Ok(out)
}

/// Logical position of the stream (ftell).
pub(crate) fn tell(ctx: &mut ApiCtx, addr: u64) -> Result<Option<i64>> {
    let res = {
        let Some(s) = ctx.p.stdio.streams.get_mut(&addr) else {
            return Ok(None);
        };
        match &mut s.kind {
            Kind::Console(_) => Ok(0),
            Kind::Disk(f) => match f.stream_position() {
                Ok(host) => {
                    let unread = (s.rbuf.len() - s.rpos) as i64;
                    let pending = s.wbuf.len() as i64;
                    Ok(host as i64 - unread + pending)
                }
                Err(e) => Err(errno_of(&e)),
            },
        }
    };
    match res {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            ctx.set_errno(e);
            Ok(None)
        }
    }
}

/// Reposition the stream (fseek/_fseeki64). Returns true on success.
pub(crate) fn seek(ctx: &mut ApiCtx, addr: u64, off: i64, whence: i32) -> Result<bool> {
    if !flush_stream(ctx, addr)? {
        return Ok(false);
    }
    let res: std::result::Result<(), i32> = {
        let Some(s) = ctx.p.stdio.streams.get_mut(&addr) else {
            return Ok(false);
        };
        let unread = (s.rbuf.len() - s.rpos) as i64;
        match &mut s.kind {
            Kind::Console(_) => Err(29),
            Kind::Disk(f) => {
                let from = match whence {
                    0 => Ok(SeekFrom::Start(off.max(0) as u64)),
                    1 => match f.stream_position() {
                        Ok(cur) => {
                            let target = cur as i64 - unread + off;
                            if target < 0 {
                                Err(22)
                            } else {
                                Ok(SeekFrom::Start(target as u64))
                            }
                        }
                        Err(e) => Err(errno_of(&e)),
                    },
                    2 => Ok(SeekFrom::End(off)),
                    _ => Err(22),
                };
                match from {
                    Err(e) => Err(e),
                    Ok(from) => match f.seek(from) {
                        Ok(_) => {
                            s.rbuf.clear();
                            s.rpos = 0;
                            s.unget = None;
                            s.eof = false;
                            Ok(())
                        }
                        Err(e) => Err(errno_of(&e)),
                    },
                }
            }
        }
    };
    match res {
        Ok(()) => Ok(true),
        Err(e) => {
            ctx.set_errno(e);
            Ok(false)
        }
    }
}

/// Write the characters of a formatted result: narrow bytes, or wide units
/// converted through the C locale (ASCII only; anything else is EILSEQ).
fn emit_units(ctx: &mut ApiCtx, addr: u64, units: &[u32], wide: bool) -> Result<Option<usize>> {
    let mut bytes = Vec::with_capacity(units.len());
    for &u in units {
        if wide {
            if u > 0x7F {
                ctx.set_errno(42);
                return Ok(None);
            }
            bytes.push(u as u8);
        } else {
            bytes.push(u as u8);
        }
    }
    write_bytes(ctx, addr, &bytes)
}

/// Shared implementation of the `__stdio_common_v*printf` family for files.
pub(crate) fn printf_to_stream(
    ctx: &mut ApiCtx,
    options: u64,
    addr: u64,
    fmt: &[u32],
    wide_fmt: bool,
    mut args: Args,
) -> Result<i64> {
    let out = match format::format(ctx, options, fmt, wide_fmt, &mut args)? {
        Ok(u) => u,
        Err(e) => {
            ctx.set_errno(e);
            return Ok(-1);
        }
    };
    match emit_units(ctx, addr, &out, wide_fmt)? {
        Some(_) => Ok(out.len() as i64),
        None => Ok(-1),
    }
}

/// `_write` on a descriptor.
fn write_fd(ctx: &mut ApiCtx, fd: i32, data: &[u8]) -> Result<i64> {
    let addr = match ctx.p.stdio.fds.get(&fd) {
        Some(a) => *a,
        None => {
            ctx.set_errno(9);
            return Ok(-1);
        }
    };
    let mode = ctx.p.stdio.fd_modes.get(&fd).copied().unwrap_or(O_TEXT);
    if let Some(s) = ctx.p.stdio.streams.get_mut(&addr) {
        s.binary = mode & O_BINARY != 0;
    }
    match write_bytes(ctx, addr, data)? {
        Some(n) => {
            flush_stream(ctx, addr)?;
            Ok(n as i64)
        }
        None => Ok(-1),
    }
}

/// Register all stdio adapters.
pub(crate) fn register(v: &mut Vec<crate::ApiDef>) {
    reg!(v, "ucrtbase",
        "__acrt_iob_func" => acrt_iob_func,
        "__p__commode" => p_commode,
        "__p__fmode" => p_fmode,
        "__stdio_common_vfprintf" => stdio_vfprintf,
        "__stdio_common_vfwprintf" => stdio_vfwprintf,
        "__stdio_common_vsprintf" => stdio_vsprintf,
        "__stdio_common_vsnprintf_s" => stdio_vsnprintf_s,
        "__stdio_common_vsscanf" => stdio_vsscanf,
        "_fileno" => fileno,
        "_fseeki64" => fseeki64,
        "_ftelli64" => ftelli64,
        "_setmode" => setmode,
        "_wfopen" => wfopen,
        "_write" => write,
        "fclose" => fclose,
        "fflush" => fflush,
        "fgetwc" => fgetwc,
        "fopen" => fopen,
        "fputc" => fputc,
        "fputwc" => fputwc,
        "fread" => fread,
        "fseek" => fseek,
        "fwrite" => fwrite,
        "getc" => getc_adapter,
        "setbuf" => setbuf,
        "setvbuf" => setvbuf,
        "ungetc" => ungetc_adapter,
        "ungetwc" => ungetwc,
        "fgetc" => getc_adapter,
        "fputs" => fputs,
        "fgets" => fgets,
        "ftell" => ftell,
        "feof" => feof,
        "ferror" => ferror,
        "clearerr" => clearerr,
        "rewind" => rewind,
        "printf" => printf,
        "fprintf" => fprintf,
        "sprintf" => sprintf,
        "snprintf" => snprintf,
        "_snprintf" => snprintf,
        "puts" => puts,
        "putchar" => putchar,
        "getchar" => getchar,
        "wprintf" => wprintf,
        "fwprintf" => fwprintf,
    );
}

fn stream_arg(ctx: &ApiCtx, i: usize) -> u64 {
    ctx.a(i)
}

fn acrt_iob_func(ctx: &mut ApiCtx) -> Result<()> {
    let i = ctx.au(0);
    if i < 3 {
        let a = ctx.p.stdio.std[i as usize];
        ctx.ret(a);
    } else {
        ctx.ret(0);
    }
    Ok(())
}

fn p_commode(ctx: &mut ApiCtx) -> Result<()> {
    let a = crate::crt::var_commode(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn p_fmode(ctx: &mut ApiCtx) -> Result<()> {
    let a = crate::crt::var_fmode(ctx)?;
    ctx.ret(a);
    Ok(())
}

/// `__stdio_common_vfprintf(options, stream, format, locale, va_list)`.
fn stdio_vfprintf(ctx: &mut ApiCtx) -> Result<()> {
    let opts = ctx.a(0);
    let stream = ctx.a(1);
    let fmt = format::narrow_units(ctx, ctx.a(2))?;
    let args = Args::va(ctx.a(4));
    let r = printf_to_stream(ctx, opts, stream, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn stdio_vfwprintf(ctx: &mut ApiCtx) -> Result<()> {
    let opts = ctx.a(0);
    let stream = ctx.a(1);
    let fmt = format::wide_units(ctx, ctx.a(2))?;
    let args = Args::va(ctx.a(4));
    let r = printf_to_stream(ctx, opts, stream, &fmt, true, args)?;
    ctx.ret(r as u64);
    Ok(())
}

/// `__stdio_common_vsprintf(options, buffer, count, format, locale, va_list)`.
fn stdio_vsprintf(ctx: &mut ApiCtx) -> Result<()> {
    let opts = ctx.a(0);
    let buf = ctx.a(1);
    let count = ctx.a(2);
    let fmt = format::narrow_units(ctx, ctx.a(3))?;
    let args = Args::va(ctx.a(5));
    let r = format_into_buffer(ctx, opts, buf, count, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

/// `__stdio_common_vsnprintf_s(options, buffer, size, count, format, locale, va_list)`.
fn stdio_vsnprintf_s(ctx: &mut ApiCtx) -> Result<()> {
    let opts = ctx.a(0);
    let buf = ctx.a(1);
    let size = ctx.a(2);
    let count = ctx.a(3);
    let fmt = format::narrow_units(ctx, ctx.a(4))?;
    let args = Args::va(ctx.a(6));
    let limit = if count == u64::MAX {
        size
    } else {
        count.min(size)
    };
    let r = format_into_buffer(ctx, opts, buf, limit, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

/// Format into a guest buffer of `cap` bytes (units). Honours the legacy
/// (-1 on truncation) and standard (would-be length) snprintf behaviours.
pub(crate) fn format_into_buffer(
    ctx: &mut ApiCtx,
    options: u64,
    buf: u64,
    cap: u64,
    fmt: &[u32],
    wide: bool,
    mut args: Args,
) -> Result<i64> {
    let out = match format::format(ctx, options, fmt, wide, &mut args)? {
        Ok(u) => u,
        Err(e) => {
            ctx.set_errno(e);
            return Ok(-1);
        }
    };
    let unit = if wide { 2u64 } else { 1 };
    let total = out.len() as u64;
    if buf == 0 && cap != 0 {
        ctx.set_errno(22);
        return Ok(-1);
    }
    if cap == 0 || buf == 0 {
        return Ok(if options & OPT_STD_SNPRINTF != 0 {
            total as i64
        } else {
            -1
        });
    }
    let fit = (cap - 1).min(total);
    for (i, u) in out.iter().take(fit as usize).enumerate() {
        let a = buf + i as u64 * unit;
        if wide {
            ctx.wr(a, 2, *u as u64 & 0xFFFF)?;
        } else {
            ctx.wr(a, 1, *u as u64 & 0xFF)?;
        }
    }
    let term = buf + fit * unit;
    if wide {
        ctx.wr(term, 2, 0)?;
    } else {
        ctx.wr(term, 1, 0)?;
    }
    if fit < total {
        // truncated
        if options & OPT_STD_SNPRINTF != 0 {
            return Ok(total as i64);
        }
        ctx.set_errno(34);
        return Ok(-1);
    }
    Ok(total as i64)
}

/// `__stdio_common_vsscanf(options, input, length, format, locale, va_list)`.
fn stdio_vsscanf(ctx: &mut ApiCtx) -> Result<()> {
    let opts = ctx.a(0);
    let input_addr = ctx.a(1);
    let len = ctx.a(2);
    let fmt = format::narrow_units(ctx, ctx.a(3))?;
    let args = Args::va(ctx.a(5));
    let input = if len == u64::MAX {
        ctx.cstr(input_addr)?
    } else {
        ctx.bytes(input_addr, len)?
    };
    let r = crate::scan::sscanf(ctx, opts, &input, &fmt, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn fileno(ctx: &mut ApiCtx) -> Result<()> {
    let s = stream_arg(ctx, 0);
    let fd = ctx.p.stdio.streams.get(&s).map(|s| s.fd).unwrap_or(-1);
    ctx.ret_i32(fd);
    Ok(())
}

fn fseeki64(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let off = ctx.ai64(1);
    let whence = ctx.ai(2);
    let ok = seek(ctx, s, off, whence)?;
    ctx.ret_i32(if ok { 0 } else { -1 });
    Ok(())
}

fn ftelli64(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let r = tell(ctx, s)?.unwrap_or(-1);
    ctx.ret(r as u64);
    Ok(())
}

fn fseek(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let off = ctx.ai(1) as i64;
    let whence = ctx.ai(2);
    let ok = seek(ctx, s, off, whence)?;
    ctx.ret_i32(if ok { 0 } else { -1 });
    Ok(())
}

fn setmode(ctx: &mut ApiCtx) -> Result<()> {
    let fd = ctx.ai(0);
    let mode = ctx.au(1);
    if !ctx.p.stdio.fds.contains_key(&fd) {
        ctx.set_errno(9);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    if mode != O_TEXT && mode != O_BINARY {
        ctx.set_errno(22);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    let prev = ctx.p.stdio.fd_modes.insert(fd, mode).unwrap_or(O_TEXT);
    let addr = ctx.p.stdio.fds[&fd];
    if let Some(s) = ctx.p.stdio.streams.get_mut(&addr) {
        s.binary = mode == O_BINARY;
    }
    ctx.ret(prev as u64);
    Ok(())
}

fn wfopen(ctx: &mut ApiCtx) -> Result<()> {
    let path = ctx.wstr_string(ctx.a(0))?;
    let mode = ctx.wstr_string(ctx.a(1))?;
    let r = open_stream(ctx, &path, &mode)?.unwrap_or(0);
    ctx.ret(r);
    Ok(())
}

fn fopen(ctx: &mut ApiCtx) -> Result<()> {
    let path = ctx.cstr_string(ctx.a(0))?;
    let mode = ctx.cstr_string(ctx.a(1))?;
    let r = open_stream(ctx, &path, &mode)?.unwrap_or(0);
    ctx.ret(r);
    Ok(())
}

fn write(ctx: &mut ApiCtx) -> Result<()> {
    let fd = ctx.ai(0);
    let buf = ctx.a(1);
    let n = ctx.au(2) as u64;
    let data = ctx.bytes(buf, n)?;
    let r = write_fd(ctx, fd, &data)?;
    ctx.ret(r as u64);
    Ok(())
}

fn fclose(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let r = close(ctx, s)?.unwrap_or(EOF as i32);
    ctx.ret_i32(r);
    Ok(())
}

fn fflush(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    if s == 0 {
        flush_all(ctx)?;
        ctx.ret_i32(0);
        return Ok(());
    }
    let ok = flush_stream(ctx, s)?;
    ctx.ret_i32(if ok { 0 } else { -1 });
    Ok(())
}

fn fgetwc(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    match getc(ctx, s)? {
        Some(b) if b <= 0x7F => ctx.ret(b as u64),
        Some(_) => {
            ctx.set_errno(42);
            ctx.ret(0xFFFF);
        }
        None => ctx.ret(0xFFFF),
    }
    Ok(())
}

fn fputc(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.au(0) as u8;
    let s = ctx.a(1);
    match write_bytes(ctx, s, &[c])? {
        Some(_) => ctx.ret_i32(c as i32),
        None => ctx.ret_i32(-1),
    }
    Ok(())
}

fn fputwc(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.au(0);
    let s = ctx.a(1);
    if c > 0x7F {
        ctx.set_errno(42);
        ctx.ret(0xFFFF);
        return Ok(());
    }
    match write_bytes(ctx, s, &[c as u8])? {
        Some(_) => ctx.ret(c as u64),
        None => ctx.ret(0xFFFF),
    }
    Ok(())
}

fn fread(ctx: &mut ApiCtx) -> Result<()> {
    let buf = ctx.a(0);
    let size = ctx.a(1);
    let count = ctx.a(2);
    let s = ctx.a(3);
    let want = size.saturating_mul(count);
    if want == 0 {
        ctx.ret(0);
        return Ok(());
    }
    let data = read_bytes(ctx, s, want as usize)?;
    ctx.put(buf, &data)?;
    ctx.ret(data.len() as u64 / size.max(1));
    Ok(())
}

fn fwrite(ctx: &mut ApiCtx) -> Result<()> {
    let buf = ctx.a(0);
    let size = ctx.a(1);
    let count = ctx.a(2);
    let s = ctx.a(3);
    let total = size.saturating_mul(count);
    if total == 0 {
        ctx.ret(0);
        return Ok(());
    }
    let data = ctx.bytes(buf, total)?;
    match write_bytes(ctx, s, &data)? {
        Some(_) => ctx.ret(count),
        None => ctx.ret(0),
    }
    Ok(())
}

fn getc_adapter(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    match getc(ctx, s)? {
        Some(b) => ctx.ret_i32(b as i32),
        None => ctx.ret_i32(-1),
    }
    Ok(())
}

fn setbuf(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let buf = ctx.a(1);
    if let Some(st) = ctx.p.stdio.streams.get_mut(&s) {
        st.bufmode = if buf == 0 { 0 } else { 2 };
    }
    Ok(())
}

fn setvbuf(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let mode = ctx.au(2);
    let kind = match mode {
        0x0000 => 2u8, // _IOFBF
        0x0040 => 1,   // _IOLBF
        0x0004 => 0,   // _IONBF
        _ => {
            ctx.ret_i32(-1);
            return Ok(());
        }
    };
    if !ctx.p.stdio.streams.contains_key(&s) {
        ctx.ret_i32(-1);
        return Ok(());
    }
    flush_stream(ctx, s)?;
    if let Some(st) = ctx.p.stdio.streams.get_mut(&s) {
        st.bufmode = kind;
    }
    ctx.ret_i32(0);
    Ok(())
}

fn ungetc_adapter(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let s = ctx.a(1);
    if c == -1 || !ungetc(ctx, s, c as u8) {
        ctx.ret_i32(-1);
    } else {
        ctx.ret_i32(c & 0xFF);
    }
    Ok(())
}

fn ungetwc(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.au(0);
    let s = ctx.a(1);
    if c == 0xFFFF || c > 0x7F || !ungetc(ctx, s, c as u8) {
        ctx.ret(0xFFFF);
    } else {
        ctx.ret(c as u64);
    }
    Ok(())
}

fn fputs(ctx: &mut ApiCtx) -> Result<()> {
    let text = ctx.cstr(ctx.a(0))?;
    let s = ctx.a(1);
    match write_bytes(ctx, s, &text)? {
        Some(_) => ctx.ret_i32(0),
        None => ctx.ret_i32(EOF as i32),
    }
    Ok(())
}

fn fgets(ctx: &mut ApiCtx) -> Result<()> {
    let buf = ctx.a(0);
    let n = ctx.ai(1);
    let s = ctx.a(2);
    if n <= 0 {
        ctx.ret(0);
        return Ok(());
    }
    let mut out = Vec::new();
    while (out.len() as i64) < n as i64 - 1 {
        match getc(ctx, s)? {
            Some(b) => {
                out.push(b);
                if b == b'\n' {
                    break;
                }
            }
            None => break,
        }
    }
    if out.is_empty() {
        ctx.ret(0);
        return Ok(());
    }
    out.push(0);
    ctx.put(buf, &out)?;
    ctx.ret(buf);
    Ok(())
}

fn ftell(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let r = tell(ctx, s)?.unwrap_or(-1);
    ctx.ret_i32(r as i32);
    Ok(())
}

fn feof(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let e = ctx.p.stdio.streams.get(&s).map(|s| s.eof).unwrap_or(false);
    ctx.ret_i32(e as i32);
    Ok(())
}

fn ferror(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let e = ctx.p.stdio.streams.get(&s).map(|s| s.err).unwrap_or(false);
    ctx.ret_i32(e as i32);
    Ok(())
}

fn clearerr(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    if let Some(st) = ctx.p.stdio.streams.get_mut(&s) {
        st.eof = false;
        st.err = false;
    }
    Ok(())
}

fn rewind(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    seek(ctx, s, 0, 0)?;
    if let Some(st) = ctx.p.stdio.streams.get_mut(&s) {
        st.err = false;
    }
    Ok(())
}

fn printf(ctx: &mut ApiCtx) -> Result<()> {
    let fmt = format::narrow_units(ctx, ctx.a(0))?;
    let args = Args::regs(ctx, 1);
    let stdout = ctx.p.stdio.std[1];
    let r = printf_to_stream(ctx, 0, stdout, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn fprintf(ctx: &mut ApiCtx) -> Result<()> {
    let stream = ctx.a(0);
    let fmt = format::narrow_units(ctx, ctx.a(1))?;
    let args = Args::regs(ctx, 2);
    let r = printf_to_stream(ctx, 0, stream, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn wprintf(ctx: &mut ApiCtx) -> Result<()> {
    let fmt = format::wide_units(ctx, ctx.a(0))?;
    let args = Args::regs(ctx, 1);
    let stdout = ctx.p.stdio.std[1];
    let r = printf_to_stream(ctx, 4, stdout, &fmt, true, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn fwprintf(ctx: &mut ApiCtx) -> Result<()> {
    let stream = ctx.a(0);
    let fmt = format::wide_units(ctx, ctx.a(1))?;
    let args = Args::regs(ctx, 2);
    let r = printf_to_stream(ctx, 4, stream, &fmt, true, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn sprintf(ctx: &mut ApiCtx) -> Result<()> {
    let buf = ctx.a(0);
    let fmt = format::narrow_units(ctx, ctx.a(1))?;
    let args = Args::regs(ctx, 2);
    let r = format_into_buffer(ctx, 2, buf, u64::MAX, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn snprintf(ctx: &mut ApiCtx) -> Result<()> {
    let buf = ctx.a(0);
    let cap = ctx.a(1);
    let fmt = format::narrow_units(ctx, ctx.a(2))?;
    let args = Args::regs(ctx, 3);
    let r = format_into_buffer(ctx, 2, buf, cap, &fmt, false, args)?;
    ctx.ret(r as u64);
    Ok(())
}

fn puts(ctx: &mut ApiCtx) -> Result<()> {
    let mut text = ctx.cstr(ctx.a(0))?;
    text.push(b'\n');
    let stdout = ctx.p.stdio.std[1];
    match write_bytes(ctx, stdout, &text)? {
        Some(_) => ctx.ret_i32(1),
        None => ctx.ret_i32(-1),
    }
    Ok(())
}

fn putchar(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.au(0) as u8;
    let stdout = ctx.p.stdio.std[1];
    match write_bytes(ctx, stdout, &[c])? {
        Some(_) => ctx.ret_i32(c as i32),
        None => ctx.ret_i32(-1),
    }
    Ok(())
}

fn getchar(ctx: &mut ApiCtx) -> Result<()> {
    let stdin = ctx.p.stdio.std[0];
    match getc(ctx, stdin)? {
        Some(b) => ctx.ret_i32(b as i32),
        None => ctx.ret_i32(-1),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse() {
        let (r, w, a, bin, excl, trunc, create, plus) = parse_mode("w+b", 0).unwrap();
        assert!(
            r && w && !a && bin && !excl && trunc && create && plus,
            "w+ is readable and writable"
        );
        assert!(parse_mode("q", 0).is_none());
        let (_, _, _, bin2, ..) = parse_mode("r", O_BINARY).unwrap();
        assert!(bin2, "_fmode binary default applies");
    }

    #[test]
    fn errno_mapping() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(errno_of(&e), 2);
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(errno_of(&e), 13);
    }
}
