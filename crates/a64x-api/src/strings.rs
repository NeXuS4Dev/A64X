//! String and memory functions (narrow and wide), plus the vcruntime
//! memory primitives. Comparisons are unsigned byte/unit comparisons, as in
//! the C runtime; the C locale collation is code-point order.

use crate::{heap, reg, ApiCtx, ApiDef};
use a64x_core::Result;

/// Read the bytes of a NUL-terminated ANSI string at `a` (up to `max`).
fn bytes_of(ctx: &ApiCtx, a: u64) -> Result<Vec<u8>> {
    ctx.cstr(a)
}

/// Units of a NUL-terminated wide string at `a`.
fn units_of(ctx: &ApiCtx, a: u64) -> Result<Vec<u16>> {
    ctx.wstr(a)
}

fn put_bytes_nul(ctx: &mut ApiCtx, dst: u64, s: &[u8]) -> Result<()> {
    ctx.put(dst, s)?;
    ctx.wr(dst + s.len() as u64, 1, 0)
}

fn put_units_nul(ctx: &mut ApiCtx, dst: u64, s: &[u16]) -> Result<()> {
    ctx.put_wide(dst, s)?;
    ctx.wr(dst + 2 * s.len() as u64, 2, 0)
}

fn memcpy(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2));
    if n > 0 {
        let data = ctx.bytes(s, n)?;
        ctx.put(d, &data)?;
    }
    ctx.ret(d);
    Ok(())
}

fn memmove(ctx: &mut ApiCtx) -> Result<()> {
    // The snapshot makes overlapping regions behave as if copied via a temporary.
    memcpy(ctx)
}

fn memset(ctx: &mut ApiCtx) -> Result<()> {
    let (d, c, n) = (ctx.a(0), ctx.au(1) as u8, ctx.a(2));
    if n > 0 {
        // bounds-checked in place: no host allocation for the fill length
        ctx.mem.slice_mut(d, n)?.fill(c);
    }
    ctx.ret(d);
    Ok(())
}

fn memcmp(ctx: &mut ApiCtx) -> Result<()> {
    let (a, b, n) = (ctx.a(0), ctx.a(1), ctx.a(2));
    let x = ctx.bytes(a, n)?;
    let y = ctx.bytes(b, n)?;
    let r = match x.cmp(&y) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    ctx.ret_i32(r);
    Ok(())
}

fn memchr(ctx: &mut ApiCtx) -> Result<()> {
    let (p, c, n) = (ctx.a(0), ctx.au(1) as u8, ctx.a(2));
    let data = ctx.bytes(p, n)?;
    let r = data
        .iter()
        .position(|b| *b == c)
        .map(|i| p + i as u64)
        .unwrap_or(0);
    ctx.ret(r);
    Ok(())
}

fn strlen(ctx: &mut ApiCtx) -> Result<()> {
    let n = bytes_of(ctx, ctx.a(0))?.len();
    ctx.ret(n as u64);
    Ok(())
}

fn strnlen(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.cstr_max(ctx.a(0), ctx.a(1) as usize)?.len();
    ctx.ret(n as u64);
    Ok(())
}

fn wcslen(ctx: &mut ApiCtx) -> Result<()> {
    let n = units_of(ctx, ctx.a(0))?.len();
    ctx.ret(n as u64);
    Ok(())
}

fn wcsnlen(ctx: &mut ApiCtx) -> Result<()> {
    let max = ctx.a(1) as usize;
    let n = ctx.mem.read_wstr(ctx.a(0), max)?.len();
    ctx.ret(n as u64);
    Ok(())
}

fn cmp_result(o: std::cmp::Ordering) -> i32 {
    match o {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

fn fold_ascii(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

fn strcmp(ctx: &mut ApiCtx) -> Result<()> {
    let x = bytes_of(ctx, ctx.a(0))?;
    let y = bytes_of(ctx, ctx.a(1))?;
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn strncmp(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.a(2) as usize;
    let x = ctx.cstr_max(ctx.a(0), n)?;
    let y = ctx.cstr_max(ctx.a(1), n)?;
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn stricmp(ctx: &mut ApiCtx) -> Result<()> {
    let x: Vec<u8> = bytes_of(ctx, ctx.a(0))?
        .iter()
        .map(|b| fold_ascii(*b))
        .collect();
    let y: Vec<u8> = bytes_of(ctx, ctx.a(1))?
        .iter()
        .map(|b| fold_ascii(*b))
        .collect();
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn strnicmp(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.a(2) as usize;
    let x: Vec<u8> = ctx
        .cstr_max(ctx.a(0), n)?
        .iter()
        .map(|b| fold_ascii(*b))
        .collect();
    let y: Vec<u8> = ctx
        .cstr_max(ctx.a(1), n)?
        .iter()
        .map(|b| fold_ascii(*b))
        .collect();
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn wcscmp(ctx: &mut ApiCtx) -> Result<()> {
    let x = units_of(ctx, ctx.a(0))?;
    let y = units_of(ctx, ctx.a(1))?;
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn wcsncmp(ctx: &mut ApiCtx) -> Result<()> {
    let n = ctx.a(2) as usize;
    let x = ctx.mem.read_wstr(ctx.a(0), n)?;
    let y = ctx.mem.read_wstr(ctx.a(1), n)?;
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn wcsicmp(ctx: &mut ApiCtx) -> Result<()> {
    let fold = |u: u16| {
        char::from_u32(u as u32)
            .map(|c| c.to_lowercase().next().unwrap_or(c) as u32)
            .unwrap_or(u as u32)
    };
    let x: Vec<u32> = units_of(ctx, ctx.a(0))?
        .into_iter()
        .map(|u| fold(u))
        .collect();
    let y: Vec<u32> = units_of(ctx, ctx.a(1))?
        .into_iter()
        .map(|u| fold(u))
        .collect();
    ctx.ret_i32(cmp_result(x.cmp(&y)));
    Ok(())
}

fn strcpy(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s) = (ctx.a(0), ctx.a(1));
    let v = bytes_of(ctx, s)?;
    put_bytes_nul(ctx, d, &v)?;
    ctx.ret(d);
    Ok(())
}

fn strncpy(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2) as usize);
    let v = ctx.cstr_max(s, n)?;
    // copy, then pad with NULs up to n (bounds-checked by the destination write)
    ctx.zero(d, n as u64)?;
    ctx.put(d, &v)?;
    ctx.ret(d);
    Ok(())
}

fn strcat(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s) = (ctx.a(0), ctx.a(1));
    let dl = bytes_of(ctx, d)?.len() as u64;
    let v = bytes_of(ctx, s)?;
    put_bytes_nul(ctx, d + dl, &v)?;
    ctx.ret(d);
    Ok(())
}

fn strncat(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2) as usize);
    let dl = bytes_of(ctx, d)?.len() as u64;
    let v = ctx.cstr_max(s, n)?;
    put_bytes_nul(ctx, d + dl, &v)?;
    ctx.ret(d);
    Ok(())
}

fn strchr(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let c = ctx.au(1) as u8;
    let v = bytes_of(ctx, s)?;
    // searching for NUL finds the terminator
    let r = if c == 0 {
        s + v.len() as u64
    } else {
        v.iter()
            .position(|b| *b == c)
            .map(|i| s + i as u64)
            .unwrap_or(0)
    };
    ctx.ret(r);
    Ok(())
}

fn strrchr(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let c = ctx.au(1) as u8;
    let v = bytes_of(ctx, s)?;
    let r = if c == 0 {
        s + v.len() as u64
    } else {
        v.iter()
            .rposition(|b| *b == c)
            .map(|i| s + i as u64)
            .unwrap_or(0)
    };
    ctx.ret(r);
    Ok(())
}

fn strstr(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let hay = bytes_of(ctx, s)?;
    let needle = bytes_of(ctx, ctx.a(1))?;
    let r = if needle.is_empty() {
        s
    } else {
        hay.windows(needle.len())
            .position(|w| w == needle.as_slice())
            .map(|i| s + i as u64)
            .unwrap_or(0)
    };
    ctx.ret(r);
    Ok(())
}

fn wcscpy(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s) = (ctx.a(0), ctx.a(1));
    let v = units_of(ctx, s)?;
    put_units_nul(ctx, d, &v)?;
    ctx.ret(d);
    Ok(())
}

fn wcsncpy(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2) as usize);
    let v = ctx.mem.read_wstr(s, n)?;
    ctx.zero(d, 2 * n as u64)?;
    ctx.put_wide(d, &v)?;
    ctx.ret(d);
    Ok(())
}

fn wcschr(ctx: &mut ApiCtx) -> Result<()> {
    let s = ctx.a(0);
    let c = ctx.au(1) as u16;
    let v = units_of(ctx, s)?;
    let r = if c == 0 {
        s + 2 * v.len() as u64
    } else {
        v.iter()
            .position(|u| *u == c)
            .map(|i| s + 2 * i as u64)
            .unwrap_or(0)
    };
    ctx.ret(r);
    Ok(())
}

fn strdup(ctx: &mut ApiCtx) -> Result<()> {
    let v = bytes_of(ctx, ctx.a(0))?;
    let p = heap::alloc(ctx, 0, v.len() as u64 + 1, 16, false)?;
    if p == 0 {
        ctx.set_errno(12);
        ctx.ret(0);
        return Ok(());
    }
    put_bytes_nul(ctx, p, &v)?;
    ctx.ret(p);
    Ok(())
}

fn wcsdup(ctx: &mut ApiCtx) -> Result<()> {
    let v = units_of(ctx, ctx.a(0))?;
    let p = heap::alloc(ctx, 0, 2 * (v.len() as u64 + 1), 16, false)?;
    if p == 0 {
        ctx.set_errno(12);
        ctx.ret(0);
        return Ok(());
    }
    put_units_nul(ctx, p, &v)?;
    ctx.ret(p);
    Ok(())
}

/// `_strcoll_l`/`_strxfrm_l` in the C locale: plain code-point order.
fn strcoll_l(ctx: &mut ApiCtx) -> Result<()> {
    strcmp(ctx)
}

fn wcscoll_l(ctx: &mut ApiCtx) -> Result<()> {
    wcscmp(ctx)
}

fn strxfrm_l(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2) as usize);
    let v = bytes_of(ctx, s)?;
    if n > v.len() && d != 0 {
        put_bytes_nul(ctx, d, &v)?;
    }
    ctx.ret(v.len() as u64);
    Ok(())
}

fn wcsxfrm_l(ctx: &mut ApiCtx) -> Result<()> {
    let (d, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2) as usize);
    let v = units_of(ctx, s)?;
    if n > v.len() && d != 0 {
        put_units_nul(ctx, d, &v)?;
    }
    ctx.ret(v.len() as u64);
    Ok(())
}

/// C-locale classification flags (UCRT `_ctype` bits).
pub(crate) const C_UPPER: u16 = 0x1;
pub(crate) const C_LOWER: u16 = 0x2;
pub(crate) const C_DIGIT: u16 = 0x4;
pub(crate) const C_SPACE: u16 = 0x8;
pub(crate) const C_PUNCT: u16 = 0x10;
pub(crate) const C_CONTROL: u16 = 0x20;
pub(crate) const C_BLANK: u16 = 0x40;
pub(crate) const C_HEX: u16 = 0x80;
pub(crate) const C_ALPHA: u16 = 0x100;

/// Classification of a byte in the C locale (ASCII only).
pub(crate) fn c_flags(c: u8) -> u16 {
    if c >= 0x80 {
        return 0;
    }
    let mut f = 0;
    let ch = c as char;
    if ch.is_ascii_uppercase() {
        f |= C_UPPER | C_ALPHA;
    }
    if ch.is_ascii_lowercase() {
        f |= C_LOWER | C_ALPHA;
    }
    if ch.is_ascii_digit() {
        f |= C_DIGIT;
    }
    if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C) {
        f |= C_SPACE;
    }
    if ch.is_ascii_punctuation() {
        f |= C_PUNCT;
    }
    if c < 0x20 || c == 0x7F {
        f |= C_CONTROL;
    }
    if c == b' ' || c == b'\t' {
        f |= C_BLANK;
    }
    if ch.is_ascii_hexdigit() {
        f |= C_HEX;
    }
    f
}

fn isctype_flags(c: i32) -> u16 {
    if !(0..=255).contains(&c) {
        0
    } else {
        c_flags(c as u8)
    }
}

macro_rules! ctype_fn {
    ($name:ident, $mask:expr) => {
        fn $name(ctx: &mut ApiCtx) -> Result<()> {
            let c = ctx.ai(0);
            let r = (isctype_flags(c) & $mask) != 0;
            ctx.ret_i32(r as i32);
            Ok(())
        }
    };
}

ctype_fn!(isalpha, C_ALPHA);
ctype_fn!(isupper, C_UPPER);
ctype_fn!(islower, C_LOWER);
ctype_fn!(isdigit, C_DIGIT);
ctype_fn!(isspace, C_SPACE);
ctype_fn!(ispunct, C_PUNCT);
ctype_fn!(iscntrl, C_CONTROL);
ctype_fn!(isxdigit, C_HEX);
ctype_fn!(isblank, C_BLANK);

fn isalnum(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let r = (isctype_flags(c) & (C_ALPHA | C_DIGIT)) != 0;
    ctx.ret_i32(r as i32);
    Ok(())
}

fn isgraph(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let r = (isctype_flags(c) & (C_ALPHA | C_DIGIT | C_PUNCT)) != 0;
    ctx.ret_i32(r as i32);
    Ok(())
}

fn isprint(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let r = (isctype_flags(c) & (C_ALPHA | C_DIGIT | C_PUNCT | C_BLANK)) != 0 && c != 0x09;
    ctx.ret_i32(r as i32);
    Ok(())
}

fn tolower(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let r = if (b'A' as i32..=b'Z' as i32).contains(&c) {
        c + 32
    } else {
        c
    };
    ctx.ret_i32(r);
    Ok(())
}

fn toupper(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let r = if (b'a' as i32..=b'z' as i32).contains(&c) {
        c - 32
    } else {
        c
    };
    ctx.ret_i32(r);
    Ok(())
}

/// `_isctype_l(c, mask, locale)`.
fn isctype_l(ctx: &mut ApiCtx) -> Result<()> {
    let c = ctx.ai(0);
    let mask = ctx.au(1) as u16;
    ctx.ret_i32((isctype_flags(c) & mask != 0) as i32);
    Ok(())
}

/// Wide classification using Unicode properties (UCRT wide ctype).
fn wide_class(ctx: &mut ApiCtx, pred: fn(char) -> bool) -> Result<()> {
    let u = ctx.au(0) & 0xFFFF;
    let r = char::from_u32(u).map(pred).unwrap_or(false);
    ctx.ret_i32(r as i32);
    Ok(())
}

fn iswalpha_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_alphabetic)
}
fn iswalnum_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_alphanumeric)
}
fn iswdigit_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| c.is_ascii_digit())
}
fn iswxdigit_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| c.is_ascii_hexdigit())
}
fn iswspace_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_whitespace)
}
fn iswupper_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_uppercase)
}
fn iswlower_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_lowercase)
}
fn iswpunct_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| {
        c.is_ascii_punctuation()
            || (!c.is_ascii() && !c.is_alphanumeric() && !c.is_whitespace() && !c.is_control())
    })
}
fn iswcntrl_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, char::is_control)
}
fn iswgraph_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| !c.is_whitespace() && !c.is_control())
}
fn iswprint_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| !c.is_control())
}
fn iswblank_l(ctx: &mut ApiCtx) -> Result<()> {
    wide_class(ctx, |c| c == ' ' || c == '\t')
}

/// `_iswctype_l(wc, desc, locale)` with the standard descriptor bits.
fn iswctype_l(ctx: &mut ApiCtx) -> Result<()> {
    let u = ctx.au(0) & 0xFFFF;
    let desc = ctx.au(1) as u16;
    let c = char::from_u32(u);
    let r = match c {
        None => false,
        Some(c) => {
            (desc & C_UPPER != 0 && c.is_uppercase())
                || (desc & C_LOWER != 0 && c.is_lowercase())
                || (desc & C_ALPHA != 0 && c.is_alphabetic())
                || (desc & C_DIGIT != 0 && c.is_ascii_digit())
                || (desc & C_SPACE != 0 && c.is_whitespace())
                || (desc & C_HEX != 0 && c.is_ascii_hexdigit())
        }
    };
    ctx.ret_i32(r as i32);
    Ok(())
}

fn towlower_l(ctx: &mut ApiCtx) -> Result<()> {
    let u = ctx.au(0) & 0xFFFF;
    let r = char::from_u32(u)
        .map(|c| c.to_lowercase().next().unwrap_or(c) as u32)
        .filter(|v| *v <= 0xFFFF)
        .unwrap_or(u);
    ctx.ret(r as u64);
    Ok(())
}

fn towupper_l(ctx: &mut ApiCtx) -> Result<()> {
    let u = ctx.au(0) & 0xFFFF;
    let r = char::from_u32(u)
        .map(|c| c.to_uppercase().next().unwrap_or(c) as u32)
        .filter(|v| *v <= 0xFFFF)
        .unwrap_or(u);
    ctx.ret(r as u64);
    Ok(())
}

fn tolower_l(ctx: &mut ApiCtx) -> Result<()> {
    toupper_tolower(ctx, false)
}

fn toupper_l(ctx: &mut ApiCtx) -> Result<()> {
    toupper_tolower(ctx, true)
}

fn toupper_tolower(ctx: &mut ApiCtx, upper: bool) -> Result<()> {
    let c = ctx.ai(0);
    let r = if upper {
        if (b'a' as i32..=b'z' as i32).contains(&c) {
            c - 32
        } else {
            c
        }
    } else if (b'A' as i32..=b'Z' as i32).contains(&c) {
        c + 32
    } else {
        c
    };
    ctx.ret_i32(r);
    Ok(())
}

/// `mbrlen(s, n, ps)` in the C locale (one byte per character).
fn mbrlen(ctx: &mut ApiCtx) -> Result<()> {
    let (s, n) = (ctx.a(0), ctx.a(1));
    if s == 0 {
        ctx.ret(0);
        return Ok(());
    }
    if n == 0 {
        ctx.ret(u64::MAX - 1);
        return Ok(());
    }
    let b = ctx.rd(s, 1)? as u8;
    if b >= 0x80 {
        ctx.set_errno(42);
        ctx.ret(u64::MAX);
    } else {
        ctx.ret(if b == 0 { 0 } else { 1 });
    }
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "vcruntime140",
        "memchr" => memchr,
        "memcmp" => memcmp,
        "memcpy" => memcpy,
        "memmove" => memmove,
    );
    reg!(v, "ucrtbase",
        "memset" => memset,
        "strlen" => strlen,
        "strnlen" => strnlen,
        "wcslen" => wcslen,
        "wcsnlen" => wcsnlen,
        "strcmp" => strcmp,
        "strncmp" => strncmp,
        "_stricmp" => stricmp,
        "_strnicmp" => strnicmp,
        "_wcsicmp" => wcsicmp,
        "wcscmp" => wcscmp,
        "wcsncmp" => wcsncmp,
        "strcpy" => strcpy,
        "strncpy" => strncpy,
        "strcat" => strcat,
        "strncat" => strncat,
        "strchr" => strchr,
        "strrchr" => strrchr,
        "strstr" => strstr,
        "wcscpy" => wcscpy,
        "wcsncpy" => wcsncpy,
        "wcschr" => wcschr,
        "_strdup" => strdup,
        "_wcsdup" => wcsdup,
        "_strcoll_l" => strcoll_l,
        "_wcscoll_l" => wcscoll_l,
        "_strxfrm_l" => strxfrm_l,
        "_wcsxfrm_l" => wcsxfrm_l,
        "isalpha" => isalpha,
        "isupper" => isupper,
        "islower" => islower,
        "isdigit" => isdigit,
        "isspace" => isspace,
        "ispunct" => ispunct,
        "iscntrl" => iscntrl,
        "isxdigit" => isxdigit,
        "isblank" => isblank,
        "isalnum" => isalnum,
        "isgraph" => isgraph,
        "isprint" => isprint,
        "tolower" => tolower,
        "toupper" => toupper,
        "_isctype_l" => isctype_l,
        "_iswalpha_l" => iswalpha_l,
        "_iswalnum_l" => iswalnum_l,
        "_iswdigit_l" => iswdigit_l,
        "_iswxdigit_l" => iswxdigit_l,
        "_iswspace_l" => iswspace_l,
        "_iswupper_l" => iswupper_l,
        "_iswlower_l" => iswlower_l,
        "_iswpunct_l" => iswpunct_l,
        "_iswcntrl_l" => iswcntrl_l,
        "_iswgraph_l" => iswgraph_l,
        "_iswprint_l" => iswprint_l,
        "_iswblank_l" => iswblank_l,
        "_iswctype_l" => iswctype_l,
        "_towlower_l" => towlower_l,
        "_towupper_l" => towupper_l,
        "_tolower_l" => tolower_l,
        "_toupper_l" => toupper_l,
        "mbrlen" => mbrlen,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctype_classes_are_ascii_only() {
        assert_ne!(c_flags(b'A') & C_UPPER, 0);
        assert_ne!(c_flags(b'z') & C_LOWER, 0);
        assert_ne!(c_flags(b'7') & C_DIGIT, 0);
        assert_ne!(c_flags(b'f') & C_HEX, 0);
        assert_eq!(c_flags(0xE9), 0, "C locale does not classify high bytes");
        assert_eq!(c_flags(b'\t') & C_SPACE, C_SPACE);
    }
}
