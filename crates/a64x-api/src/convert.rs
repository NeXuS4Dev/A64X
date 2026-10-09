//! Numeric string conversion (strtol/strtod families) and multibyte/wide
//! character conversion, in the C locale (one byte per character, ASCII
//! only; bytes at or above 0x80 are EILSEQ).

use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;

const ERANGE: i32 = 34;
const EINVAL: i32 = 22;
const EILSEQ: i32 = 42;

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// Result of scanning an integer prefix.
struct IntScan {
    neg: bool,
    /// Magnitude, saturated at 2^64.
    mag: u128,
    overflow: bool,
    /// Index one past the consumed text (0 when no conversion happened).
    end: usize,
}

const MAG_CAP: u128 = 1 << 64;

/// Scan an integer prefix of `s` in `base` (0 = auto). Returns `None` for an
/// invalid base.
fn scan_int(s: &[u8], base: i32) -> Option<IntScan> {
    if base != 0 && !(2..=36).contains(&base) {
        return None;
    }
    let mut i = 0usize;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = base as u32;
    let hex_prefix = i + 1 < s.len()
        && s[i] == b'0'
        && (s[i + 1] | 0x20) == b'x'
        && s.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit());
    if (base == 0 || base == 16) && hex_prefix {
        base = 16;
        i += 2;
    } else if base == 0 {
        base = if i < s.len() && s[i] == b'0' { 8 } else { 10 };
    }
    let start = i;
    let mut mag: u128 = 0;
    let mut overflow = false;
    while i < s.len() {
        let d = match (s[i] as char).to_digit(base) {
            Some(d) => d as u128,
            None => break,
        };
        mag = mag * base as u128 + d;
        if mag >= MAG_CAP {
            mag = MAG_CAP;
            overflow = true;
        }
        i += 1;
    }
    if i == start {
        // no digits: nothing converted (end pointer stays at the start)
        return Some(IntScan {
            neg: false,
            mag: 0,
            overflow: false,
            end: 0,
        });
    }
    Some(IntScan {
        neg,
        mag,
        overflow,
        end: i,
    })
}

/// Narrow text of a wide string (non-ASCII units become non-numeric bytes).
fn narrow_of_units(units: &[u16]) -> Vec<u8> {
    units
        .iter()
        .map(|u| if *u <= 0x7F { *u as u8 } else { 0xFF })
        .collect()
}

/// Write the parsed end address to `endp` if non-null (`src + consumed`
/// units; `consumed == 0` means no conversion, so the end is `src`).
fn set_end(ctx: &mut ApiCtx, endp: u64, src: u64, consumed: usize, wide: bool) -> Result<()> {
    if endp == 0 {
        return Ok(());
    }
    let unit = if wide { 2 } else { 1 };
    let at = src + consumed as u64 * unit;
    ctx.wr(endp, 8, at)
}

/// Narrow strtol-family driver: arguments (s, endp, base).
fn strtol_narrow(ctx: &mut ApiCtx, bits: u32, signed: bool) -> Result<()> {
    let src = ctx.a(0);
    let endp = ctx.a(1);
    let base = ctx.ai(2);
    let text = ctx.cstr(src)?;
    let r = int_convert(ctx, &text, base, bits, signed, src, endp, false)?;
    ctx.ret(r);
    Ok(())
}

/// Wide strtol-family driver: arguments (s, endp, base).
fn strtol_wide(ctx: &mut ApiCtx, bits: u32, signed: bool) -> Result<()> {
    let src = ctx.a(0);
    let endp = ctx.a(1);
    let base = ctx.ai(2);
    let units = ctx.wstr(src)?;
    let text = narrow_of_units(&units);
    let r = int_convert(ctx, &text, base, bits, signed, src, endp, true)?;
    ctx.ret(r);
    Ok(())
}

/// Core of the integer conversions with end-pointer and errno handling.
fn int_convert(
    ctx: &mut ApiCtx,
    text: &[u8],
    base: i32,
    bits: u32,
    signed: bool,
    src: u64,
    endp: u64,
    wide: bool,
) -> Result<u64> {
    let Some(scan) = scan_int(text, base) else {
        ctx.set_errno(EINVAL);
        set_end(ctx, endp, src, 0, wide)?;
        return Ok(0);
    };
    let mut range = false;
    let value: i128 = if signed {
        let max = (1i128 << (bits - 1)) - 1;
        let min = -(1i128 << (bits - 1));
        let v = if scan.neg {
            -(scan.mag as i128)
        } else {
            scan.mag as i128
        };
        if scan.overflow || v > max || v < min {
            range = true;
            if scan.neg {
                min
            } else {
                max
            }
        } else {
            v
        }
    } else {
        let max = (1i128 << bits) - 1;
        let m = scan.mag as i128;
        let mut v = if scan.neg { -m } else { m };
        if scan.overflow || v.abs() > max {
            range = true;
        }
        if range {
            v = max;
        } else if scan.neg {
            v = v.rem_euclid(1i128 << bits);
        }
        v
    };
    if range {
        ctx.set_errno(ERANGE);
    }
    set_end(ctx, endp, src, scan.end, wide)?;
    Ok(value as u64)
}

fn strtol(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 32, true)
}
fn strtoul(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 32, false)
}
fn strtoll(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 64, true)
}
fn strtoull(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 64, false)
}
fn wcstol(ctx: &mut ApiCtx) -> Result<()> {
    strtol_wide(ctx, 32, true)
}
fn wcstoul(ctx: &mut ApiCtx) -> Result<()> {
    strtol_wide(ctx, 32, false)
}
fn wcstoll(ctx: &mut ApiCtx) -> Result<()> {
    strtol_wide(ctx, 64, true)
}
fn wcstoull(ctx: &mut ApiCtx) -> Result<()> {
    strtol_wide(ctx, 64, false)
}

/// `_strtoi64_l(s, end, base, locale)` / `_strtoui64_l(...)`.
fn strtoi64_l(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 64, true)
}
fn strtoui64_l(ctx: &mut ApiCtx) -> Result<()> {
    strtol_narrow(ctx, 64, false)
}

fn atoi(ctx: &mut ApiCtx) -> Result<()> {
    let text = ctx.cstr(ctx.a(0))?;
    let r = int_convert(ctx, &text, 10, 32, true, 0, 0, false)?;
    ctx.ret(r);
    Ok(())
}

fn atol_ll(ctx: &mut ApiCtx) -> Result<()> {
    let text = ctx.cstr(ctx.a(0))?;
    let r = int_convert(ctx, &text, 10, 64, true, 0, 0, false)?;
    ctx.ret(r);
    Ok(())
}

/// Floating-point prefix scan. Returns `(value, consumed bytes, range_error)`.
fn scan_float(s: &[u8]) -> (f64, usize, bool) {
    let mut i = 0usize;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let start_num = i;
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let rest = &s[i..];
    let lower: Vec<u8> = rest
        .iter()
        .take(9)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if lower.starts_with(b"infinity") {
        return (
            if neg {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            },
            i + 8,
            false,
        );
    }
    if lower.starts_with(b"inf") {
        return (
            if neg {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            },
            i + 3,
            false,
        );
    }
    if lower.starts_with(b"nan") {
        let v = if neg { -f64::NAN } else { f64::NAN };
        return (v, i + 3, false);
    }
    // hexadecimal floating point
    if rest.len() >= 2 && rest[0] == b'0' && (rest[1] | 0x20) == b'x' {
        let mut j = i + 2;
        let mut mant = 0f64;
        let mut any = false;
        let mut scale = 0i32;
        while j < s.len() && s[j].is_ascii_hexdigit() {
            mant = mant * 16.0 + (s[j] as char).to_digit(16).unwrap_or(0) as f64;
            any = true;
            j += 1;
        }
        if j < s.len() && s[j] == b'.' {
            j += 1;
            while j < s.len() && s[j].is_ascii_hexdigit() {
                mant = mant * 16.0 + (s[j] as char).to_digit(16).unwrap_or(0) as f64;
                scale -= 4;
                any = true;
                j += 1;
            }
        }
        if any {
            let mut exp = 0i32;
            if j < s.len() && (s[j] | 0x20) == b'p' {
                let mut k = j + 1;
                let mut eneg = false;
                if k < s.len() && (s[k] == b'+' || s[k] == b'-') {
                    eneg = s[k] == b'-';
                    k += 1;
                }
                let mut e = 0i32;
                let mut ed = false;
                while k < s.len() && s[k].is_ascii_digit() {
                    e = e.saturating_mul(10).saturating_add((s[k] - b'0') as i32);
                    ed = true;
                    k += 1;
                }
                if ed {
                    exp = if eneg { -e } else { e };
                    j = k;
                }
            }
            let v = mant * 2f64.powi(scale + exp);
            return (if neg { -v } else { v }, j, v.is_infinite());
        }
        return (0.0, start_num + 1, false);
    }
    let mut j = i;
    let mut digits = 0;
    let mut nonzero = false;
    while j < s.len() && s[j].is_ascii_digit() {
        nonzero |= s[j] != b'0';
        j += 1;
        digits += 1;
    }
    if j < s.len() && s[j] == b'.' {
        let mut k = j + 1;
        while k < s.len() && s[k].is_ascii_digit() {
            nonzero |= s[k] != b'0';
            k += 1;
            digits += 1;
        }
        if digits > 0 {
            j = k;
        }
    }
    if digits == 0 {
        return (0.0, 0, false);
    }
    if j < s.len() && (s[j] | 0x20) == b'e' {
        let mut k = j + 1;
        if k < s.len() && (s[k] == b'+' || s[k] == b'-') {
            k += 1;
        }
        let ds = k;
        while k < s.len() && s[k].is_ascii_digit() {
            k += 1;
        }
        if k > ds {
            j = k;
        }
    }
    let text = std::str::from_utf8(&s[start_num..j]).unwrap_or("0");
    let v: f64 = text.parse().unwrap_or(0.0);
    let range = (v.is_infinite()) || (v == 0.0 && nonzero);
    (v, j, range)
}

/// Common strtod body: `src` is the string address, `endp` the end pointer.
fn strtod_common(ctx: &mut ApiCtx, src: u64, endp: u64, wide: bool) -> Result<(f64, bool)> {
    let text: Vec<u8> = if wide {
        narrow_of_units(&ctx.wstr(src)?)
    } else {
        ctx.cstr(src)?
    };
    let (v, consumed, range) = scan_float(&text);
    set_end(ctx, endp, src, consumed, wide)?;
    if range {
        ctx.set_errno(ERANGE);
    }
    Ok((v, range))
}

fn strtod(ctx: &mut ApiCtx) -> Result<()> {
    let (v, _) = strtod_common(ctx, ctx.a(0), ctx.a(1), false)?;
    ctx.ret_f64(v);
    Ok(())
}

fn strtod_l(ctx: &mut ApiCtx) -> Result<()> {
    let (v, _) = strtod_common(ctx, ctx.a(0), ctx.a(1), false)?;
    ctx.ret_f64(v);
    Ok(())
}

fn wcstod(ctx: &mut ApiCtx) -> Result<()> {
    let (v, _) = strtod_common(ctx, ctx.a(0), ctx.a(1), true)?;
    ctx.ret_f64(v);
    Ok(())
}

fn strtof(ctx: &mut ApiCtx) -> Result<()> {
    let (v, _) = strtod_common(ctx, ctx.a(0), ctx.a(1), false)?;
    let f = v as f32;
    if f.is_infinite() && v.is_finite() {
        ctx.set_errno(ERANGE);
    }
    ctx.ret_f32(f);
    Ok(())
}

fn atof(ctx: &mut ApiCtx) -> Result<()> {
    let (v, _) = strtod_common(ctx, ctx.a(0), 0, false)?;
    ctx.ret_f64(v);
    Ok(())
}

/// `mbrtowc(pwc, s, n, ps)` in the C locale.
fn mbrtowc(ctx: &mut ApiCtx) -> Result<()> {
    let (pwc, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2));
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
        ctx.set_errno(EILSEQ);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    if pwc != 0 {
        ctx.wr(pwc, 2, b as u64)?;
    }
    ctx.ret(if b == 0 { 0 } else { 1 });
    Ok(())
}

/// `_mbtowc_l(pwc, s, n, locale)`.
fn mbtowc_l(ctx: &mut ApiCtx) -> Result<()> {
    let (pwc, s, n) = (ctx.a(0), ctx.a(1), ctx.a(2));
    if s == 0 {
        ctx.ret_i32(0);
        return Ok(());
    }
    if n == 0 {
        ctx.ret_i32(-1);
        return Ok(());
    }
    let b = ctx.rd(s, 1)? as u8;
    if b >= 0x80 {
        ctx.set_errno(EILSEQ);
        ctx.ret_i32(-1);
        return Ok(());
    }
    if pwc != 0 {
        ctx.wr(pwc, 2, b as u64)?;
    }
    ctx.ret_i32(if b == 0 { 0 } else { 1 });
    Ok(())
}

/// `mbsrtowcs(dst, src**, len, ps)` in the C locale.
fn mbsrtowcs(ctx: &mut ApiCtx) -> Result<()> {
    let (dst, srcp, len) = (ctx.a(0), ctx.a(1), ctx.a(2));
    let src = ctx.rd_ptr(srcp)?;
    let text = ctx.cstr(src)?;
    let mut out: Vec<u16> = Vec::new();
    let mut consumed = 0usize;
    let mut bad = false;
    for &b in &text {
        if dst != 0 && out.len() as u64 >= len {
            break;
        }
        if b >= 0x80 {
            bad = true;
            break;
        }
        out.push(b as u16);
        consumed += 1;
    }
    if bad {
        ctx.set_errno(EILSEQ);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    if dst != 0 {
        ctx.put_wide(dst, &out)?;
        if (out.len() as u64) < len {
            ctx.wr(dst + 2 * out.len() as u64, 2, 0)?;
            ctx.wr(srcp, 8, 0)?;
        } else {
            ctx.wr(srcp, 8, src + consumed as u64)?;
        }
    }
    ctx.ret(out.len() as u64);
    Ok(())
}

/// `wcrtomb(s, wc, ps)` in the C locale.
fn wcrtomb(ctx: &mut ApiCtx) -> Result<()> {
    let (s, wc) = (ctx.a(0), ctx.au(1) & 0xFFFF);
    if s == 0 {
        ctx.ret(1);
        return Ok(());
    }
    if wc > 0x7F {
        ctx.set_errno(EILSEQ);
        ctx.ret(u64::MAX);
        return Ok(());
    }
    ctx.wr(s, 1, wc as u64)?;
    ctx.ret(1);
    Ok(())
}

/// `wcrtomb_s(pReturnValue, s, sizeInBytes, wc, ps)`.
fn wcrtomb_s(ctx: &mut ApiCtx) -> Result<()> {
    let (pret, s, size, wc) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.au(3) & 0xFFFF);
    let mut written = 0u64;
    let mut code = 0i32;
    if s == 0 {
        written = 1;
    } else if size == 0 {
        code = EINVAL;
    } else if wc > 0x7F {
        code = EILSEQ;
        ctx.wr(s, 1, 0)?;
        written = u64::MAX;
    } else {
        ctx.wr(s, 1, wc as u64)?;
        written = 1;
    }
    if pret != 0 {
        ctx.wr(pret, 8, written)?;
    }
    if code != 0 {
        ctx.set_errno(code);
    }
    ctx.ret_i32(code);
    Ok(())
}

/// Register the conversion adapters.
pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "ucrtbase",
        "strtol" => strtol,
        "strtoul" => strtoul,
        "strtoll" => strtoll,
        "strtoull" => strtoull,
        "wcstol" => wcstol,
        "wcstoul" => wcstoul,
        "wcstoll" => wcstoll,
        "wcstoull" => wcstoull,
        "_strtoi64_l" => strtoi64_l,
        "_strtoui64_l" => strtoui64_l,
        "_strtod_l" => strtod_l,
        "strtod" => strtod,
        "wcstod" => wcstod,
        "strtof" => strtof,
        "atoi" => atoi,
        "atol" => atol_ll,
        "atoll" => atol_ll,
        "_atoi64" => atol_ll,
        "atof" => atof,
        "mbrtowc" => mbrtowc,
        "_mbtowc_l" => mbtowc_l,
        "mbsrtowcs" => mbsrtowcs,
        "wcrtomb" => wcrtomb,
        "wcrtomb_s" => wcrtomb_s,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_handles_sign_base_and_prefix() {
        let s = scan_int(b"  -0x1fZ", 0).unwrap();
        assert!(s.neg);
        assert_eq!(s.mag, 0x1f);
        assert_eq!(s.end, 7);
        let t = scan_int(b"0777", 0).unwrap();
        assert_eq!(t.mag, 0o777);
        assert!(scan_int(b"1", 1).is_none(), "invalid base");
        let none = scan_int(b"xyz", 10).unwrap();
        assert_eq!(none.end, 0, "no conversion leaves end at start");
    }

    #[test]
    fn float_scan_matches_c_prefix_rules() {
        let (v, n, r) = scan_float(b"  3.5e2xyz");
        assert_eq!((v, n, r), (350.0, 7, false));
        let (v2, n2, _) = scan_float(b"1e");
        assert_eq!((v2, n2), (1.0, 1), "dangling exponent is not consumed");
        let (v3, _, r3) = scan_float(b"1e400");
        assert!(v3.is_infinite() && r3);
        let (h, _, _) = scan_float(b"0x1.8p1");
        assert_eq!(h, 3.0);
    }
}
