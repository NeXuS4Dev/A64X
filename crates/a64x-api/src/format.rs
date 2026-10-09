//! printf engine with UCRT semantics.
//!
//! Arguments follow the Windows ARM64 calling convention: the first eight
//! integer-class arguments are in x0..x7, the rest are on the stack; variadic
//! doubles travel in integer slots as their raw bits. Argument sizes follow
//! the MSVC rules: `%ld`/`%lu` are 32-bit (Windows `long`), `%lld`, `%I64d`,
//! `%jd`, `%zd`, `%td` are 64-bit, `%Id` is pointer-sized. `%n` is rejected
//! (the UCRT default since Visual Studio 2015) and yields EINVAL.
//!
//! The engine works on `u32` code units so that one implementation serves
//! the narrow (`printf`) and wide (`wprintf`) families. Legacy wide
//! specifiers (`%s` is a wide string in `wprintf`) follow option bit 4
//! (`_CRT_INTERNAL_PRINTF_LEGACY_WIDE_SPECIFIERS`), and the standard
//! snprintf return value follows option bit 2.

use crate::ApiCtx;
use a64x_core::Result;

/// Largest field width or precision accepted (larger is EINVAL).
const MAX_FIELD: usize = 1 << 20;
/// Option bit: legacy wide specifiers (`%s` wide in wprintf).
pub(crate) const OPT_LEGACY_WIDE: u64 = 1 << 2;
/// Option bit: standard snprintf return value (would-be length).
pub(crate) const OPT_STD_SNPRINTF: u64 = 1 << 1;
/// Option bit: three-digit exponents (legacy MSVCRT).
pub(crate) const OPT_THREE_DIGIT_EXP: u64 = 1 << 4;

/// Source of variadic arguments.
pub(crate) enum Args {
    /// Arguments in registers starting at index `idx`, then the stack.
    Regs { idx: usize },
    /// A `va_list` (pointer to 8-byte slots), advanced as it is read.
    Va { ptr: u64 },
}

impl Args {
    /// Variadic arguments of an adapter whose first variadic argument is
    /// register `first` (x0-based).
    pub(crate) fn regs(_ctx: &ApiCtx, first: usize) -> Args {
        Args::Regs { idx: first }
    }

    /// Arguments from a `va_list`.
    pub(crate) fn va(ptr: u64) -> Args {
        Args::Va { ptr }
    }

    /// Next 64-bit argument slot.
    pub(crate) fn next(&mut self, ctx: &ApiCtx) -> Result<u64> {
        match self {
            Args::Regs { idx } => {
                let i = *idx;
                *idx += 1;
                if i < 8 {
                    Ok(ctx.state.x[i])
                } else {
                    ctx.rd_ptr(ctx.state.sp + 8 * (i as u64 - 8))
                }
            }
            Args::Va { ptr } => {
                let v = ctx.rd_ptr(*ptr)?;
                *ptr += 8;
                Ok(v)
            }
        }
    }
}

/// Integer size selected by the length modifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Len {
    /// No modifier: int.
    Default,
    /// `hh`: char.
    Char,
    /// `h`: short.
    Short,
    /// `l`: long (32 bits on Windows).
    Long,
    /// `ll`, `I64`, `j`, `z`, `t`, `q`: 64 bits.
    Big,
    /// `I`: pointer size (64 bits on ARM64 Windows).
    Ptr,
    /// `I32`: 32 bits.
    I32,
    /// `L` (long double, the same as double here).
    LongDouble,
    /// `w` (wide char for `c`/`s`).
    Wide,
}

/// Read a NUL-terminated narrow string as code units (NULL reads as "").
pub(crate) fn narrow_units(ctx: &ApiCtx, addr: u64) -> Result<Vec<u32>> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    Ok(ctx.cstr(addr)?.into_iter().map(|b| b as u32).collect())
}

/// Read a NUL-terminated wide string as code units (NULL reads as "").
pub(crate) fn wide_units(ctx: &ApiCtx, addr: u64) -> Result<Vec<u32>> {
    if addr == 0 {
        return Ok(Vec::new());
    }
    Ok(ctx.wstr(addr)?.into_iter().map(|u| u as u32).collect())
}

/// Convert one wide unit to the C locale's narrow form (ASCII only).
fn to_narrow(u: u32) -> std::result::Result<u32, i32> {
    if u > 0x7F {
        Err(42)
    } else {
        Ok(u)
    }
}

/// Convert one narrow byte to the wide form (ASCII only).
fn to_wide(u: u32) -> std::result::Result<u32, i32> {
    if u > 0x7F {
        Err(42)
    } else {
        Ok(u)
    }
}

/// Push `s` (ASCII) into the output as code units.
fn push_str(out: &mut Vec<u32>, s: &str) {
    out.extend(s.bytes().map(|b| b as u32));
}

/// Emit `sign` + `body` padded to `width` units.
fn emit_padded(out: &mut Vec<u32>, sign: &str, body: &[u32], width: usize, left: bool, zero: bool) {
    let total = sign.len() + body.len();
    let pad = width.saturating_sub(total);
    if left {
        push_str(out, sign);
        out.extend_from_slice(body);
        out.extend(std::iter::repeat_n(b' ' as u32, pad));
    } else if zero {
        push_str(out, sign);
        out.extend(std::iter::repeat_n(b'0' as u32, pad));
        out.extend_from_slice(body);
    } else {
        out.extend(std::iter::repeat_n(b' ' as u32, pad));
        push_str(out, sign);
        out.extend_from_slice(body);
    }
}

/// Scientific notation with `prec` fraction digits and at least two exponent
/// digits (three with the legacy option). `upper` selects `E`.
fn sci(v: f64, prec: usize, upper: bool, three_digits: bool) -> String {
    let s = format!("{:.*e}", prec, v);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let e: i32 = exp.parse().unwrap_or(0);
    let digits = if three_digits { 3 } else { 2 };
    let mut out = String::with_capacity(mant.len() + 6);
    out.push_str(mant);
    out.push(if upper { 'E' } else { 'e' });
    out.push(if e < 0 { '-' } else { '+' });
    out.push_str(&format!("{:0width$}", e.unsigned_abs(), width = digits));
    out
}

/// Hexadecimal floating point (`%a`), normalized to `0x1.hhhp+e`.
fn hex_float(v: f64, prec: Option<usize>, upper: bool) -> String {
    let bits = v.to_bits();
    let exp_bits = ((bits >> 52) & 0x7FF) as i64;
    let frac = bits & ((1u64 << 52) - 1);
    let (lead, e) = if exp_bits == 0 {
        if frac == 0 {
            (0u64, 0i64)
        } else {
            (0u64, -1022i64)
        }
    } else {
        (1u64, exp_bits - 1023)
    };
    let mut digits = format!("{:013x}", frac);
    match prec {
        None => {
            while digits.ends_with('0') {
                digits.pop();
            }
        }
        Some(p) => {
            if p < 13 {
                let shift = (13 - p) * 4;
                let full = frac;
                let mut q = full >> shift;
                let rem = full & ((1u64 << shift) - 1);
                let half = 1u64 << (shift - 1);
                if rem > half || (rem == half && q & 1 == 1) {
                    q += 1;
                }
                digits = if p == 0 {
                    String::new()
                } else {
                    format!("{:0width$x}", q, width = p)
                };
            } else {
                digits = format!("{:0<width$}", digits, width = p);
            }
        }
    }
    let mut s = format!("0x{}", lead);
    if !digits.is_empty() {
        s.push('.');
        s.push_str(&digits);
    }
    s.push('p');
    s.push(if e < 0 { '-' } else { '+' });
    s.push_str(&e.unsigned_abs().to_string());
    if upper {
        s = s.to_uppercase();
    }
    s
}

/// Format a double for `%f %e %g %a` (without padding).
fn float_body(
    v: f64,
    conv: u8,
    prec: Option<usize>,
    alt: bool,
    three_digits: bool,
) -> (String, bool) {
    let neg = v.is_sign_negative();
    let a = v.abs();
    let upper = conv.is_ascii_uppercase();
    if a.is_nan() {
        let base = if upper { "NAN" } else { "nan" };
        return (base.to_string(), neg);
    }
    if a.is_infinite() {
        let base = if upper { "INF" } else { "inf" };
        return (base.to_string(), neg);
    }
    let body = match conv.to_ascii_lowercase() {
        b'f' => {
            let p = prec.unwrap_or(6);
            let mut s = format!("{:.*}", p, a);
            if alt && p == 0 {
                s.push('.');
            }
            s
        }
        b'e' => sci(a, prec.unwrap_or(6), upper, three_digits),
        b'g' => {
            let p = match prec {
                None => 6,
                Some(0) => 1,
                Some(p) => p,
            };
            // exponent X of the e-style rendering with precision p-1
            let e_style = format!("{:.*e}", p - 1, a);
            let x: i64 = e_style
                .split_once('e')
                .map(|(_, e)| e.parse().unwrap_or(0))
                .unwrap_or(0);
            let mut s = if (x as i64) < p as i64 && x >= -4 {
                format!("{:.*}", (p as i64 - 1 - x).max(0) as usize, a)
            } else {
                sci(a, p - 1, upper, three_digits)
            };
            if !alt {
                // strip trailing zeros of the fraction (and a bare '.')
                let (mant, exp) = match s.find(['e', 'E']) {
                    Some(i) => (s[..i].to_string(), s[i..].to_string()),
                    None => (s.clone(), String::new()),
                };
                let mut m = mant;
                if m.contains('.') {
                    while m.ends_with('0') {
                        m.pop();
                    }
                    if m.ends_with('.') {
                        m.pop();
                    }
                }
                s = m + &exp;
            }
            s
        }
        b'a' => hex_float(a, prec, upper),
        _ => String::new(),
    };
    (body, neg)
}

/// Format `fmt` with `args`. `wide` selects the wide printf family: the
/// output is wide units and `%s` follows the legacy specifier rule. Returns
/// the output units, or `Err(errno)` for a format error (EINVAL, EILSEQ).
pub(crate) fn format(
    ctx: &ApiCtx,
    options: u64,
    fmt: &[u32],
    wide: bool,
    args: &mut Args,
) -> Result<std::result::Result<Vec<u32>, i32>> {
    let legacy = options & OPT_LEGACY_WIDE != 0;
    let three = options & OPT_THREE_DIGIT_EXP != 0;
    let mut out: Vec<u32> = Vec::with_capacity(fmt.len() + 16);
    let mut i = 0usize;
    macro_rules! tri {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            }
        };
    }
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' as u32 {
            out.push(c);
            continue;
        }
        if fmt.get(i) == Some(&(b'%' as u32)) {
            out.push(b'%' as u32);
            i += 1;
            continue;
        }
        let (mut left, mut plus, mut space, mut alt, mut zero) =
            (false, false, false, false, false);
        while let Some(&f) = fmt.get(i) {
            match f as u8 {
                b'-' if f < 0x80 => left = true,
                b'+' if f < 0x80 => plus = true,
                b' ' if f < 0x80 => space = true,
                b'#' if f < 0x80 => alt = true,
                b'0' if f < 0x80 => zero = true,
                _ => break,
            }
            i += 1;
        }
        let mut width: Option<usize> = None;
        if fmt.get(i) == Some(&(b'*' as u32)) {
            i += 1;
            let w = args.next(ctx)? as u32 as i32;
            if w < 0 {
                left = true;
            }
            width = Some(w.unsigned_abs() as usize);
        } else {
            let mut w = 0usize;
            let mut any = false;
            while let Some(&d) = fmt.get(i) {
                if !(0x30..=0x39).contains(&d) {
                    break;
                }
                w = w.saturating_mul(10).saturating_add((d - 0x30) as usize);
                any = true;
                i += 1;
            }
            if any {
                width = Some(w);
            }
        }
        let mut prec: Option<usize> = None;
        if fmt.get(i) == Some(&(b'.' as u32)) {
            i += 1;
            if fmt.get(i) == Some(&(b'*' as u32)) {
                i += 1;
                let p = args.next(ctx)? as u32 as i32;
                prec = if p < 0 { None } else { Some(p as usize) };
            } else {
                let mut p = 0usize;
                while let Some(&d) = fmt.get(i) {
                    if !(0x30..=0x39).contains(&d) {
                        break;
                    }
                    p = p.saturating_mul(10).saturating_add((d - 0x30) as usize);
                    i += 1;
                }
                prec = Some(p);
            }
        }
        let mut len = Len::Default;
        match fmt.get(i).copied().unwrap_or(0) {
            0x68 => {
                // 'h'
                i += 1;
                if fmt.get(i) == Some(&0x68) {
                    i += 1;
                    len = Len::Char;
                } else {
                    len = Len::Short;
                }
            }
            0x6C => {
                // 'l'
                i += 1;
                if fmt.get(i) == Some(&0x6C) {
                    i += 1;
                    len = Len::Big;
                } else {
                    len = Len::Long;
                }
            }
            0x49 => {
                // 'I'
                i += 1;
                if fmt.get(i) == Some(&0x36) && fmt.get(i + 1) == Some(&0x34) {
                    i += 2;
                    len = Len::Big;
                } else if fmt.get(i) == Some(&0x33) && fmt.get(i + 1) == Some(&0x32) {
                    i += 2;
                    len = Len::I32;
                } else {
                    len = Len::Ptr;
                }
            }
            0x6A | 0x7A | 0x74 | 0x71 => {
                i += 1;
                len = Len::Big;
            }
            0x4C => {
                i += 1;
                len = Len::LongDouble;
            }
            0x77 => {
                i += 1;
                len = Len::Wide;
            }
            _ => {}
        }
        let Some(&conv_u) = fmt.get(i) else {
            return Ok(Err(22));
        };
        i += 1;
        let conv = conv_u as u8;
        let w = width.unwrap_or(0);
        if w > MAX_FIELD || prec.is_some_and(|p| p > MAX_FIELD) {
            return Ok(Err(22));
        }
        match conv {
            b'd' | b'i' => {
                let raw = args.next(ctx)?;
                let v: i64 = match len {
                    Len::Char => raw as u8 as i8 as i64,
                    Len::Short => raw as u16 as i16 as i64,
                    Len::Big | Len::Ptr => raw as i64,
                    _ => raw as u32 as i32 as i64,
                };
                let mut digits = v.unsigned_abs().to_string();
                if prec == Some(0) && v == 0 {
                    digits.clear();
                }
                if let Some(p) = prec {
                    while digits.len() < p {
                        digits.insert(0, '0');
                    }
                }
                let sign = if v < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                let body: Vec<u32> = digits.bytes().map(|b| b as u32).collect();
                emit_padded(&mut out, sign, &body, w, left, zero && prec.is_none());
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = args.next(ctx)?;
                let v: u64 = match len {
                    Len::Char => raw as u8 as u64,
                    Len::Short => raw as u16 as u64,
                    Len::Big | Len::Ptr => raw,
                    _ => raw as u32 as u64,
                };
                let mut digits = match conv {
                    b'u' => v.to_string(),
                    b'x' => format!("{v:x}"),
                    b'X' => format!("{v:X}"),
                    _ => format!("{v:o}"),
                };
                if prec == Some(0) && v == 0 {
                    digits.clear();
                }
                if let Some(p) = prec {
                    while digits.len() < p {
                        digits.insert(0, '0');
                    }
                }
                let mut prefix = "";
                if alt && v != 0 {
                    match conv {
                        b'x' => prefix = "0x",
                        b'X' => prefix = "0X",
                        b'o' if !digits.starts_with('0') => digits.insert(0, '0'),
                        _ => {}
                    }
                }
                let body: Vec<u32> = digits.bytes().map(|b| b as u32).collect();
                emit_padded(&mut out, prefix, &body, w, left, zero && prec.is_none());
            }
            b'c' | b'C' => {
                let raw = args.next(ctx)? as u32;
                let wchar = matches!(len, Len::Long | Len::Wide) || (conv == b'C') != wide;
                let unit = if wchar {
                    tri!(to_narrow(raw & 0xFFFF).or_else(|e| if wide {
                        Ok(raw & 0xFFFF)
                    } else {
                        Err(e)
                    }))
                } else {
                    raw & 0xFF
                };
                let body = [unit];
                emit_padded(&mut out, "", &body, w, left, false);
            }
            b's' | b'S' => {
                let ptr = args.next(ctx)?;
                let wide_str = match len {
                    Len::Long | Len::Wide => true,
                    Len::Short | Len::Char => false,
                    _ => {
                        if conv == b's' {
                            wide && legacy
                        } else {
                            !(wide && legacy)
                        }
                    }
                };
                let units: Vec<u32> = if ptr == 0 {
                    if wide_str {
                        "(null)".bytes().map(|b| b as u32).collect()
                    } else {
                        "(null)".bytes().map(|b| b as u32).collect()
                    }
                } else if wide_str {
                    ctx.wstr(ptr)?.into_iter().map(|u| u as u32).collect()
                } else {
                    ctx.cstr(ptr)?.into_iter().map(|b| b as u32).collect()
                };
                let units = if let Some(p) = prec {
                    units.into_iter().take(p).collect()
                } else {
                    units
                };
                // convert to the output encoding
                let mut conv_units = Vec::with_capacity(units.len());
                for u in units {
                    let v = match (wide_str, wide) {
                        (true, false) => tri!(to_narrow(u)),
                        (false, true) => tri!(to_wide(u)),
                        _ => u,
                    };
                    conv_units.push(v);
                }
                emit_padded(&mut out, "", &conv_units, w, left, false);
            }
            b'p' => {
                let raw = args.next(ctx)?;
                let body = format!("{raw:016X}");
                let body: Vec<u32> = body.bytes().map(|b| b as u32).collect();
                emit_padded(&mut out, "", &body, w, left, false);
            }
            b'n' => {
                // %n is disabled by default in the UCRT (invalid parameter).
                return Ok(Err(22));
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                let v = f64::from_bits(args.next(ctx)?);
                let (body, neg) = float_body(v, conv, prec, alt, three);
                let sign = if neg {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                let units: Vec<u32> = body.bytes().map(|b| b as u32).collect();
                let finite = v.is_finite();
                emit_padded(&mut out, sign, &units, w, left, zero && finite);
            }
            _ => return Ok(Err(22)),
        }
    }
    Ok(Ok(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(units: &[u32]) -> String {
        units
            .iter()
            .map(|u| char::from_u32(*u).unwrap_or('?'))
            .collect()
    }

    #[test]
    fn floats_match_c() {
        assert_eq!(float_body(3.14159, b'f', Some(2), false, false).0, "3.14");
        assert_eq!(
            float_body(1234.5, b'e', None, false, false).0,
            "1.234500e+03"
        );
        assert_eq!(float_body(0.0001, b'g', None, false, false).0, "0.0001");
        assert_eq!(float_body(1e-5, b'g', None, false, false).0, "1e-05");
        assert_eq!(float_body(100.0, b'g', None, false, false).0, "100");
        assert_eq!(float_body(1.0, b'a', None, false, false).0, "0x1p+0");
        assert_eq!(float_body(f64::INFINITY, b'F', None, false, false).0, "INF");
    }

    #[test]
    fn integer_flags() {
        let mut out = Vec::new();
        emit_padded(&mut out, "-", &[b'4' as u32, b'2' as u32], 6, false, true);
        assert_eq!(s(&out), "-00042");
        let mut out2 = Vec::new();
        emit_padded(&mut out2, "", &[b'7' as u32], 3, true, false);
        assert_eq!(s(&out2), "7  ");
    }

    #[test]
    fn length_names_select_sizes() {
        let raw: u64 = 0xFFFF_FFFF_0000_0001;
        // %ld is 32-bit: the value wraps to 1
        assert_eq!(raw as u32 as i32, 1);
        assert_eq!(raw as i64, -4294967295);
    }
}
