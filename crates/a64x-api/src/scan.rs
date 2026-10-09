//! sscanf engine with UCRT semantics.
//!
//! Supports `%d %i %u %o %x %X %p %f %e %g %a %s %c %[set] %n %%`, the `*`
//! suppression flag, field widths and the length modifiers that select the
//! destination size (`hh`, `h`, `l`, `ll`, `I64`, `j`, `z`, `t`, `L`).
//! Whitespace in the format matches any run of input whitespace; numeric and
//! string conversions skip leading whitespace, `%c` and `%[` do not. The
//! return value is the number of assigned fields, or -1 (EOF) if the input
//! ends before the first conversion.

use crate::format::{Args, OPT_LEGACY_WIDE};
use crate::ApiCtx;
use a64x_core::Result;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Size {
    Char,
    Short,
    Int,
    Long64,
    Float64,
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

/// Run a scanf over `input` with the format code units `fmt`.
pub(crate) fn sscanf(
    ctx: &mut ApiCtx,
    options: u64,
    input: &[u8],
    fmt: &[u32],
    mut args: Args,
) -> Result<i64> {
    let _ = options & OPT_LEGACY_WIDE;
    let mut pos = 0usize;
    let mut assigned: i64 = 0;
    let mut converted_any = false;
    let mut fi = 0usize;
    let fmt_u8: Vec<u8> = fmt.iter().map(|u| *u as u8).collect();
    while fi < fmt_u8.len() {
        let c = fmt_u8[fi];
        if is_space(c) {
            while pos < input.len() && is_space(input[pos]) {
                pos += 1;
            }
            fi += 1;
            continue;
        }
        if c != b'%' {
            if pos >= input.len() {
                return Ok(if converted_any { assigned } else { -1 });
            }
            if input[pos] != c {
                return Ok(assigned);
            }
            pos += 1;
            fi += 1;
            continue;
        }
        fi += 1;
        if fmt_u8.get(fi) == Some(&b'%') {
            while pos < input.len() && is_space(input[pos]) {
                pos += 1;
            }
            if pos >= input.len() {
                return Ok(if converted_any { assigned } else { -1 });
            }
            if input[pos] != b'%' {
                return Ok(assigned);
            }
            pos += 1;
            fi += 1;
            continue;
        }
        let mut suppress = false;
        if fmt_u8.get(fi) == Some(&b'*') {
            suppress = true;
            fi += 1;
        }
        let mut width: Option<usize> = None;
        let mut w = 0usize;
        let mut any = false;
        while let Some(&d) = fmt_u8.get(fi) {
            if !d.is_ascii_digit() {
                break;
            }
            w = w.saturating_mul(10).saturating_add((d - b'0') as usize);
            any = true;
            fi += 1;
        }
        if any {
            width = Some(w);
        }
        let mut size = Size::Int;
        let mut wide_target = false;
        match fmt_u8.get(fi).copied().unwrap_or(0) {
            b'h' => {
                fi += 1;
                if fmt_u8.get(fi) == Some(&b'h') {
                    fi += 1;
                    size = Size::Char;
                } else {
                    size = Size::Short;
                }
            }
            b'l' => {
                fi += 1;
                if fmt_u8.get(fi) == Some(&b'l') {
                    fi += 1;
                    size = Size::Long64;
                } else {
                    size = Size::Int;
                    wide_target = true;
                }
            }
            b'I' => {
                fi += 1;
                if fmt_u8.get(fi) == Some(&b'6') && fmt_u8.get(fi + 1) == Some(&b'4') {
                    fi += 2;
                    size = Size::Long64;
                } else if fmt_u8.get(fi) == Some(&b'3') && fmt_u8.get(fi + 1) == Some(&b'2') {
                    fi += 2;
                } else {
                    size = Size::Long64;
                }
            }
            b'j' | b'z' | b't' | b'q' => {
                fi += 1;
                size = Size::Long64;
            }
            b'L' => {
                fi += 1;
                size = Size::Float64;
            }
            _ => {}
        }
        let Some(&conv) = fmt_u8.get(fi) else {
            break;
        };
        fi += 1;

        if conv == b'n' {
            if !suppress {
                let p = args.next(ctx)?;
                write_int(ctx, p, size, pos as i64)?;
            }
            continue;
        }
        // skip whitespace for all but %c and %[
        if !matches!(conv, b'c' | b'[') {
            while pos < input.len() && is_space(input[pos]) {
                pos += 1;
            }
        }
        if pos >= input.len() {
            return Ok(if converted_any { assigned } else { -1 });
        }
        let limit = width.unwrap_or(usize::MAX);
        match conv {
            b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'p' => {
                let radix = match conv {
                    b'o' => 8,
                    b'x' | b'X' | b'p' => 16,
                    b'i' => 0,
                    _ => 10,
                };
                let start = pos;
                let mut neg = false;
                let mut p = pos;
                let lim = |p: usize| p - start < limit && p < input.len();
                if lim(p) && (input[p] == b'+' || input[p] == b'-') {
                    neg = input[p] == b'-';
                    p += 1;
                }
                let mut base = radix;
                if (radix == 16 || radix == 0)
                    && lim(p)
                    && input[p] == b'0'
                    && lim(p + 1)
                    && matches!(input[p + 1], b'x' | b'X')
                {
                    base = 16;
                    p += 2;
                } else if radix == 0 {
                    base = if lim(p) && input[p] == b'0' { 8 } else { 10 };
                }
                let digit_ok = |b: u8| match base {
                    8 => (b'0'..=b'7').contains(&b),
                    10 => b.is_ascii_digit(),
                    _ => b.is_ascii_hexdigit(),
                };
                let mut val: i128 = 0;
                let mut nd = 0;
                while lim(p) && digit_ok(input[p]) {
                    val = val.saturating_mul(base as i128).saturating_add(
                        (input[p] as char).to_digit(base as u32).unwrap_or(0) as i128,
                    );
                    p += 1;
                    nd += 1;
                }
                if nd == 0 {
                    return Ok(assigned);
                }
                pos = p;
                converted_any = true;
                if neg {
                    val = -val;
                }
                if !suppress {
                    let target = args.next(ctx)?;
                    let bits = match size {
                        Size::Char => 8,
                        Size::Short => 16,
                        Size::Long64 => 64,
                        _ => 32,
                    };
                    let (lo, hi) = if conv == b'u'
                        || conv == b'o'
                        || conv == b'x'
                        || conv == b'X'
                        || conv == b'p'
                    {
                        (0i128, (1i128 << bits) - 1)
                    } else {
                        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
                    };
                    let clamped = val.clamp(lo, hi);
                    write_int(ctx, target, size, clamped as i64)?;
                    assigned += 1;
                }
            }
            b'f' | b'e' | b'g' | b'E' | b'G' | b'a' | b'A' => {
                let start = pos;
                let mut p = pos;
                let lim = |p: usize| p - start < limit && p < input.len();
                if lim(p) && (input[p] == b'+' || input[p] == b'-') {
                    p += 1;
                }
                let mut nd = 0;
                while lim(p) && input[p].is_ascii_digit() {
                    p += 1;
                    nd += 1;
                }
                if lim(p) && input[p] == b'.' {
                    p += 1;
                    while lim(p) && input[p].is_ascii_digit() {
                        p += 1;
                        nd += 1;
                    }
                }
                if nd == 0 {
                    return Ok(assigned);
                }
                if lim(p) && matches!(input[p], b'e' | b'E') {
                    let save = p;
                    p += 1;
                    if lim(p) && (input[p] == b'+' || input[p] == b'-') {
                        p += 1;
                    }
                    let mut ed = 0;
                    while lim(p) && input[p].is_ascii_digit() {
                        p += 1;
                        ed += 1;
                    }
                    if ed == 0 {
                        p = save;
                    }
                }
                let text = String::from_utf8_lossy(&input[start..p]).into_owned();
                pos = p;
                converted_any = true;
                if !suppress {
                    let v: f64 = text.parse().unwrap_or(0.0);
                    let target = args.next(ctx)?;
                    if size == Size::Float64
                        || (size == Size::Int && wide_target)
                        || size == Size::Long64
                    {
                        ctx.wr(target, 8, v.to_bits())?;
                    } else {
                        ctx.wr(target, 4, (v as f32).to_bits() as u64)?;
                    }
                    assigned += 1;
                }
            }
            b's' => {
                let start = pos;
                while pos < input.len() && !is_space(input[pos]) && pos - start < limit {
                    pos += 1;
                }
                let word = &input[start..pos];
                converted_any = true;
                if !suppress {
                    let target = args.next(ctx)?;
                    if wide_target {
                        let units: Vec<u16> = word.iter().map(|b| *b as u16).collect();
                        ctx.put_wide(target, &units)?;
                        ctx.wr(target + 2 * units.len() as u64, 2, 0)?;
                    } else {
                        ctx.put(target, word)?;
                        ctx.wr(target + word.len() as u64, 1, 0)?;
                    }
                    assigned += 1;
                }
            }
            b'c' => {
                let n = width.unwrap_or(1);
                let avail = (input.len() - pos).min(n);
                let chunk = input[pos..pos + avail].to_vec();
                pos += avail;
                converted_any = true;
                if !suppress {
                    let target = args.next(ctx)?;
                    if wide_target {
                        let units: Vec<u16> = chunk.iter().map(|b| *b as u16).collect();
                        ctx.put_wide(target, &units)?;
                    } else {
                        ctx.put(target, &chunk)?;
                    }
                    assigned += 1;
                }
            }
            b'[' => {
                let mut negate = false;
                if fmt_u8.get(fi) == Some(&b'^') {
                    negate = true;
                    fi += 1;
                }
                let mut set = [false; 256];
                let mut first = true;
                while let Some(&ch) = fmt_u8.get(fi) {
                    if ch == b']' && !first {
                        break;
                    }
                    first = false;
                    if fmt_u8.get(fi + 1) == Some(&b'-')
                        && fmt_u8.get(fi + 2).is_some_and(|x| *x != b']')
                    {
                        let hi = fmt_u8[fi + 2];
                        for x in ch..=hi {
                            set[x as usize] = true;
                        }
                        fi += 3;
                    } else {
                        set[ch as usize] = true;
                        fi += 1;
                    }
                }
                fi += 1; // skip ']'
                let start = pos;
                while pos < input.len() && pos - start < limit && set[input[pos] as usize] != negate
                {
                    pos += 1;
                }
                if pos == start {
                    return Ok(assigned);
                }
                let word = input[start..pos].to_vec();
                converted_any = true;
                if !suppress {
                    let target = args.next(ctx)?;
                    ctx.put(target, &word)?;
                    ctx.wr(target + word.len() as u64, 1, 0)?;
                    assigned += 1;
                }
            }
            _ => return Ok(assigned),
        }
    }
    Ok(assigned)
}

/// Store `v` at `p` with the destination size selected by `size`.
fn write_int(ctx: &mut ApiCtx, p: u64, size: Size, v: i64) -> Result<()> {
    match size {
        Size::Char => ctx.wr(p, 1, v as u64),
        Size::Short => ctx.wr(p, 2, v as u64),
        Size::Long64 => ctx.wr(p, 8, v as u64),
        _ => ctx.wr(p, 4, v as u64),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn whitespace_and_literals_match() {
        assert!(super::is_space(b'\t'));
        assert!(!super::is_space(b'a'));
    }
}
