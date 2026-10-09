//! strftime in the C locale, over the UCRT `struct tm` (nine 32-bit ints).
//!
//! Supported conversions: the MSVC set (`%a %A %b %B %c %d %H %I %j %m %M %p
//! %S %U %w %W %x %X %y %Y %z %Z %%`) plus `%e %D %T %R %h %n %t`. Any other
//! conversion is an invalid parameter: strftime returns 0.

use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;

const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// The fields of a `struct tm`.
#[derive(Clone, Copy)]
struct Tm {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
    wday: i32,
    yday: i32,
}

fn read_tm(ctx: &ApiCtx, p: u64) -> Result<Tm> {
    let f = |i: u64| -> Result<i32> { Ok(ctx.rd(p + 4 * i, 4)? as u32 as i32) };
    Ok(Tm {
        sec: f(0)?,
        min: f(1)?,
        hour: f(2)?,
        mday: f(3)?,
        mon: f(4)?,
        year: f(5)?,
        wday: f(6)?,
        yday: f(7)?,
    })
}

/// Format per the C-locale rules; `None` for an invalid conversion or a
/// field outside its range.
fn format_tm(fmt: &[u8], t: Tm) -> Option<Vec<u8>> {
    if !(0..=6).contains(&t.wday) || !(0..=11).contains(&t.mon) || !(1..=31).contains(&t.mday) {
        return None;
    }
    let year = t.year + 1900;
    let h12 = match t.hour % 12 {
        0 => 12,
        h => h,
    };
    let mut out = String::new();
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c as char);
            continue;
        }
        let Some(&spec) = fmt.get(i) else {
            return None;
        };
        i += 1;
        let day_abbr = &DAYS[t.wday as usize][..3];
        let mon_abbr = &MONTHS[t.mon as usize][..3];
        match spec {
            b'a' => out.push_str(day_abbr),
            b'A' => out.push_str(DAYS[t.wday as usize]),
            b'b' | b'h' => out.push_str(mon_abbr),
            b'B' => out.push_str(MONTHS[t.mon as usize]),
            b'c' => out.push_str(&format!(
                "{} {} {:02} {:02}:{:02}:{:02} {}",
                day_abbr, mon_abbr, t.mday, t.hour, t.min, t.sec, year
            )),
            b'd' => out.push_str(&format!("{:02}", t.mday)),
            b'e' => out.push_str(&format!("{:2}", t.mday)),
            b'D' => out.push_str(&format!(
                "{:02}/{:02}/{:02}",
                t.mon + 1,
                t.mday,
                (year % 100).abs()
            )),
            b'H' => out.push_str(&format!("{:02}", t.hour)),
            b'I' => out.push_str(&format!("{:02}", h12)),
            b'j' => out.push_str(&format!("{:03}", t.yday + 1)),
            b'm' => out.push_str(&format!("{:02}", t.mon + 1)),
            b'M' => out.push_str(&format!("{:02}", t.min)),
            b'n' => out.push('\n'),
            b'p' => out.push_str(if t.hour < 12 { "AM" } else { "PM" }),
            b'R' => out.push_str(&format!("{:02}:{:02}", t.hour, t.min)),
            b'S' => out.push_str(&format!("{:02}", t.sec)),
            b't' => out.push('\t'),
            b'T' => out.push_str(&format!("{:02}:{:02}:{:02}", t.hour, t.min, t.sec)),
            b'U' => out.push_str(&format!("{:02}", (t.yday + 7 - t.wday) / 7)),
            b'w' => out.push_str(&t.wday.to_string()),
            b'W' => out.push_str(&format!("{:02}", (t.yday + 7 - (t.wday + 6) % 7) / 7)),
            b'x' => out.push_str(&format!(
                "{:02}/{:02}/{:02}",
                t.mon + 1,
                t.mday,
                (year % 100).abs()
            )),
            b'X' => out.push_str(&format!("{:02}:{:02}:{:02}", t.hour, t.min, t.sec)),
            b'y' => out.push_str(&format!("{:02}", (year % 100).abs())),
            b'Y' => out.push_str(&year.to_string()),
            // The runtime does not carry a time-zone offset: UTC is reported.
            b'z' => out.push_str("+0000"),
            b'Z' => out.push_str("UTC"),
            b'%' => out.push('%'),
            _ => return None,
        }
    }
    Some(out.into_bytes())
}

/// `_strftime_l(buf, maxsize, format, tm, locale)`.
fn strftime_l(ctx: &mut ApiCtx) -> Result<()> {
    let (buf, max, fmt_p, tm_p) = (ctx.a(0), ctx.a(1), ctx.a(2), ctx.a(3));
    let fmt = ctx.cstr(fmt_p)?;
    let t = read_tm(ctx, tm_p)?;
    let produced = match format_tm(&fmt, t) {
        Some(s) => s,
        None => {
            ctx.set_errno(22);
            ctx.ret(0);
            return Ok(());
        }
    };
    if produced.len() as u64 + 1 > max {
        ctx.ret(0);
        return Ok(());
    }
    let mut data = produced.clone();
    data.push(0);
    ctx.put(buf, &data)?;
    ctx.ret(produced.len() as u64);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "ucrtbase",
        "_strftime_l" => strftime_l,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_locale_conversions() {
        // Thursday 1 January 2026, 14:05:09
        let t = Tm {
            sec: 9,
            min: 5,
            hour: 14,
            mday: 1,
            mon: 0,
            year: 126,
            wday: 4,
            yday: 0,
        };
        let s = format_tm(b"%Y-%m-%d %H:%M:%S %a %b %p %j", t).unwrap();
        assert_eq!(
            String::from_utf8(s).unwrap(),
            "2026-01-01 14:05:09 Thu Jan PM 001"
        );
        assert!(format_tm(b"%Q", t).is_none());
    }
}
