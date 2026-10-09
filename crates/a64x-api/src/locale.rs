//! Locale functions. Only the "C" locale is available: names other than
//! "C"/"POSIX"/"" are rejected (setlocale returns NULL, _create_locale fails).
//! Classification and conversion follow the C locale (ASCII only).

use crate::strings::c_flags;
use crate::{heap, reg, ApiCtx, ApiDef};
use a64x_core::Result;
use std::collections::BTreeMap;

/// `_ENABLE_PER_THREAD_LOCALE` (documented semantics; value unverified).
const ENABLE_PER_THREAD: u64 = 1;
/// `_DISABLE_PER_THREAD_LOCALE` (documented semantics; value unverified).
const DISABLE_PER_THREAD: u64 = 2;
/// Size of the guest `lconv` structure.
const LCONV_SIZE: u64 = 152;
const EINVAL: i32 = 22;

/// Locale state of the process.
#[derive(Default)]
pub(crate) struct LocaleState {
    /// Per-thread locale status by thread id (absent = global).
    pub per_thread: BTreeMap<u32, bool>,
    /// Guest address of the ctype table, once created.
    pub ctype: u64,
    /// Guest address of the lconv structure, once created.
    pub lconv: u64,
}

/// Valid LC_* category numbers (LC_ALL = 6).
fn valid_category(c: i32) -> bool {
    (0..=6).contains(&c)
}

/// True for the locale names this runtime supports.
fn supported(name: &str) -> bool {
    matches!(name, "" | "C" | "POSIX")
}

fn ctype_table(ctx: &mut ApiCtx) -> Result<u64> {
    if ctx.p.locale.ctype != 0 {
        return Ok(ctx.p.locale.ctype);
    }
    // index 0 is EOF (-1), index 1 + c is byte c
    let base = ctx.p.statics.alloc(2 * 257 + 2, 16)?;
    for k in 0..257u64 {
        let c = k as i64 - 1;
        let flags = if (0..=255).contains(&c) {
            c_flags(c as u8)
        } else {
            0
        };
        ctx.wr(base + 2 * k, 2, flags as u64)?;
    }
    let table = base + 2; // pointer to byte 0's entry; [-1] is EOF
    ctx.p.locale.ctype = table;
    Ok(table)
}

fn lconv_struct(ctx: &mut ApiCtx) -> Result<u64> {
    if ctx.p.locale.lconv != 0 {
        return Ok(ctx.p.locale.lconv);
    }
    let base = ctx.p.statics.alloc(LCONV_SIZE, 16)?;
    let dot = ctx.intern_cstr(b".")?;
    let empty = ctx.intern_cstr(b"")?;
    let wdot = ctx.intern_wstr(&[b'.' as u16])?;
    let wempty = ctx.intern_wstr(&[])?;
    ctx.zero(base, LCONV_SIZE)?;
    // narrow string fields 0..=63 (decimal_point, thousands_sep, grouping, ...)
    for i in 0..8u64 {
        let v = if i == 0 { dot } else { empty };
        ctx.wr(base + 8 * i, 8, v)?;
    }
    for i in 8..16u64 {
        ctx.wr(base + 8 * i, 8, empty)?;
    }
    // char fields 80..=87 are CHAR_MAX ("not specified" in the C locale)
    for i in 80..88u64 {
        ctx.wr(base + i, 1, 127)?;
    }
    // wide string fields 88..=151
    for i in 0..8u64 {
        let v = if i == 0 { wdot } else { wempty };
        ctx.wr(base + 88 + 8 * i, 8, v)?;
    }
    ctx.p.locale.lconv = base;
    Ok(base)
}

fn setlocale(ctx: &mut ApiCtx) -> Result<()> {
    let cat = ctx.ai(0);
    let name_ptr = ctx.a(1);
    if !valid_category(cat) {
        ctx.set_errno(EINVAL);
        ctx.ret(0);
        return Ok(());
    }
    if name_ptr == 0 {
        let a = ctx.intern_cstr(b"C")?;
        ctx.ret(a);
        return Ok(());
    }
    let name = ctx.cstr_string(name_ptr)?;
    if !supported(&name) {
        ctx.ret(0);
        return Ok(());
    }
    let a = ctx.intern_cstr(b"C")?;
    ctx.ret(a);
    Ok(())
}

fn localeconv(ctx: &mut ApiCtx) -> Result<()> {
    let a = lconv_struct(ctx)?;
    ctx.ret(a);
    Ok(())
}

fn create_locale(ctx: &mut ApiCtx) -> Result<()> {
    let cat = ctx.ai(0);
    let name = ctx.cstr_string(ctx.a(1))?;
    if !valid_category(cat) || !supported(&name) {
        ctx.set_errno(EINVAL);
        ctx.ret(0);
        return Ok(());
    }
    // a locale object: a heap block holding the locale name's first byte
    let p = heap::alloc(ctx, 0, 16, 16, true)?;
    if p == 0 {
        ctx.ret(0);
        return Ok(());
    }
    ctx.wr(p, 1, b'C' as u64)?;
    ctx.ret(p);
    Ok(())
}

fn free_locale(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    if p != 0 {
        heap::free(ctx, 0, p);
    }
    Ok(())
}

fn configthreadlocale(ctx: &mut ApiCtx) -> Result<()> {
    let ty = ctx.au(0) as u64;
    let tid = ctx.p.sched.cur_tid();
    let current = ctx.p.locale.per_thread.get(&tid).copied().unwrap_or(false);
    let prev = if current {
        ENABLE_PER_THREAD
    } else {
        DISABLE_PER_THREAD
    };
    match ty {
        0 => ctx.ret_i32(prev as i32),
        ENABLE_PER_THREAD => {
            ctx.p.locale.per_thread.insert(tid, true);
            ctx.ret_i32(prev as i32);
        }
        DISABLE_PER_THREAD => {
            ctx.p.locale.per_thread.insert(tid, false);
            ctx.ret_i32(prev as i32);
        }
        _ => {
            ctx.set_errno(EINVAL);
            ctx.ret_i32(-1);
        }
    }
    Ok(())
}

fn lc_codepage(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(0);
    Ok(())
}

fn mb_cur_max(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(1);
    Ok(())
}

fn pctype(ctx: &mut ApiCtx) -> Result<()> {
    let t = ctype_table(ctx)?;
    ctx.ret(t);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "ucrtbase",
        "setlocale" => setlocale,
        "localeconv" => localeconv,
        "_create_locale" => create_locale,
        "_free_locale" => free_locale,
        "_configthreadlocale" => configthreadlocale,
        "___lc_codepage_func" => lc_codepage,
        "___mb_cur_max_func" => mb_cur_max,
        "__pctype_func" => pctype,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_c_locale_is_supported() {
        assert!(supported("C"));
        assert!(supported("POSIX"));
        assert!(supported(""));
        assert!(!supported("en_US.UTF-8"));
        assert!(valid_category(6));
        assert!(!valid_category(7));
    }
}
