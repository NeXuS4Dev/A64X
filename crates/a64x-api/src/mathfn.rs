//! Math functions with MSVC error semantics.
//!
//! Errors are classified like the UCRT (`_DOMAIN`, `_SING`, `_OVERFLOW`,
//! `_UNDERFLOW`): domain errors set EDOM, pole/overflow/underflow set ERANGE.
//! If a handler was installed with `__setusermatherr`, it is called with a
//! `struct _exception` and its return value replaces the result when it
//! returns non-zero (the continuation resumes the original call).

use crate::cont::{self, Frame};
use crate::{reg, ApiCtx, ApiDef};
use a64x_core::Result;

const EDOM: i32 = 33;
const ERANGE: i32 = 34;

/// `_DOMAIN`.
const T_DOMAIN: u32 = 1;
/// `_SING`.
const T_SING: u32 = 2;
/// `_OVERFLOW`.
const T_OVERFLOW: u32 = 3;
/// `_UNDERFLOW`.
const T_UNDERFLOW: u32 = 4;

/// Size of `struct _exception` (type, name, arg1, arg2, retval).
const EXCEPTION_SIZE: u64 = 40;

/// Classification of a computed result: `Some((type, errno))` on error.
type MathErr = Option<(u32, i32)>;

fn exp_err(x: f64, r: f64) -> MathErr {
    if r.is_infinite() && x.is_finite() {
        Some((T_OVERFLOW, ERANGE))
    } else if r == 0.0 && x.is_finite() {
        Some((T_UNDERFLOW, ERANGE))
    } else {
        None
    }
}

fn log_err(x: f64) -> MathErr {
    if x < 0.0 {
        Some((T_DOMAIN, EDOM))
    } else if x == 0.0 {
        Some((T_SING, ERANGE))
    } else {
        None
    }
}

fn pow_err(x: f64, y: f64, r: f64) -> MathErr {
    if x == 0.0 && y < 0.0 && y.is_finite() {
        return Some((T_SING, ERANGE));
    }
    if x < 0.0 && x.is_finite() && y.is_finite() && y.fract() != 0.0 {
        return Some((T_DOMAIN, EDOM));
    }
    if r.is_infinite() && x.is_finite() && y.is_finite() {
        return Some((T_OVERFLOW, ERANGE));
    }
    if r == 0.0 && x != 0.0 && x.is_finite() && y.is_finite() {
        return Some((T_UNDERFLOW, ERANGE));
    }
    None
}

/// Deliver a math result: set errno, optionally call the user matherr.
fn finish(ctx: &mut ApiCtx, name: &str, value: f64, err: MathErr, a1: f64, a2: f64) -> Result<()> {
    let Some((kind, errno)) = err else {
        ctx.ret_f64(value);
        return Ok(());
    };
    let prev = ctx.errno();
    ctx.set_errno(errno);
    let handler = ctx.p.crt.matherr;
    if handler == 0 {
        ctx.ret_f64(value);
        return Ok(());
    }
    let (ex, _) = ctx.p.statics.var("matherr_exception", EXCEPTION_SIZE)?;
    let name_ptr = ctx.intern_cstr(name.as_bytes())?;
    ctx.wr(ex, 4, kind as u64)?;
    ctx.wr(ex + 8, 8, name_ptr)?;
    ctx.wr(ex + 16, 8, a1.to_bits())?;
    ctx.wr(ex + 24, 8, a2.to_bits())?;
    ctx.wr(ex + 32, 8, value.to_bits())?;
    let lr = ctx.state.x[30];
    cont::call_guest(
        ctx,
        handler,
        &[ex],
        Frame::MathErr {
            lr,
            ex,
            prev_errno: prev,
        },
    );
    Ok(())
}

fn exp(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    let r = x.exp();
    finish(ctx, "exp", r, exp_err(x, r), x, 0.0)
}

fn log(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    let r = x.ln();
    finish(ctx, "log", r, log_err(x), x, 0.0)
}

fn log10(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    let r = x.log10();
    finish(ctx, "log10", r, log_err(x), x, 0.0)
}

fn pow(ctx: &mut ApiCtx) -> Result<()> {
    let (x, y) = (ctx.af(0), ctx.af(1));
    let r = x.powf(y);
    finish(ctx, "pow", r, pow_err(x, y, r), x, y)
}

fn sqrt(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    let r = x.sqrt();
    let err = if x < 0.0 {
        Some((T_DOMAIN, EDOM))
    } else {
        None
    };
    finish(ctx, "sqrt", r, err, x, 0.0)
}

fn fabs(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    ctx.ret_f64(x.abs());
    Ok(())
}

fn floor(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    ctx.ret_f64(x.floor());
    Ok(())
}

fn ceil(ctx: &mut ApiCtx) -> Result<()> {
    let x = ctx.af(0);
    ctx.ret_f64(x.ceil());
    Ok(())
}

/// `__setusermatherr(handler)`: install the matherr callback.
fn setusermatherr(ctx: &mut ApiCtx) -> Result<()> {
    ctx.p.crt.matherr = ctx.a(0);
    Ok(())
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "ucrtbase",
        "exp" => exp,
        "log" => log,
        "log10" => log10,
        "pow" => pow,
        "sqrt" => sqrt,
        "fabs" => fabs,
        "floor" => floor,
        "ceil" => ceil,
        "__setusermatherr" => setusermatherr,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_matches_msvc_categories() {
        assert_eq!(log_err(-1.0), Some((T_DOMAIN, EDOM)));
        assert_eq!(log_err(0.0), Some((T_SING, ERANGE)));
        assert_eq!(exp_err(1000.0, f64::INFINITY), Some((T_OVERFLOW, ERANGE)));
        assert_eq!(exp_err(-1000.0, 0.0), Some((T_UNDERFLOW, ERANGE)));
        assert_eq!(pow_err(-8.0, 1.0 / 3.0, f64::NAN), Some((T_DOMAIN, EDOM)));
        assert_eq!(pow_err(2.0, 10.0, 1024.0), None);
        assert_eq!(pow_err(0.0, -1.0, f64::INFINITY), Some((T_SING, ERANGE)));
    }
}
