//! KERNEL32 system information: time and FILETIME conversion, performance
//! counters, processor/NUMA queries and FormatMessage.

use crate::format::{self, Args};
use crate::kernel32::{copy_ansi_out, copy_wide_out, ERROR_INSUFFICIENT_BUFFER};
use crate::{heap, reg, ApiCtx, ApiDef};
use a64x_core::Result;

/// 100-ns intervals between 1601-01-01 and 1970-01-01.
pub(crate) const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Win32 error for an unknown message number.
const ERROR_MR_MID_NOT_FOUND: u32 = 317;

/// FILETIME for a host time.
pub(crate) fn unix_to_filetime(t: std::time::SystemTime) -> u64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => FILETIME_EPOCH_DIFF + d.as_secs() * 10_000_000 + (d.subsec_nanos() / 100) as u64,
        Err(e) => {
            let d = e.duration();
            FILETIME_EPOCH_DIFF
                .saturating_sub(d.as_secs() * 10_000_000 + (d.subsec_nanos() / 100) as u64)
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month, day) for days since 1970-01-01.
pub(crate) fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// SYSTEMTIME fields (year, month, dow, day, hour, minute, second, ms) from
/// a FILETIME value (UTC).
pub(crate) fn systemtime_fields(ft: u64) -> [u16; 8] {
    let total_ms = ft.saturating_sub(FILETIME_EPOCH_DIFF) / 10_000;
    let secs = (total_ms / 1000) as i64;
    let ms = (total_ms % 1000) as u16;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let dow = (days + 4).rem_euclid(7) as u16;
    [
        y as u16,
        m as u16,
        dow,
        d as u16,
        (rem / 3600) as u16,
        ((rem % 3600) / 60) as u16,
        (rem % 60) as u16,
        ms,
    ]
}

/// FILETIME from SYSTEMTIME fields (UTC).
pub(crate) fn filetime_from_fields(f: [u16; 8]) -> u64 {
    let days = days_from_civil(f[0] as i64, f[1] as i64, f[3] as i64);
    let secs = days * 86_400 + f[4] as i64 * 3600 + f[5] as i64 * 60 + f[6] as i64;
    let ticks = secs as u64 * 10_000_000 + f[7] as u64 * 10_000;
    FILETIME_EPOCH_DIFF + ticks
}

fn now_ft() -> u64 {
    crate::kernel32::filetime_now()
}

fn write_systemtime(ctx: &mut ApiCtx, out: u64, ft: u64) -> Result<()> {
    let f = systemtime_fields(ft);
    for (i, v) in f.iter().enumerate() {
        ctx.wr(out + 2 * i as u64, 2, *v as u64)?;
    }
    Ok(())
}

fn read_systemtime(ctx: &ApiCtx, p: u64) -> Result<[u16; 8]> {
    let mut f = [0u16; 8];
    for (i, v) in f.iter_mut().enumerate() {
        *v = ctx.rd(p + 2 * i as u64, 2)? as u16;
    }
    Ok(f)
}

fn logical_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
        .min(64)
}

/// SYSTEM_INFO (48 bytes): ARM64 architecture, 4 KiB pages, 64 KiB granularity.
fn get_system_info(ctx: &mut ApiCtx) -> Result<()> {
    let out = ctx.a(0);
    let n = logical_cpus();
    ctx.zero(out, 48)?;
    ctx.wr(out, 2, 12)?; // PROCESSOR_ARCHITECTURE_ARM64
    ctx.wr(out + 4, 4, 0x1000)?;
    ctx.wr(out + 8, 8, 0x1_0000)?;
    ctx.wr(out + 16, 8, 0x7FFF_FFFE_FFFF)?;
    let mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    ctx.wr(out + 24, 8, mask)?;
    ctx.wr(out + 32, 4, n as u64)?;
    ctx.wr(out + 36, 4, 0)?;
    ctx.wr(out + 40, 4, 0x1_0000)?;
    Ok(())
}

fn get_active_processor_count(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(logical_cpus() as u64);
    Ok(())
}

fn get_processor_affinity_mask(ctx: &mut ApiCtx) -> Result<()> {
    let (proc_p, sys_p) = (ctx.a(1), ctx.a(2));
    let n = logical_cpus();
    let mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    if proc_p != 0 {
        ctx.wr(proc_p, 8, mask)?;
    }
    if sys_p != 0 {
        ctx.wr(sys_p, 8, mask)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn get_tick_count(ctx: &mut ApiCtx) -> Result<()> {
    let ms = ctx.p.k32.start.elapsed().as_millis() as u64;
    ctx.ret(ms & 0xFFFF_FFFF);
    Ok(())
}

fn get_tick_count_64(ctx: &mut ApiCtx) -> Result<()> {
    let ms = ctx.p.k32.start.elapsed().as_millis() as u64;
    ctx.ret(ms);
    Ok(())
}

fn query_performance_counter(ctx: &mut ApiCtx) -> Result<()> {
    let ns = ctx.p.k32.start.elapsed().as_nanos() as u64;
    ctx.wr(ctx.a(0), 8, ns)?;
    ctx.ret_bool(true);
    Ok(())
}

fn query_performance_frequency(ctx: &mut ApiCtx) -> Result<()> {
    ctx.wr(ctx.a(0), 8, 1_000_000_000)?;
    ctx.ret_bool(true);
    Ok(())
}

fn get_system_time_as_file_time(ctx: &mut ApiCtx) -> Result<()> {
    let out = ctx.a(0);
    let ft = now_ft();
    ctx.wr(out, 8, ft)?;
    Ok(())
}

fn get_system_time(ctx: &mut ApiCtx) -> Result<()> {
    let out = ctx.a(0);
    let ft = now_ft();
    write_systemtime(ctx, out, ft)
}

fn system_time_to_file_time(ctx: &mut ApiCtx) -> Result<()> {
    let f = read_systemtime(ctx, ctx.a(0))?;
    let out = ctx.a(1);
    let ft = filetime_from_fields(f);
    ctx.wr(out, 8, ft)?;
    ctx.ret_bool(true);
    Ok(())
}

fn file_time_to_system_time(ctx: &mut ApiCtx) -> Result<()> {
    let ft = ctx.rd(ctx.a(0), 8)?;
    let out = ctx.a(1);
    write_systemtime(ctx, out, ft)?;
    ctx.ret_bool(true);
    Ok(())
}

/// Local time is UTC on this runtime (no time-zone information is provided).
fn file_time_passthrough(ctx: &mut ApiCtx) -> Result<()> {
    let ft = ctx.rd(ctx.a(0), 8)?;
    ctx.wr(ctx.a(1), 8, ft)?;
    ctx.ret_bool(true);
    Ok(())
}

fn get_time_zone_information(ctx: &mut ApiCtx) -> Result<()> {
    let out = ctx.a(0);
    ctx.zero(out, 172)?;
    ctx.ret(0); // TIME_ZONE_ID_UNKNOWN
    Ok(())
}

fn get_numa_highest_node_number(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(0);
    if p != 0 {
        ctx.wr(p, 4, 0)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn get_numa_processor_node(ctx: &mut ApiCtx) -> Result<()> {
    let p = ctx.a(1);
    if p != 0 {
        ctx.wr(p, 2, 0)?;
    }
    ctx.ret_bool(true);
    Ok(())
}

fn get_current_processor_number(ctx: &mut ApiCtx) -> Result<()> {
    ctx.ret(0);
    Ok(())
}

/// GetLogicalProcessorInformation: one RelationProcessorCore record (32
/// bytes) per logical processor; the runtime does not expose cache topology.
fn get_logical_processor_information(ctx: &mut ApiCtx) -> Result<()> {
    let (buf, len_p) = (ctx.a(0), ctx.a(1));
    let n = logical_cpus() as u64;
    let need = 32 * n;
    let have = ctx.rd(len_p, 4)?;
    if buf == 0 || have < need {
        ctx.wr(len_p, 4, need)?;
        ctx.set_last_error(ERROR_INSUFFICIENT_BUFFER);
        ctx.ret_bool(false);
        return Ok(());
    }
    for i in 0..n {
        let rec = buf + 32 * i;
        ctx.zero(rec, 32)?;
        ctx.wr(rec, 8, 1u64 << i)?;
        ctx.wr(rec + 8, 4, 0)?; // RelationProcessorCore
    }
    ctx.wr(len_p, 4, need)?;
    ctx.ret_bool(true);
    Ok(())
}

/// Message text of a known system error code.
pub(crate) fn system_message(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "The operation completed successfully.",
        1 => "Incorrect function.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough memory resources are available to process this command.",
        18 => "There are no more files.",
        87 => "The parameter is incorrect.",
        122 => "The data area passed to a system call is too small.",
        126 => "The specified module could not be found.",
        127 => "The specified procedure could not be found.",
        183 => "Cannot create a file when that file already exists.",
        203 => "The system could not find the environment option that was entered.",
        998 => "Invalid access to memory location.",
        1460 => "This operation returned because the timeout period expired.",
        _ => return None,
    })
}

/// Expand a FormatMessage format string: `%n` (CRLF), `%%`, `%0`, and
/// insertions `%N` / `%N!spec!` taken from the argument list.
fn expand_message(
    ctx: &ApiCtx,
    fmt: &[u32],
    args: &mut Args,
    cache: &mut Vec<u64>,
) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let arg_at = |idx: usize, args: &mut Args, cache: &mut Vec<u64>| -> Result<u64> {
        while cache.len() <= idx {
            cache.push(args.next(ctx)?);
        }
        Ok(cache[idx])
    };
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' as u32 {
            out.push(c);
            continue;
        }
        let Some(&n) = fmt.get(i) else {
            out.push(c);
            break;
        };
        i += 1;
        match n {
            0x25 => out.push(0x25),
            0x6E => out.extend("\r\n".bytes().map(|b| b as u32)),
            0x30 => {}
            0x31..=0x39 => {
                let mut idx = (n - 0x30) as usize;
                while let Some(&d) = fmt.get(i) {
                    if (0x30..=0x39).contains(&d) && idx < 100 {
                        idx = idx * 10 + (d - 0x30) as usize;
                        i += 1;
                    } else {
                        break;
                    }
                }
                let mut spec: Vec<u8> = Vec::new();
                if fmt.get(i) == Some(&(b'!' as u32)) {
                    i += 1;
                    while let Some(&d) = fmt.get(i) {
                        i += 1;
                        if d == b'!' as u32 {
                            break;
                        }
                        spec.push(d as u8);
                    }
                }
                let raw = arg_at(idx - 1, args, cache)?;
                let text: Vec<u32> = match spec.as_slice() {
                    b"s" | b"S" => ctx.cstr(raw)?.into_iter().map(|b| b as u32).collect(),
                    b"ls" | b"ws" => ctx.wstr(raw)?.into_iter().map(|u| u as u32).collect(),
                    b"x" => format!("{:x}", raw as u32)
                        .bytes()
                        .map(|b| b as u32)
                        .collect(),
                    b"X" => format!("{:X}", raw as u32)
                        .bytes()
                        .map(|b| b as u32)
                        .collect(),
                    b"c" => vec![raw as u32 & 0xFF],
                    _ => (raw as u32 as i32)
                        .to_string()
                        .bytes()
                        .map(|b| b as u32)
                        .collect(),
                };
                out.extend(text);
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// FormatMessageA/W core.
fn format_message(ctx: &mut ApiCtx, wide: bool) -> Result<()> {
    let flags = ctx.au(0);
    let source = ctx.a(1);
    let msg_id = ctx.au(2);
    let buf_p = ctx.a(4);
    let size = ctx.au(5) as u64;
    let arg_p = ctx.a(6);
    const ALLOCATE: u32 = 0x100;
    const FROM_STRING: u32 = 0x400;
    const FROM_SYSTEM: u32 = 0x1000;
    const IGNORE_INSERTS: u32 = 0x200;
    const ARGUMENT_ARRAY: u32 = 0x2000;

    let template: Vec<u32> = if flags & FROM_STRING != 0 {
        if wide {
            format::wide_units(ctx, source)?
        } else {
            format::narrow_units(ctx, source)?
        }
    } else if flags & FROM_SYSTEM != 0 {
        match system_message(msg_id) {
            Some(m) => {
                let mut t: Vec<u32> = m.bytes().map(|b| b as u32).collect();
                t.extend("\r\n".bytes().map(|b| b as u32));
                t
            }
            None => {
                ctx.set_last_error(ERROR_MR_MID_NOT_FOUND);
                ctx.ret(0);
                return Ok(());
            }
        }
    } else {
        ctx.set_last_error(87);
        ctx.ret(0);
        return Ok(());
    };
    let text = if flags & IGNORE_INSERTS != 0 {
        template
    } else {
        let mut args = if flags & ARGUMENT_ARRAY != 0 {
            // an array of 64-bit slots, read as a va_list
            Args::va(arg_p)
        } else {
            Args::va(arg_p)
        };
        let mut cache = Vec::new();
        expand_message(ctx, &template, &mut args, &mut cache)?
    };
    let units: Vec<u16> = if wide {
        text.iter().map(|u| *u as u16).collect()
    } else {
        Vec::new()
    };
    let ansi: Vec<u8> = if wide {
        Vec::new()
    } else {
        text.iter().map(|u| *u as u8).collect()
    };
    let count = if wide { units.len() } else { ansi.len() } as u64;
    if flags & ALLOCATE != 0 {
        let bytes = if wide { 2 * (count + 1) } else { count + 1 };
        let block = heap::alloc(ctx, 0, bytes, 16, false)?;
        if block == 0 {
            ctx.set_last_error(8);
            ctx.ret(0);
            return Ok(());
        }
        if wide {
            ctx.put_wide(block, &units)?;
            ctx.wr(block + 2 * count, 2, 0)?;
        } else {
            ctx.put(block, &ansi)?;
            ctx.wr(block + count, 1, 0)?;
        }
        ctx.wr(buf_p, 8, block)?;
        ctx.ret(count);
        return Ok(());
    }
    let written = if wide {
        copy_wide_out(ctx, buf_p, size, &units)?
    } else {
        copy_ansi_out(ctx, buf_p, size, &ansi)?
    };
    if written > count {
        ctx.set_last_error(ERROR_INSUFFICIENT_BUFFER);
        ctx.ret(0);
        return Ok(());
    }
    ctx.ret(count);
    Ok(())
}

fn format_message_a(ctx: &mut ApiCtx) -> Result<()> {
    format_message(ctx, false)
}

fn format_message_w(ctx: &mut ApiCtx) -> Result<()> {
    format_message(ctx, true)
}

pub(crate) fn register(v: &mut Vec<ApiDef>) {
    reg!(v, "kernel32",
        "GetSystemInfo" => get_system_info,
        "GetNativeSystemInfo" => get_system_info,
        "GetActiveProcessorCount" => get_active_processor_count,
        "GetMaximumProcessorCount" => get_active_processor_count,
        "GetProcessAffinityMask" => get_processor_affinity_mask,
        "GetTickCount" => get_tick_count,
        "GetTickCount64" => get_tick_count_64,
        "QueryPerformanceCounter" => query_performance_counter,
        "QueryPerformanceFrequency" => query_performance_frequency,
        "GetSystemTimeAsFileTime" => get_system_time_as_file_time,
        "GetSystemTimePreciseAsFileTime" => get_system_time_as_file_time,
        "GetSystemTime" => get_system_time,
        "GetLocalTime" => get_system_time,
        "SystemTimeToFileTime" => system_time_to_file_time,
        "FileTimeToSystemTime" => file_time_to_system_time,
        "FileTimeToLocalFileTime" => file_time_passthrough,
        "LocalFileTimeToFileTime" => file_time_passthrough,
        "GetTimeZoneInformation" => get_time_zone_information,
        "GetNumaHighestNodeNumber" => get_numa_highest_node_number,
        "GetNumaProcessorNode" => get_numa_processor_node,
        "GetCurrentProcessorNumber" => get_current_processor_number,
        "GetLogicalProcessorInformation" => get_logical_processor_information,
        "FormatMessageA" => format_message_a,
        "FormatMessageW" => format_message_w,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        let d = days_from_civil(2026, 10, 9);
        assert_eq!(civil_from_days(d), (2026, 10, 9));
    }

    #[test]
    fn filetime_round_trip() {
        let f = [2026u16, 10, 5, 9, 14, 5, 9, 123];
        let ft = filetime_from_fields(f);
        assert_eq!(systemtime_fields(ft), f);
        // 1970-01-01 00:00:00 UTC is the FILETIME epoch difference
        assert_eq!(
            filetime_from_fields([1970, 1, 4, 1, 0, 0, 0, 0]),
            FILETIME_EPOCH_DIFF
        );
    }

    #[test]
    fn known_messages() {
        assert_eq!(
            system_message(2),
            Some("The system cannot find the file specified.")
        );
        assert_eq!(system_message(9999), None);
    }
}
