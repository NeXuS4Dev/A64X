//! # a64x — command-line frontend for the A64X compatibility layer.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use a64x_core::memory;
use a64x_core::state::ExitReason;
use a64x_pe::PeImage;
use a64x_rt::{demo, dispatch, Guest};
use a64x_xlat::{CodeCache, XlatConfig};

const BANNER: &str = "A64X 0.1.0 — ARM64-on-x86-64 Windows compatibility layer";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        usage(&mut io::stdout()).ok();
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    let code: u8 = match cmd {
        "info" => cmd_info(rest),
        "xlat" => cmd_xlat(rest),
        "run" => cmd_run(rest),
        "cache" => cmd_cache(rest),
        "demo" => cmd_demo(rest),
        "-h" | "--help" | "help" => {
            usage(&mut io::stdout()).ok();
            0
        }
        "-V" | "--version" => {
            println!("{BANNER}");
            0
        }
        other => {
            eprintln!("a64x: unknown command `{other}` — try `a64x help`");
            2
        }
    };
    ExitCode::from(code)
}

fn usage(w: &mut dyn Write) -> io::Result<()> {
    writeln!(
        w,
        "{BANNER}

USAGE:
    a64x info  <program.exe>                     PE headers, sections, imports
    a64x xlat  <program.exe> [--disasm]          translate the entry block
    a64x run   <program.exe> [--fast] [--trace] [-- args...]
    a64x cache <cache-dir> <program.exe> [-- args...]
                                                 run with a persistent code cache
    a64x demo  [--bench N] [--trace]             built-in ARM64 demo

FLAGS:
    --fast     mask memory accesses instead of bounds-checking (faster)
    --trace    print one line per dispatcher round (very verbose)
    --disasm   also print the decoded guest instruction listing"
    )
}

// -- helpers -----------------------------------------------------------------

fn load_exe(path: &str) -> Result<Vec<u8>, u8> {
    fs::read(path).map_err(|e| {
        eprintln!("a64x: cannot read `{path}`: {e}");
        2u8
    })
}

fn exe_arg(args: &[String]) -> Option<&str> {
    args.iter().take_while(|a| a.as_str() != "--").find(|a| !a.starts_with('-')).map(String::as_str)
}

fn tail_args(args: &[String]) -> Vec<&str> {
    let mut it = args.iter();
    if it.any(|a| a == "--") {
        it.map(String::as_str).collect()
    } else {
        Vec::new()
    }
}

fn guest_cmdline(prog: &str, tail: &[&str]) -> Vec<u8> {
    let mut s = format!("\"{prog}\"");
    for a in tail {
        s.push(' ');
        s.push_str(a);
    }
    s.push('\0');
    s.into_bytes()
}

fn mk_guest(bytes: &[u8], cfg: XlatConfig) -> Result<Guest, u8> {
    Guest::load(bytes, cfg).map_err(|e| {
        eprintln!("a64x: failed to load image: {e}");
        2u8
    })
}

fn print_outcome(out: &dispatch::RunOutcome, wall: std::time::Duration) {
    println!("---");
    println!("reason:       {:?} (exit code {})", out.reason, out.exit_code);
    if let Some(m) = &out.message {
        println!("message:      {m}");
    }
    println!("stopped at:   pc={:#x}", out.pc);
    println!(
        "guest insns:  {}  ({} API calls, {} blocks translated)",
        out.insn_count, out.api_calls, out.blocks_translated
    );
    let secs = wall.as_secs_f64();
    if secs > 0.001 {
        println!("wall time:    {secs:.3}s  {:.1} M guest-insn/s", out.insn_count as f64 / secs / 1e6);
    }
}

fn outcome_code(out: &dispatch::RunOutcome) -> u8 {
    match out.reason {
        ExitReason::Exited => (out.exit_code & 0xFF) as u8,
        _ => 64,
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// -- info --------------------------------------------------------------------

fn cmd_info(args: &[String]) -> u8 {
    let Some(path) = exe_arg(args) else {
        eprintln!("a64x info: missing <program.exe>");
        return 2;
    };
    let bytes = match load_exe(path) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let pe = match PeImage::parse(&bytes) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("a64x: `{path}` is not a supported PE: {e}");
            return 2;
        }
    };
    let out = io::stdout();
    let mut o = out.lock();
    let _ = writeln!(o, "{BANNER}");
    let _ = writeln!(o, "file:        {path} ({} bytes)", bytes.len());
    let _ = writeln!(o, "machine:     {:#06x} ({})", pe.machine, pe.machine_name());
    let _ = writeln!(o, "type:        {}", if pe.is_dll() { "DLL" } else { "executable" });
    let _ = writeln!(o, "image base:  {:#x}", pe.image_base);
    let _ = writeln!(o, "entry RVA:   {:#x} (VA {:#x})", pe.entry_point, pe.image_base + pe.entry_point as u64);
    let _ = writeln!(o, "image size:  {:#x}", pe.size_of_image);
    let _ = writeln!(o, "sections:    {}", pe.sections.len());
    for s in &pe.sections {
        let _ = writeln!(
            o,
            "  {:8} va {:#08x} raw {:#08x} {}{}{}",
            s.name.trim_end_matches('\0'),
            s.vaddr,
            s.raw_size,
            if s.is_code() { "exec " } else { "" },
            if s.flags & 0x4000_0000 != 0 { "init " } else { "" },
            if s.flags & 0x8000_0000 != 0 { "write" } else { "" },
        );
    }
    match pe.imports() {
        Ok(imports) if !imports.is_empty() => {
            let _ = writeln!(o, "imports:     {}", imports.len());
            let mut last_dll = String::new();
            for imp in &imports {
                if imp.dll != last_dll {
                    last_dll = imp.dll.clone();
                    let _ = writeln!(o, "  {}:", last_dll);
                }
                let _ = writeln!(o, "    {:40} IAT @{:#x}", imp.symbol, imp.iat_rva);
            }
        }
        _ => {
            let _ = writeln!(o, "imports:     <none>");
        }
    }
    0
}

// -- xlat --------------------------------------------------------------------

fn cmd_xlat(args: &[String]) -> u8 {
    let disasm = args.iter().any(|a| a == "--disasm");
    let Some(path) = exe_arg(args) else {
        eprintln!("a64x xlat: missing <program.exe>");
        return 2;
    };
    let bytes = match load_exe(path) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let pe = match PeImage::parse(&bytes) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("a64x: `{path}` is not a supported PE: {e}");
            return 2;
        }
    };
    if pe.machine != a64x_pe::IMAGE_FILE_MACHINE_ARM64 {
        eprintln!("a64x xlat: `{path}` is not an ARM64 image (machine {:?})", pe.machine);
        return 2;
    }
    let mut g = match mk_guest(&bytes, XlatConfig::default()) {
        Ok(g) => g,
        Err(c) => return c,
    };
    let entry = g.image.entry;
    let t0 = Instant::now();
    if let Err(e) = g.machine.cache.get_or_translate(&g.machine.mem, entry) {
        eprintln!("a64x xlat: translation failed at {entry:#x}: {e}");
        return 2;
    }
    let dt = t0.elapsed();
    println!("{BANNER}");
    println!(
        "translated entry block in {:?}: {} block(s), {} guest insns, {} host code bytes",
        dt, g.machine.cache.len(), g.machine.cache.stats.insns_translated, g.machine.cache.stats.code_bytes
    );
    for (pc, blk) in g.machine.cache.blocks() {
        println!(
            "block @{pc:#x}: {} guest insns ({} guest bytes) → {} host bytes, {} exit link(s)",
            blk.n_insns,
            blk.guest_len,
            blk.exec.code_len(),
            blk.links.len()
        );
        if !disasm {
            continue;
        }
        for i in 0..blk.n_insns {
            let addr = pc + i as u64 * 4;
            let w = match g.machine.mem.read_int(addr, 4).map(|v| v as u32) {
                Ok(w) => w,
                Err(_) => {
                    println!("    {addr:#x}:  <unreadable>");
                    break;
                }
            };
            match a64x_arm64::decode(w, addr) {
                Ok(insn) => println!("    {addr:#x}:  {w:08x}    {insn:?}"),
                Err(_) => println!("    {addr:#x}:  {w:08x}    .word {w:#010x}"),
            }
        }
    }
    0
}

// -- run ---------------------------------------------------------------------

/// Windows-style path of the program as the guest sees it.
fn windows_path(path: &str) -> String {
    let base = std::path::Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    format!("C:\\guest\\{base}")
}

fn cmd_run(args: &[String]) -> u8 {
    let fast = args.iter().any(|a| a == "--fast");
    let trace = args.iter().any(|a| a == "--trace");
    let Some(path) = exe_arg(args) else {
        eprintln!("a64x run: missing <program.exe>");
        return 2;
    };
    let bytes = match load_exe(path) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let cfg = XlatConfig { checked_mem: !fast, count_stats: true };
    let mut g = match mk_guest(&bytes, cfg) {
        Ok(g) => g,
        Err(c) => return c,
    };
    let cmdline = guest_cmdline(path, &tail_args(args));
    g = g.with_path(&windows_path(path));

    let t0 = Instant::now();
    let modules = [g.image.module.clone()];
    let run_cfg = a64x_rt::RunConfig {
        entry: g.image.entry,
        cmdline: &cmdline,
        image_base: g.image.image_base,
        modules: &modules,
        trace,
    };
    let out = a64x_rt::dispatch::run_with(&mut g.machine, &g.api, &run_cfg);
    let wall = t0.elapsed();
    print_outcome(&out, wall);
    outcome_code(&out)
}

// -- cache -------------------------------------------------------------------

fn cmd_cache(args: &[String]) -> u8 {
    let mut nonflag = args.iter().take_while(|a| a.as_str() != "--").filter(|a| !a.starts_with('-'));
    let (Some(dir), Some(path)) = (nonflag.next(), nonflag.next()) else {
        eprintln!("a64x cache: expected <cache-dir> <program.exe>");
        return 2;
    };
    let dir = PathBuf::from(dir);
    let bytes = match load_exe(path) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let hash = fnv1a(&bytes);
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("a64x cache: cannot create `{}`: {e}", dir.display());
        return 2;
    }
    let cache_file = dir.join(format!("{hash:016x}.a64xc"));
    let mut guest = match mk_guest(&bytes, XlatConfig::default()) {
        Ok(g) => g,
        Err(c) => return c,
    };

    let warm = cache_file.exists();
    if warm {
        match fs::read(&cache_file) {
            Ok(raw) => match CodeCache::load(XlatConfig::default(), &raw, hash) {
                Ok(cache) => {
                    let n = cache.len();
                    guest.machine.cache = cache;
                    println!("warm start: loaded {n} translated blocks from {}", cache_file.display());
                }
                Err(e) => println!("cache rejected ({e}); running cold"),
            },
            Err(e) => {
                eprintln!("a64x cache: read `{}`: {e}", cache_file.display());
                return 2;
            }
        }
    }
    println!("running {}…", if warm { "(cached)" } else { "(fresh)" });

    let t0 = Instant::now();
    let modules = [guest.image.module.clone()];
    let run_cfg = a64x_rt::RunConfig {
        entry: guest.image.entry,
        cmdline: &[],
        image_base: guest.image.image_base,
        modules: &modules,
        trace: false,
    };
    let out = a64x_rt::dispatch::run_with(&mut guest.machine, &guest.api, &run_cfg);
    let wall = t0.elapsed();
    print_outcome(&out, wall);

    if !warm {
        let data = guest.machine.cache.save(hash);
        if let Err(e) = fs::write(&cache_file, &data) {
            eprintln!("a64x cache: write `{}`: {e}", cache_file.display());
            return 2;
        }
        println!("cached {} blocks ({} bytes) to {}", guest.machine.cache.len(), data.len(), cache_file.display());
        println!("note: `.a64xc` files are host-machine-code snapshots — same host + same build only.");
    }
    outcome_code(&out)
}

// -- demo --------------------------------------------------------------------

fn cmd_demo(args: &[String]) -> u8 {
    let trace = args.iter().any(|a| a == "--trace");
    let bench = args
        .iter()
        .position(|a| a == "--bench")
        .and_then(|i| args.get(i + 1))
        .and_then(|n| n.parse::<u64>().ok());

    let base = memory::DEFAULT_IMAGE_BASE;
    match bench {
        None => {
            println!("{BANNER}");
            let bytes = demo::build_demo_image(base);
            let mut g = Guest::load(&bytes, XlatConfig::default()).expect("synthesized demo image must load");
            let out = if trace { g.run_traced() } else { g.run() };
            println!("[guest exited: {:?}, code {}]", out.reason, out.exit_code);
            if out.reason == ExitReason::Exited { 0 } else { 1 }
        }
        Some(iters) => {
            println!("{BANNER}");
            println!("bench: {iters} iterations of a 4-insn ARM64 loop, translated once, run natively");
            let bytes = demo::build_bench_image(base, iters);
            let mut g = Guest::load(&bytes, XlatConfig::default()).expect("bench image must load");
            let t0 = Instant::now();
            let out = if trace { g.run_traced() } else { g.run() };
            let wall = t0.elapsed();
            let secs = wall.as_secs_f64();
            println!(
                "{} guest insns in {secs:.3}s — {:.1} M insn/s ({} blocks translated, {} bytes of host code)",
                out.insn_count,
                out.insn_count as f64 / secs / 1e6,
                out.blocks_translated,
                guest_machine_code_bytes(&g),
            );
            println!("(reason {:?}: SVC logged+skipped, then BRK halt — expected)", out.reason);
            if matches!(out.reason, ExitReason::Breakpoint | ExitReason::Exited) { 0 } else { 1 }
        }
    }
}

fn guest_machine_code_bytes(g: &Guest) -> u64 {
    g.machine.cache.stats.code_bytes
}

