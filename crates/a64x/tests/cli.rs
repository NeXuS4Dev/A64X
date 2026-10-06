//! CLI end-to-end: runs the actual `a64x` binary against real PE files.

use std::path::PathBuf;
use std::process::Command;

/// Unique temp path per call (tests run in parallel threads).
fn demo_exe() -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!("a64x_cli_demo_{}_{}.exe", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let bytes = a64x_rt::demo::build_demo_image(0x40_0000);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_a64x"))
        .args(args)
        .output()
        .expect("spawn a64x")
}

#[test]
fn info_prints_pe_facts() {
    let p = demo_exe();
    let out = run(&["info", p.to_str().unwrap()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("ARM64"), "{s}");
    assert!(s.contains(".text"), "{s}");
    assert!(s.contains("kernel32"), "{s}");
    assert!(s.contains("msvcrt"), "{s}");
    assert!(s.contains("puts"), "{s}");
}

#[test]
fn xlat_translates_entry_block() {
    let p = demo_exe();
    let out = run(&["xlat", "--disasm", p.to_str().unwrap()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("translated entry block"), "{s}");
    assert!(s.contains("block @0x"), "{s}");
    assert!(s.contains("LdStPair"), "{s}"); // disassembly shows decoded insns
}

#[test]
fn run_executes_guest_and_forwards_exit_code() {
    let p = demo_exe();
    let out = run(&["run", p.to_str().unwrap()]);
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("Hello from an ARM64 guest, running NATIVE on A64X"), "stdout={so}");
    assert!(so.contains("7 x 6 = 42"), "stdout={so}");
    // demo exits with code 7
    assert_eq!(out.status.code(), Some(7), "stderr={}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn run_rejects_junk_file() {
    let p = std::env::temp_dir().join(format!("a64x_junk_{}.bin", std::process::id()));
    std::fs::write(&p, b"not a pe").unwrap();
    let out = run(&["run", p.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to load image"));
}

#[test]
fn cache_round_trip_cold_then_warm() {
    let p = demo_exe();
    let dir = std::env::temp_dir().join(format!("a64x_cli_cache_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let d = dir.to_str().unwrap().to_string();
    let exe = p.to_str().unwrap().to_string();

    let out = run(&["cache", &d, &exe]);
    assert_eq!(out.status.code(), Some(7), "cold: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("cached"), "cold run must write the cache");

    let out = run(&["cache", &d, &exe]);
    assert_eq!(out.status.code(), Some(7), "warm: {}", String::from_utf8_lossy(&out.stderr));
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("warm start"), "second run must hit the cache: {so}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn demo_subcommand_runs_builtin_guest() {
    let out = run(&["demo"]);
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Hello from an ARM64 guest, running NATIVE on A64X"), "{s}");
}

#[test]
fn demo_bench_reports_speed() {
    let out = run(&["demo", "--bench", "1000000"]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("M insn/s"), "{s}");
}
