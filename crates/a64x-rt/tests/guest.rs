//! End-to-end runtime tests: full PE images built in-process, loaded,
//! translated and executed natively by this very machine.

use a64x_core::state::ExitReason;
use a64x_rt::{demo, Guest};
use a64x_xlat::XlatConfig;

const BASE: u64 = a64x_core::memory::DEFAULT_IMAGE_BASE;

/// The complete "hello world" demo ARM64 PE: puts + printf through real
/// Win32/CRT API adapters, then ExitProcess(7).
#[test]
fn demo_image_runs_to_completion() {
    let bytes = demo::build_demo_image(BASE);
    let mut g = Guest::load(&bytes, XlatConfig::default()).expect("load demo image");
    let out = g.run();
    assert!(out.message.is_none(), "unexpected message: {:?}", out.message);
    assert_eq!(out.reason, ExitReason::Exited, "outcome: {out:?}");
    assert_eq!(out.exit_code, 7);
    // puts + printf + ExitProcess
    assert_eq!(out.api_calls, 3, "outcome: {out:?}");
    assert!(out.insn_count > 10);
    assert!(out.blocks_translated >= 3, "entry block + branches: {out:?}");
}

/// The `--bench` image: a hot 4-insn loop, translated once and executed
/// natively the whole way. Retired-insn accounting must be exact.
#[test]
fn bench_image_retires_loop_insns_exactly() {
    let run = |iters: u64| {
        let bytes = demo::build_bench_image(BASE, iters);
        let mut g = Guest::load(&bytes, XlatConfig::default()).expect("load bench image");
        g.run()
    };
    let a = run(1_000_000);
    let b = run(2_000_000);
    // SVC gets logged+skipped, BRK ends the process cleanly.
    assert_eq!(a.reason, ExitReason::Breakpoint, "outcome a: {a:?}");
    assert_eq!(b.reason, ExitReason::Breakpoint, "outcome b: {b:?}");
    // The loop adds 4 instructions per iteration and nothing else scales.
    assert_eq!(b.insn_count - a.insn_count, 4 * (2_000_000 - 1_000_000), "a={a:?} b={b:?}");
    // Translated once (a handful of blocks), then pure native execution.
    assert!(a.blocks_translated < 64, "a={a:?}");
    // block_count is the *native* per-block-entry counter.
    assert_eq!(a.block_count, 1_000_002, "a={a:?}");
    // THE speed-pillar proof: 2 million loop iterations complete in a
    // handful of dispatcher rounds — chaining keeps control in native
    // code (a non-chaining JIT would take ~1M rounds here).
    assert!(b.rounds < 100, "too many dispatcher rounds: b={b:?}");
}

/// Reloading an image in a fresh guest works (loader is pure).
#[test]
fn loading_twice_is_independent() {
    let bytes = demo::build_demo_image(BASE);
    let mut g1 = Guest::load(&bytes, XlatConfig::default()).unwrap();
    let mut g2 = Guest::load(&bytes, XlatConfig::default()).unwrap();
    let o1 = g1.run();
    let o2 = g2.run();
    assert_eq!(o1.exit_code, o2.exit_code);
    assert_eq!(o1.reason, o2.reason);
}

/// A guest that jumps to an unmapped/out-of-bounds PECOFF text address
/// is reported, not a crash.
#[test]
fn bad_entry_is_reported_not_fatal() {
    let bytes = demo::build_demo_image(BASE);
    let mut g = Guest::load(&bytes, XlatConfig::default()).unwrap();
    let out = a64x_rt::dispatch::run(&mut g.machine, &g.api, 0xDEAD_0000, &[], BASE, false);
    assert_ne!(out.reason, ExitReason::Exited);
    assert!(out.message.is_some());
}
