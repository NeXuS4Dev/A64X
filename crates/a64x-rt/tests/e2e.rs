//! End-to-end guest programs: ARM64 code running through the translator and
//! calling imported Win32/CRT APIs. Each image is linked in two passes so
//! the import slot addresses are known when the code is generated.

use a64x_arm64::asm;
use a64x_arm64::insn::LdStOp;
use a64x_core::ExitReason;
use a64x_pe::builder::{ImageBuilder, SectionBuild};
use a64x_pe::{ImportSymbol, PeImage};
use a64x_rt::Guest;
use a64x_xlat::XlatConfig;
use std::collections::HashMap;

const IMAGE_BASE: u64 = 0x40_0000;
/// Guest scratch memory outside the image, shared by the program's threads.
const SHARED: u64 = 0x20_0000;

/// Build the image: `code` receives the IAT slot address of each import and
/// the VA of the text section.
fn image(
    imports: &[(&str, &str)],
    code: &dyn Fn(&dyn Fn(&str) -> u64, u64) -> Vec<u32>,
) -> Vec<u8> {
    let link = |iat: &dyn Fn(&str) -> u64, text_va: u64| -> Vec<u8> {
        let mut b = ImageBuilder::default();
        b.image_base(IMAGE_BASE);
        let text = b.section(SectionBuild::text(&words(&code(iat, text_va))));
        b.entry(text);
        for &(dll, name) in imports {
            b.imports(&[dll, name]);
        }
        b.build().expect("image builds")
    };
    // pass 1: learn where the text and the import slots land
    let first = link(&|_: &str| 0u64, IMAGE_BASE + 0x1000);
    let pe = PeImage::parse(&first).expect("parse pass 1");
    let text_va = IMAGE_BASE + pe.section(".text").expect(".text").vaddr as u64;
    let slots: HashMap<String, u64> = pe
        .imports()
        .expect("imports")
        .iter()
        .filter_map(|i| match &i.symbol {
            ImportSymbol::Name(n) => Some((n.clone(), IMAGE_BASE + i.iat_rva as u64)),
            ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    // pass 2: the real code (same length: addresses are fixed-width moves)
    link(
        &|name| {
            *slots
                .get(name)
                .unwrap_or_else(|| panic!("no IAT slot for {name}"))
        },
        text_va,
    )
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// `ldr x8, [slot]; blr x8` for an imported function (arguments already set).
fn call_import(a: &mut Vec<u32>, slot: u64) {
    a.extend(asm::mov_imm64_fixed(8, slot));
    a.push(asm::ld_st_unsigned(8, LdStOp::LoadZ, 8, 8, 0));
    a.push(0xD63F_0100); // blr x8
}

/// Store the low 32 bits of `reg` at the shared scratch address.
fn store_shared_w(a: &mut Vec<u32>, reg: u8) {
    a.extend(asm::mov_imm64_fixed(9, SHARED));
    a.push(asm::ld_st_unsigned(4, LdStOp::Store, reg, 9, 0));
}

fn thread_program(iat: &dyn Fn(&str) -> u64, text_va: u64) -> Vec<u32> {
    // The worker follows main; its address is known once main's length is.
    let main_len = |worker: u64| main_code(iat, worker).len();
    let worker = text_va + 4 * main_len(0) as u64;
    let _ = text_va;
    let mut code = main_code(iat, worker);
    assert_eq!(main_len(worker), code.len(), "fixed-width layout");
    code.extend(worker_code());
    code
}

fn main_code(iat: &dyn Fn(&str) -> u64, worker: u64) -> Vec<u32> {
    let mut a = Vec::new();
    // CreateThread(NULL, 0, worker, 0x2A, 0, &tid)
    a.push(asm::movz(true, 0, 0, 0));
    a.push(asm::movz(true, 1, 0, 0));
    a.extend(asm::mov_imm64_fixed(2, worker));
    a.push(asm::movz(true, 3, 0x2A, 0));
    a.push(asm::movz(true, 4, 0, 0));
    a.extend(asm::mov_imm64_fixed(5, SHARED + 8));
    call_import(&mut a, iat("CreateThread"));
    a.push(asm::mov_reg(true, 19, 0)); // keep the thread handle
                                       // WaitForSingleObject(handle, INFINITE)
    a.push(asm::mov_reg(true, 0, 19));
    a.extend(asm::mov_imm32(1, 0xFFFF_FFFF));
    call_import(&mut a, iat("WaitForSingleObject"));
    // record the wait result (WAIT_OBJECT_0 expected) at SHARED + 16
    a.extend(asm::mov_imm64_fixed(9, SHARED + 16));
    a.push(asm::ld_st_unsigned(4, LdStOp::Store, 0, 9, 0));
    // ExitProcess(value the worker stored)
    a.extend(asm::mov_imm64_fixed(9, SHARED));
    a.push(asm::ld_st_unsigned(4, LdStOp::LoadZ, 0, 9, 0));
    call_import(&mut a, iat("ExitProcess"));
    a
}

fn worker_code() -> Vec<u32> {
    let mut a = Vec::new();
    a.push(asm::add(true, 0, 0, 1)); // x0 = parameter + 1
    store_shared_w(&mut a, 0);
    a.push(asm::ret());
    a
}

#[test]
fn created_thread_runs_and_main_waits_for_it() {
    let imports = [
        ("kernel32.dll", "CreateThread"),
        ("kernel32.dll", "WaitForSingleObject"),
        ("kernel32.dll", "ExitProcess"),
    ];
    let bytes = image(&imports, &thread_program);
    let mut g = Guest::load(&bytes, XlatConfig::default()).expect("load");
    let out = g.run();
    assert!(out.message.is_none(), "message: {:?}", out.message);
    assert_eq!(out.reason, ExitReason::Exited, "{out:?}");
    assert_eq!(
        out.exit_code, 0x2B,
        "worker stored 0x2A + 1 and main exited with it"
    );
    assert_eq!(g.machine.mem.read_int(SHARED, 4).unwrap(), 0x2B);
    assert_eq!(g.machine.mem.read_int(SHARED + 16, 4).unwrap(), 0, "WAIT_OBJECT_0 after the retry");
    assert!(
        out.api_calls >= 4,
        "CreateThread, WaitForSingleObject (retried), worker return, ExitProcess"
    );
}

fn atexit_program(iat: &dyn Fn(&str) -> u64, text_va: u64) -> Vec<u32> {
    let handler_va = text_va + 4 * exit_main_len(iat, 0) as u64;
    let mut a = exit_main(iat, handler_va);
    // handler: store 0x77 at SHARED, then return to the exit sequence
    a.extend(asm::mov_imm64_fixed(9, SHARED));
    a.push(asm::movz(true, 0, 0x77, 0));
    a.push(asm::ld_st_unsigned(4, LdStOp::Store, 0, 9, 0));
    a.push(asm::ret());
    a
}

fn exit_main_len(iat: &dyn Fn(&str) -> u64, handler: u64) -> usize {
    exit_main(iat, handler).len()
}

fn exit_main(iat: &dyn Fn(&str) -> u64, handler: u64) -> Vec<u32> {
    let mut a = Vec::new();
    // atexit(handler)
    a.extend(asm::mov_imm64_fixed(0, handler));
    call_import(&mut a, iat("atexit"));
    // exit(5): runs the atexit handler through a callback frame, then ends
    a.push(asm::movz(true, 0, 5, 0));
    call_import(&mut a, iat("exit"));
    a
}

#[test]
fn exit_runs_atexit_handlers_before_terminating() {
    let imports = [
        ("api-ms-win-crt-runtime-l1-1-0.dll", "atexit"),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "exit"),
    ];
    let bytes = image(&imports, &atexit_program);
    let mut g = Guest::load(&bytes, XlatConfig::default()).expect("load");
    let out = g.run();
    assert!(out.message.is_none(), "message: {:?}", out.message);
    assert_eq!(out.reason, ExitReason::Exited, "{out:?}");
    assert_eq!(out.exit_code, 5);
    assert_eq!(
        g.machine.mem.read_int(SHARED, 4).unwrap(),
        0x77,
        "handler ran before termination"
    );
}
