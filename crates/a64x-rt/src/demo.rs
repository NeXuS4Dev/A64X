//! Built-in demo image: a real PE32+ ARM64 executable synthesized in
//! memory by [`a64x_pe::builder::ImageBuilder`]. It exercises the complete
//! pipeline end to end — PE load, import binding, binary translation,
//! native execution and Win32 adapter calls — with no third-party guest
//! binary required.

use a64x_arm64::asm::{self, Assembler};
use a64x_pe::builder::{ImageBuilder, SectionBuild};

/// Guest string area base RVA inside the demo image.
const STR_RVA: u32 = 0x2000;

/// Program layout helpers.
struct Strings {
    hello: u32,
    fmt: u32,
    name: u32,
}

fn strings_blob(image_base: u64) -> (Vec<u8>, Strings) {
    let s1 = b"Hello from an ARM64 guest, running NATIVE on A64X\0";
    let s2 = b"%s: 7 x 6 = %d, and 1+2+...+10 = %lld\n\0";
    let s3 = b"printf through the API adapter works\0";

    let mut blob = Vec::new();
    let hello = STR_RVA + blob.len() as u32;
    blob.extend_from_slice(s1);
    let fmt = STR_RVA + blob.len() as u32;
    blob.extend_from_slice(s2);
    let name = STR_RVA + blob.len() as u32;
    blob.extend_from_slice(s3);
    let _ = image_base;
    (blob, Strings { hello, fmt, name })
}

/// Program generator: given final guest VAs, emit the demo code.
fn demo_code(image_base: u64, iat: &[(u64, &str)], text_rva: u64, ds: &Strings) -> Vec<u8> {
    let mut a = Assembler::new();
    let find = |name: &str| -> u64 { iat.iter().find(|(_, n)| *n == name).map(|(a, _)| *a).expect("iat slot") };

    // -- prologue: save LR, align stack
    a.w(asm::stp_pre(true, 29, 30, 31, -16)); // stp x29, x30, [sp, #-16]!
    a.w(asm::mov_reg(true, 29, 31)); // mov x29, sp

    // -- compute 7*6 and sum 1..10 with "real" guest work
    a.w(asm::movz(true, 20, 7, 0));
    a.w(asm::movz(true, 21, 6, 0));
    a.w(asm::mul(true, 22, 20, 21)); // x22 = 42
    a.w(asm::movz(true, 23, 0, 0)); // acc
    a.w(asm::movz(true, 24, 10, 0)); // i
    a.label("sum");
    a.w(asm::add_r(true, 23, 23, 24));
    a.w(asm::subs_imm1(24)); // subs i, i, #1
    a.b_cond(a64x_arm64::Cond::Ne, "sum");

    // -- puts(hello)
    a.ws(&asm::mov_imm64_fixed(0, image_base + ds.hello as u64));
    a.ws(&asm::mov_imm64_fixed(8, find("puts")));
    a.w(asm::ld_st_unsigned(8, a64x_arm64::LdStOp::LoadZ, 8, 8, 0)); // ldr x8, [x8]
    a.w(asm::branch_reg(1, 8)); // blr x8

    // -- printf(fmt, name, x22, x23)
    a.ws(&asm::mov_imm64_fixed(0, image_base + ds.fmt as u64));
    a.ws(&asm::mov_imm64_fixed(1, image_base + ds.name as u64));
    a.w(asm::mov_reg(true, 2, 22));
    a.w(asm::mov_reg(true, 3, 23));
    a.ws(&asm::mov_imm64_fixed(8, find("printf")));
    a.w(asm::ld_st_unsigned(8, a64x_arm64::LdStOp::LoadZ, 8, 8, 0));
    a.w(asm::branch_reg(1, 8)); // blr x8

    // -- ExitProcess(7)
    a.w(asm::movz(true, 0, 7, 0));
    a.ws(&asm::mov_imm64_fixed(8, find("ExitProcess")));
    a.w(asm::ld_st_unsigned(8, a64x_arm64::LdStOp::LoadZ, 8, 8, 0));
    a.w(asm::branch_reg(1, 8)); // blr x8

    // -- epilogue (unreached)
    a.w(asm::ldp_post(true, 29, 30, 31, 16));
    a.w(asm::ret());
    let _ = text_rva;
    a.finish()
}

/// The demo import list.
fn demo_imports(b: &mut ImageBuilder) {
    b.imports(&["kernel32.dll", "ExitProcess", "GetStdHandle", "WriteConsoleA"]);
    b.imports(&["msvcrt.dll", "puts", "printf"]);
}

/// One deterministic build pass (code bytes parameter).
fn build_pass(code: &[u8], blobs: &[(&str, &[u8])], image_base: u64) -> Vec<u8> {
    let mut b = ImageBuilder::default();
    b.image_base(image_base);
    let text = b.section(SectionBuild::text(code));
    for (name, data) in blobs {
        b.section(SectionBuild::data(name, data, false));
    }
    b.entry(text);
    demo_imports(&mut b);
    b.build().expect("demo image build")
}

/// Build the demo image at the given base.
///
/// The builder is deterministic, so we build once with placeholder code
/// to learn the assigned IAT RVAs (parsing the result with the PE reader
/// itself), then re-emit the code with real guest VAs and build the
/// final image.
pub fn build_demo_image(image_base: u64) -> Vec<u8> {
    let (blob, ds) = strings_blob(image_base);
    let dummy_iat: Vec<(u64, &str)> = ["ExitProcess", "GetStdHandle", "WriteConsoleA", "puts", "printf"]
        .iter()
        .map(|n| (image_base, *n))
        .collect();
    let code_placeholder = demo_code(image_base, &dummy_iat, 0x1000, &ds);
    let blobs: Vec<(&str, &[u8])> = vec![(".data", &blob)];
    let img1 = build_pass(&code_placeholder, &blobs, image_base);
    // recover the iat rvas via our own parser
    let pe1 = a64x_pe::PeImage::parse(&img1).expect("self-parse");
    let mut iat: Vec<(u64, &str)> = Vec::new();
    for imp in pe1.imports().expect("self-imports") {
        for n in ["ExitProcess", "GetStdHandle", "WriteConsoleA", "puts", "printf"] {
            if imp.symbol.to_string().eq_ignore_ascii_case(n) {
                iat.push((image_base + imp.iat_rva as u64, n));
            }
        }
    }
    let code = demo_code(image_base, &iat, 0x1000, &ds);
    debug_assert_eq!(code.len(), code_placeholder.len());
    build_pass(&code, &blobs, image_base)
}

/// A compute-only demo for `--bench`: no API calls, exits with SVC.
pub fn build_bench_image(image_base: u64, iterations: u64) -> Vec<u8> {
    let mut a = Assembler::new();
    a.w(asm::stp_pre(true, 29, 30, 31, -16));
    a.ws(&asm::mov_imm64_fixed(20, iterations));
    a.w(asm::movz(true, 21, 0, 0)); // acc
    a.label("loop");
    a.w(asm::add_r(true, 21, 21, 20));
    a.w(asm::add_r(true, 21, 21, 20));
    a.w(asm::add_imm(true, true, true, 20, 20, 1, false)); // subs i, i, #1
    a.b_cond(a64x_arm64::Cond::Ne, "loop");
    // keep result live so nothing is dead-code eliminated conceptually
    a.ws(&asm::mov_imm64_fixed(22, 0x2000));
    a.w(asm::ld_st_unsigned(8, a64x_arm64::LdStOp::Store, 21, 22, 0)); // str x21, [x22]
    a.w(asm::ldp_post(true, 29, 30, 31, 16));
    a.w(asm::svc(0)); // dispatcher logs + skips ...
    a.w(asm::brk(0)); // ... and lands here to stop the process
    let code = a.finish();

    let mut b = ImageBuilder::default();
    b.image_base(image_base);
    let text = b.section(SectionBuild::text(&code));
    b.section(SectionBuild::data(".data", &[0u8; 16], true));
    b.entry(text);
    b.build().expect("demo image build")
}
