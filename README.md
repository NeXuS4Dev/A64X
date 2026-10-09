# A64X — ARM64-on-x86-64 Windows compatibility layer

**A64X** runs Windows **ARM64 (PE32+ / machine `0xAA64`)** software natively
on **x86-64** machines. It follows the Rosetta 2 / box64 model:

1. **Not an emulator.** Guest ARM64 basic blocks are **translated to native
   x86-64 machine code** and executed directly on the host CPU. There is no
   interpretive dispatch loop — the execution engine translates once per
   block and never looks at the guest instruction again.
2. **API translation, not DLL emulation.** When guest code calls a Win32 /
   CRT API (`kernel32!WriteFile`, `msvcrt!printf`, …) the call is routed
   through an **API gateway** to a *native adapter* — an `extern "C"`
   implementation that marshals arguments and does real host work
   (console output, `std::fs` file I/O, heap, TLS, command line, …).
3. **Native conversion, cached.** Translated blocks live in a code cache,
   are **chained together directly** (a hot loop stays in pure native code
   with zero dispatcher involvement), and can be **persisted to disk**
   (`.a64xc`) and reloaded for instant warm starts.
4. **Speed.** One flag-forwarding translation scheme keeps host EFLAGS
   live across translated ALU operations; per-iteration cost of a hot
   loop is a handful of native instructions; block exits patch themselves
   into direct native jumps once their targets exist.

```
$ cargo run -p a64x -- demo
Hello from an ARM64 guest, running NATIVE on A64X
printf through the API adapter works: 7 x 6 = 42, and 1+2+...+10 = 55
[guest exited with code 7]

$ cargo run -p a64x -- demo --bench 50000000
1,018,232,914 guest insn/s  (197,856,456 guest insn, 4 blocks translated)
```

## Crates

| Crate         | Role |
|---------------|------|
| `a64x-core`   | CpuState, guest memory, host RWX exec memory, exit reasons |
| `a64x-pe`     | PE32+ parser + PE image builder (used to synthesize test/demo images) |
| `a64x-arm64`  | ARM64 decoder + assembler subset (bitmask-immediate logic, branches, ld/st) |
| `a64x-x64`    | x86-64 machine-code emitter |
| `a64x-xlat`   | **Block translator, code cache (chaining, disk persistence), Machine** |
| `a64x-api`    | API gateway + registry; process model (green threads, heaps, VM map, handles, continuations, SEH unwinding); portable `kernel32`, `ucrtbase`, `vcruntime140`, `shell32` adapters |
| `a64x-rt`     | PE loader (relocations, import binding), dispatcher, demo images, `Guest` |
| `a64x`        | Command-line frontend |

## Using it

```console
a64x info  <program.exe>            # PE headers, sections, imports
a64x xlat  <program.exe> [--disasm] # translate the entry block, dump it
a64x run   <program.exe> [--fast] [--trace] [-- args...]
a64x cache <dir> <program.exe>      # persistent code cache (.a64xc)
a64x demo  [--bench N] [--trace]    # built-in ARM64 demo (needs no guest binary)
```

`--fast` disables per-access bounds checks (out-of-bounds accesses wrap
inside the guest address space); `--trace` prints a line per dispatcher
round.

## Design in one screen

- **Register mapping**: guest `x0..x30/sp/pc/NZCV` live in a `#[repr(C)]`
  `CpuState`; each translated block keeps `r15 = &CpuState` and
  `r14 = guest_address_space_base` for the whole block.
- **Block ABI**: block entry decrements a chain budget and bumps the
  block counter inside native code. Every static-target exit is a 12-byte
  slot initially containing `ret`; once the target block exists the slot
  is patched to `movabs rax, entry; jmp rax` — self-links, pending links
  and disk-relinked links all work the same way, so steady-state hot
  loops never touch Rust.
- **Flags**: after a translated `add/sub` the host flags are trapped with
  `setcc` into the `NZCV` bytes; logical ops keep N/Z live from the host.
  ARM shifter-carry is captured right after the shift.
- **API gateway**: imports are bound to `GATEWAY_BASE + 16*id` stubs in an
  otherwise-unmapped region; a `blr` into it stops translation and is
  serviced by the dispatcher against the `ApiLayer` registry.
- **Faults**: checked mode emits `cmp r11, mem_size; jbe ok; <fault
  thunk>; ok:` per access — a faulting EA is reported with guest PC and
  address instead of segfaulting the host.

## Status & scope

- Integer ISA broadly covered: DP imm/reg (shifts, extends), logical with
  bitmask immediates, branches (all forms), cbz/tbz, ld/st every width
  (signed/unsigned, pre/post index, pairs), mul/div family, bitfield
  (SBFM/UBFM/BFM aliases incl. LSL/LSR/ASR extracts), CLZ/REV, CSEL.
- **Not yet in the translator**: FP/SIMD instructions, atomics/barriers,
  DllMain/TLS callbacks, `CCMP` — unknown opcodes exit cleanly with the raw
  word + address.
- The API layer implements structured exception dispatch and `.pdata`/`.xdata`
  unwinding, but guest exception code only runs once the translator covers
  the instructions it uses.
- The API surface is implemented natively against the adapter ABI (see
  `docs/api-surface.md` for the full list and the known deviations). The
  runtime does not load the real system DLLs; imports are bound by name.

## Testing

The test suite executes *actual translated x86-64 on the build machine*;
every translated behavior is verified by observing guest state after
native execution, including chained hot loops and cache round-trips:

```console
$ cargo test --workspace     # 109 tests: decoders, emitters, native exec, API adapters, unwinding, threads, end-to-end PE runs, CLI integration
```

## License

BSD 3-Clause (see `LICENSE`).
