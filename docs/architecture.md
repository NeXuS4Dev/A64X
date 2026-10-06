# A64X architecture

## Pipeline

```
ARM64 .exe ──► a64x-pe (parse) ──► a64x-rt loader ──► guest Memory
                                                           │
                  Win32 API surface                        ▼
        ┌──────── a64x-api gateway ◄──── blr GATEWAY ── a64x-xlat Machine
        │                  ▲                              │  translate blocks
        ▼                  │                              ▼
   native adapters ◄───────┘                      native x86-64 code cache
   (kernel32, msvcrt)                             (chained, persistable)
```

## Not an emulator

There is no fetch-decode-execute loop. `a64x_xlat::codegen::translate_block`
consumes one guest basic block (up to `MAX_BLOCK_INSNS = 64` insns or the
first control-flow terminator) and emits host x86-64 machine code into an
RWX `ExecBuffer`. Running guest code means running *translated* code.

The dispatcher (`a64x_rt::dispatch::run`) only regains control when:

1. the chain **budget** hits zero (per-block-entry decrement; one budget
   round covers ~4M block entries);
2. a block exits to a **not-yet-translated** target (12-byte exit slot in
   `ret` form);
3. the guest hits a gateway stub (Win32 API call), an `svc`/`brk`, an
   unimplemented opcode or a memory fault.

In steady state none of those happen inside hot loops once chain links
are patched.

## Block chaining

Every exit with a statically-known target is emitted as:

```
    mov  rax, target_guest_pc     # written to state.pc
    mov  [r15+pc], rax
    <12-byte slot>                # ret + 11 NOPs initially
```

`CodeCache::insert` scans the block's `links`; when the target block
exists (or later gets translated) the slot is atomically rewritten to
`movabs rax, entry; jmp rax`, so control never leaves native code. The
same mechanism re-links blocks after a disk-cache reload — the on-disk
format (`A64XC1…` magic + FNV-1a image hash, config tag) stores code
images and link tables, never host pointers.

## Flags

After a flag-setting ALU op the host flags are immediately captured with
`setcc` into the four `NZCV` bytes of `CpuState`:

- `ADDS`: `CF ← setc` (same sense as ARM carry);
- `SUBS`: `C ← setnc` (ARM carry = NOT borrow);
- logical (TST/ANDS/BICS): N/Z live from host, V=0, C from the shifter
  carry routine (captured into `r10` immediately after the shift, before
  the logical op disturbs EFLAGS).

Condition evaluation only touches `rax/rcx/rdx`; `CSEL` keeps operands in
`r8/r9`.

## Memory safety

`checked_mem` mode emits per access:

```
    cmp r11, [r15+mem_size]
    jbe ok
    <inline fault stub: reason=MemoryFault, aux1=EA, pc=insn; ret>
ok: mov rax, [r14+r11]
```

`--fast` replaces the check with `and r11, mem_size-1` (guest sizes are
powers of two; accesses wrap — UB from the guest's perspective but never
a host crash).

## API translation

Guest imports bind to `GATEWAY_BASE + 16*id`. `blr` there exits
translation; the dispatcher maps the stub address back to an adapter id
and invokes the Rust function with an `ApiCtx { state, mem, cmd_line,
image_base, api }`. Adapters model Win32 semantics portably:

- console via stdout/stderr handles,
- `CreateFile/ReadFile/WriteFile` with real `std::fs` handles,
- process heap bump allocator inside guest memory,
- command line, exit codes, GetLastError state in `CpuState`,
- CRT (`printf` with real varargs parsing, `malloc`, `strcmp`, …).

On Windows hosts the same registry binds the *real* DLL exports with the
same marshaling ABI (`WIN32` cfg paths in `a64x-api`).

## Instruction coverage (current)

- DP immediate/register (add/sub/logical, all shift+extend forms)
- movz/movn/movk, adrp/adr
- bitmask logic immediates (full 13-bit N/immr/imms decode)
- b/bl/b.cond/br/blr/ret, cbz/cbnz/tbz/tbnz
- ld/st: all widths (8/16/32/64), signed/zero extend, pre/post index,
  register offset, pairs (ldp/stp)
- mul/madd/msub/smulh/umulh, sdiv/udiv (ARM semantics: div-by-zero → 0)
- sbfm/ubfm/bfm (incl. lsl/lsr/asr/sxtb/sxth/sxtw/uxt* aliases), clz,
  rev/rev16/rev32, csel family
- svc, brk (both exit cleanly to the dispatcher)

Out of scope for v1: FP/SIMD, LDXR/STXR atomics, barriers, CCMP, SEH.

## Persistence format `.a64xc`

```
magic        "A64XC001" 8 bytes
image_hash   u64      (FNV-1a over the loaded guest image)
config_tag   u16      (checked_mem/count_stats/…)
n_blocks     u32
per block:   guest_pc u64, guest_len u32, n_insns u32,
             n_links u32, code_len u32,
             links[(code_off u32, target u64)],
             code[code_len]   (slots in ret-form)
```

Slots are stripped to `ret` form before save (machine addresses are not
portable across processes); on load every link is re-resolved against
the loaded block set, after which lookups hit the cache exactly like in
a live session.
