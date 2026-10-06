# A64X host API surface

Adapters are registered in `a64x_api::ApiLayer` under
`"dllname!FunctionName"` and bound to gateway stubs `GATEWAY_BASE + 16*id`
at load time. Guest ABI: args in `x0..x7`, result in `x0`. Every adapter
receives `&mut ApiCtx` (CpuState + Memory + process context).

Design rule: **do real host work**. Output APIs write to the real
console, file APIs use real `std::fs`, memory APIs manage guest memory.

## kernel32.dll (selection)

Process / environment:
`ExitProcess`, `GetCommandLineA/W`, `GetLastError`, `SetLastError`,
`GetCurrentProcessId`, `GetCurrentThreadId`, `GetTickCount(64)`,
`QueryPerformanceCounter/Frequency`, `GetSystemInfo`,
`IsProcessorFeaturePresent`, `GetVersionExW`.

Console / stdio:
`GetStdHandle`, `WriteConsoleA/W`, `ReadConsoleA`, `SetConsoleMode`,
`GetConsoleMode`, `WriteFile`, `ReadFile`,
`FlushFileBuffers`, `SetEndOfFile`.

Files (real `std::fs`, handles ≥ 0x30):
`CreateFileA/W` (`GENERIC_READ/WRITE`, `CREATE_ALWAYS/OPEN_EXISTING/
OPEN_ALWAYS/CREATE_NEW/TRUNCATE_EXISTING`),
`CloseHandle`, `GetFileSize(Ex)`, `SetFilePointer(Ex)`, `DeleteFileA/W`,
`CreateDirectoryA/W`, `GetFileAttributesA/W`, `MoveFileA/W`,
`GetFullPathNameA/W`, `GetTempPathA/W`, `FindFirstFile*`/minimal.

Memory (bump-allocated guest heap at `HEAP_BASE`, 64-byte aligned):
`GetProcessHeap`, `HeapCreate`, `HeapAlloc`, `HeapReAlloc`, `HeapFree`,
`HeapSize`, `HeapDestroy`, `LocalAlloc/Free`, `GlobalAlloc/Free`,
`VirtualAlloc/VirtualFree` (anonymous-style commits inside guest space),
`RtlZeroMemory`, `RtlMoveMemory`, `RtlFillMemory`.

TLS (128 slots out of a 256-slot TIB-equivalent block in `CpuState.aux`):
`TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, `FlsAlloc`,
`FlsGetValue`, `FlsSetValue`, `FlsFree`.

Strings / CRT-bridge used by loader (`IsDebuggerPresent` etc.):
`IsDebuggerPresent`, `GetStartupInfoA/W` (zeroed STARTUPINFO),
`GetCurrentDirectoryA/W`, `Sleep`, `DebugBreak`.

## msvcrt.dll / CRT (selection with real semantics)

`printf`, `puts`, `putchar`, `vprintf`-style varargs marshaling
(`%d %i %u %x %o %s %c %p %f %lld %llu %llx`, width/precision as far as
common console use needs), `sprintf`, `snprintf`, `fprintf(stderr…`,
`fwrite(stdout…`, `fflush`, `fputs`, `fputc`.

Memory: `malloc`, `calloc`, `realloc`, `free`, `memset`, `memcpy`,
`memmove`, `memcmp`.

Strings: `strlen`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strcmp`,
`strncmp`, `stricmp/_stricmp`, `strchr`, `strrchr`, `strstr`, `strdup`,
`toupper`, `tolower`.

Conversions: `atoi`, `atol`, `atof` (best-effort), `abs`, `labs`.

## Adding an adapter

```rust
api.register("kernel32.dll", "MyFunction", |ctx: &mut ApiCtx| {
    let arg = ctx.state.x[0];
    // do real work, using ctx.mem for guest pointers
    ctx.state.x[0] = result;
    Ok(())
});
```

The loader binds any import with a registered name automatically; an
unbound import terminates the run with a clear
`unbound import dll!Name` error instead of a crash.
