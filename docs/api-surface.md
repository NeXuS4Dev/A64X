# A64X host API surface

A64X does not emulate `kernel32.dll` or `ucrtbase.dll`. Every imported
function is bound to a **gateway address** (`GATEWAY_BASE + 16 * id`) when the
image is loaded. Calling it leaves translated code; the dispatcher invokes a
native Rust adapter that reads the guest's ARM64 registers (`x0..x7`,
`d0..d7` / `v0..v7`), does the Windows work on the host and writes the result
back to `x0` / `d0`.

## Name resolution

Imports are resolved with `ApiLayer::resolve(dll, name)`. The DLL name is
mapped to the host that implements it (`canonical_dll`):

| Imported as                                   | Hosted by       |
|-----------------------------------------------|-----------------|
| `api-ms-win-crt-private-*`, `vcruntime140*`   | `vcruntime140`  |
| `api-ms-win-crt-*`, `ucrtbase`, `msvcrt*`     | `ucrtbase`      |
| `api-ms-win-shell-*`, `shell32`               | `shell32`       |
| other `api-ms-win-*`, `ext-ms-win-*`, `kernel32`, `kernelbase`, `ntdll` | `kernel32` |

Names are matched case-insensitively. The loader reports every import that
does not resolve in one error message, so a missing name is never hidden.

`tests/manifest.rs` (in `a64x-rt`) imports the complete required list through
the real loader; it must bind with no error.

## Process model

* **Threads** are green threads (`sched.rs`). Each has its own `CpuState`,
  continuation frames, TLS and FLS slots and errno cell. The dispatcher
  preempts at translator round boundaries, and threads switch at blocking
  calls, sleeps, yields and thread exit. Blocking is a *retry*: a call that
  cannot finish parks the thread and re-runs the same adapter with its
  original arguments once a synchronization object changes or its deadline
  passes. When no thread can run and no deadline is pending, the process is
  terminated with a deadlock diagnostic.
* **Callbacks into guest code** (`_initterm`, `exit`/`atexit`, `abort`'s signal
  handler, `InitOnceExecuteOnce`, FLS destructors, SEH filters and `finally`
  blocks, `__setusermatherr` handlers, thread start routines) run through
  continuation frames (`cont.rs`). The adapter points the guest at the function
  with the return address set to the internal `__continue` gateway and
  returns; the frame records what to do with the result.
* **Heap**: a real first-fit allocator over the process heap range, with
  alignment, coalescing, in-place resize and validated `HeapFree`/`HeapSize`.
  `HeapCreate` heaps are carved from the VM arena.
* **Virtual memory**: `VirtualAlloc` reserve/commit/decommit/release,
  `VirtualProtect`, `VirtualQuery(Ex)` with per-region state, protection and
  allocation base; committed pages are zero-filled when they come from
  reserved memory.
* **Structured exceptions**: `RaiseException` and `RtlUnwindEx` run a
  two-phase walk over `.pdata`/`.xdata` unwind information (`unwind.rs`
  implements the ARM64 unwind codes, packed and full forms, including
  epilogues). `__C_specific_handler` (vcruntime140) runs scope tables with
  filters, `__except` unwinding and `__finally` blocks.

## Surface

### vcruntime140 (`api-ms-win-crt-private-l1-1-0`)

`__C_specific_handler`, `memchr`, `memcmp`, `memcpy`, `memmove`.

### ucrtbase (`api-ms-win-crt-*`, `msvcrt`)

* **stdio**: `__acrt_iob_func`, `__p__commode`, `__p__fmode`,
  `__stdio_common_vfprintf`, `__stdio_common_vfwprintf`,
  `__stdio_common_vsprintf`, `__stdio_common_vsnprintf_s`,
  `__stdio_common_vsscanf`, `_fileno`, `_fseeki64`, `_ftelli64`, `_setmode`,
  `_wfopen`, `_write`, `fclose`, `fflush`, `fgetc`/`getc`, `fgetwc`, `fgets`,
  `fopen`, `fprintf`, `fputc`, `fputs`, `fputwc`, `fread`, `fseek`, `ftell`,
  `feof`, `ferror`, `clearerr`, `rewind`, `fwrite`, `setbuf`, `setvbuf`,
  `ungetc`, `ungetwc`, `printf`, `sprintf`, `snprintf`, `_snprintf`,
  `wprintf`, `fwprintf`, `puts`, `putchar`, `getchar`.
* **runtime**: `_assert`, `__p___argc`, `__p___argv`, `__sys_nerr`,
  `__sys_errlist`, `_beginthreadex`, `_endthreadex`, `_cexit`,
  `_configure_narrow_argv`, `_initialize_narrow_environment`, `_crt_atexit`,
  `atexit`, `_errno`, `_exit`, `_fpreset`, `_initterm`, `_initterm_e`,
  `_set_app_type`, `_set_invalid_parameter_handler`, `abort`, `exit`,
  `signal`, `strerror`, `strerror_s`.
* **string**: `_isctype_l`, `_is{alnum,alpha,blank,cntrl,ctype,digit,graph,
  lower,print,punct,space,upper,xdigit}_l` (wide forms), `_strcoll_l`,
  `_strdup`, `_strxfrm_l`, `_tolower_l`, `_toupper_l`, `_tow{lower,upper}_l`,
  `_wcscoll_l`, `_wcsxfrm_l`, `isalnum`, `isalpha`, `isblank`, `iscntrl`,
  `isdigit`, `isgraph`, `islower`, `isprint`, `ispunct`, `isspace`,
  `isupper`, `isxdigit`, `tolower`, `toupper`, `mbrlen`, `memset`, `strcmp`,
  `_stricmp`, `_strnicmp`, `strlen`, `strnlen`, `strncmp`, `strcpy`,
  `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, `wcslen`,
  `wcsnlen`, `wcscmp`, `wcsncmp`, `_wcsicmp`, `wcscpy`, `wcsncpy`, `wcschr`,
  `_wcsdup`.
* **locale**: `___lc_codepage_func`, `___mb_cur_max_func`, `__pctype_func`,
  `_configthreadlocale`, `_create_locale`, `_free_locale`, `localeconv`,
  `setlocale`.
* **math**: `__setusermatherr`, `exp`, `log`, `log10`, `pow`, `sqrt`, `fabs`,
  `floor`, `ceil`.
* **heap**: `malloc`, `calloc`, `realloc`, `free`, `_aligned_malloc`,
  `_aligned_free`, `_msize`, `_set_new_mode`.
* **convert**: `strtol`, `strtoul`, `strtoll`, `strtoull`, `_strtoi64_l`,
  `_strtoui64_l`, `_strtod_l`, `strtod`, `strtof`, `atoi`, `atol`, `atoll`,
  `_atoi64`, `atof`, `wcstol`, `wcstoul`, `wcstoll`, `wcstoull`, `wcstod`,
  `mbrtowc`, `_mbtowc_l`, `mbsrtowcs`, `wcrtomb`, `wcrtomb_s`.
* **time**: `_strftime_l`.
* **environment**: `__p__environ`, `getenv`, `_putenv_s`.
* **utility**: `rand_s`.
* **filesystem**: `_lock_file`, `_unlock_file` (per-stream recursive locks,
  blocking across threads).

### kernel32.dll

* **process and modules**: `ExitProcess`, `TerminateProcess`,
  `GetCurrentProcess`, `GetCurrentProcessId`, `GetExitCodeProcess`,
  `GetLastError`, `SetLastError`, `GetCommandLineA/W`, `GetStartupInfoA/W`,
  `GetEnvironmentVariableA/W`, `SetEnvironmentVariableA/W`,
  `ExpandEnvironmentStringsA/W`, `GetEnvironmentStringsA/W`,
  `FreeEnvironmentStringsA/W`, `GetModuleHandleA/W`, `GetModuleFileNameA/W`,
  `LoadLibraryA/W`, `FreeLibrary`, `GetProcAddress` (main image exports and
  hosted DLL functions), `CloseHandle`, `DuplicateHandle`, `GetStdHandle`,
  `SetStdHandle`, `SetConsoleCtrlHandler`, `IsDebuggerPresent`,
  `OutputDebugStringA/W`, `DebugBreak`, `SetErrorMode`, `GetErrorMode`,
  `FlushInstructionCache`, `GetConsoleWindow`, `GetACP`, `GetOEMCP`,
  `IsValidCodePage`, `GetUserDefaultLCID`, `lstrlenA/W`.
* **files, directories, console**: `CreateFileA/W`, `ReadFile`, `WriteFile`,
  `ReadConsoleA/W`, `WriteConsoleA/W`, `GetFileSize`, `GetFileSizeEx`,
  `SetFilePointer`, `SetFilePointerEx`, `SetEndOfFile`, `FlushFileBuffers`,
  `GetFileType`, `GetFileTime`, `GetFileAttributesA/W`, `DeleteFileA/W`,
  `CreateDirectoryA/W`, `RemoveDirectoryA/W`, `Get/SetCurrentDirectoryA/W`,
  `GetFullPathNameA/W`, `GetTempPathA/W`, `MoveFileA/W`, `CopyFileA/W`,
  `FindFirstFileA/W`, `FindNextFileA/W`, `FindClose`, `GetConsoleMode`,
  `SetConsoleMode`, `GetConsoleCP`, `GetConsoleOutputCP`, `SetConsoleCP`,
  `SetConsoleOutputCP`.
* **memory**: `GetProcessHeap`, `HeapCreate`, `HeapDestroy`, `HeapAlloc`,
  `HeapFree`, `HeapReAlloc`, `HeapSize`, `HeapValidate`, `HeapCompact`,
  `HeapLock`, `HeapUnlock`, `VirtualAlloc`, `VirtualFree`, `VirtualProtect`,
  `VirtualQuery`, `VirtualQueryEx`, `IsBadReadPtr`, `IsBadWritePtr`,
  `CreateFileMappingA/W`, `OpenFileMappingA/W`, `MapViewOfFile`,
  `MapViewOfFileEx`, `UnmapViewOfFile`, `FlushViewOfFile`, `LocalAlloc`,
  `LocalFree`, `LocalReAlloc`, `LocalSize`, `LocalLock`, `LocalUnlock`,
  `GlobalAlloc`, `GlobalFree`, `GlobalReAlloc`, `GlobalSize`, `GlobalLock`,
  `GlobalUnlock`, `GetLargePageMinimum`.
* **synchronization and threads**: `WaitForSingleObject(Ex)`,
  `WaitForMultipleObjects(Ex)`, `SignalObjectAndWait`, `Sleep`, `SleepEx`,
  `SwitchToThread`, `CreateEventA/W`, `OpenEventA/W`, `SetEvent`,
  `ResetEvent`, `PulseEvent`, `CreateMutexA/W`, `OpenMutexA/W`,
  `ReleaseMutex`, `CreateSemaphoreA/W`, `OpenSemaphoreA/W`,
  `ReleaseSemaphore`, `InitializeCriticalSection(AndSpinCount)`,
  `EnterCriticalSection`, `TryEnterCriticalSection`,
  `LeaveCriticalSection`, `DeleteCriticalSection`,
  `SetCriticalSectionSpinCount`, `CreateThread`, `ExitThread`,
  `GetCurrentThread`, `GetCurrentThreadId`, `GetThreadId`, `SuspendThread`,
  `ResumeThread`, `TerminateThread`, `GetExitCodeThread`,
  `SetThreadPriority`, `GetThreadPriority`, `TlsAlloc`, `TlsFree`,
  `TlsGetValue`, `TlsSetValue`, `FlsAlloc`, `FlsFree`, `FlsGetValue`,
  `FlsSetValue`, `InitOnceInitialize`, `InitOnceBeginInitialize`,
  `InitOnceComplete`, `InitOnceExecuteOnce`, `InitializeSRWLock`,
  `Acquire/ReleaseSRWLockExclusive/Shared`,
  `TryAcquireSRWLockExclusive/Shared`, `InitializeConditionVariable`,
  `WakeConditionVariable`, `WakeAllConditionVariable`,
  `SleepConditionVariableCS/SRW`, `WaitOnAddress`, `WakeByAddressSingle/All`.
* **system information and time**: `GetSystemInfo`, `GetNativeSystemInfo`,
  `GetActiveProcessorCount`, `GetMaximumProcessorCount`,
  `GetProcessAffinityMask`, `GetTickCount`, `GetTickCount64`,
  `QueryPerformanceCounter`, `QueryPerformanceFrequency`,
  `GetSystemTimeAsFileTime`, `GetSystemTimePreciseAsFileTime`,
  `GetSystemTime`, `GetLocalTime`, `SystemTimeToFileTime`,
  `FileTimeToSystemTime`, `FileTimeToLocalFileTime`,
  `LocalFileTimeToFileTime`, `GetTimeZoneInformation`,
  `GetNumaHighestNodeNumber`, `GetNumaProcessorNode`,
  `GetCurrentProcessorNumber`, `GetLogicalProcessorInformation`,
  `FormatMessageA/W`.
* **structured exceptions**: `RtlCaptureContext`, `RtlLookupFunctionEntry`,
  `RtlVirtualUnwind`, `RtlRestoreContext`, `RtlUnwindEx`, `RaiseException`,
  `SetUnhandledExceptionFilter`, `UnhandledExceptionFilter`.

### shell32.dll

`CommandLineToArgvW` (Microsoft C runtime splitting rules).

## Deviations and limits

These are the places where the behaviour is not the full Windows behaviour.
Each is intentional and visible in the code.

* **Import manifest.** The required list was reconstructed from the request
  notes; the verbatim list was not available. Any name missing from the
  manifest is not guaranteed; the loader error names every unresolved import.
* **Protection is not enforced.** `VirtualProtect` and `VirtualQuery` report
  protection exactly, but translated loads and stores do not fault on
  protection violations. All committed memory is readable and writable.
* **Reserve/commit are bookkeeping.** The whole guest space is one flat host
  mapping, so reserved memory is physically present. Commit zero-fills pages
  that were reserved; reads of reserved memory are not faulted.
* **File mappings** are copies. Each mapping object owns one block; views of
  the same object return the same block. File-backed writes are written back
  on `UnmapViewOfFile` and `FlushViewOfFile`, not on every store.
* **`setvbuf`/`setbuf`** change buffering mode; the user-supplied buffer is
  not used (the runtime's own 4 KiB buffers are).
* **Locale** is the `C` locale only. `setlocale` returns `NULL` for any other
  name; `_create_locale` fails for other names. Classification is ASCII only;
  wide classification uses Unicode properties.
* **Message table** (`FormatMessage`) covers a set of common system errors;
  other codes return 0 with `ERROR_MR_MID_NOT_FOUND`, as Windows does for a
  missing message.
* **Console**: output is written with LF line endings (no CRLF translation in
  `WriteFile`/`WriteConsole`); `CONIN$`/`CONOUT$` are the process's stdin/out.
  Control handlers are recorded but no Ctrl+C events are generated.
* **Environment** is a snapshot of the host environment at process start.
* **Time zone**: local time equals UTC; `%z`/`%Z` in `strftime` print
  `+0000`/`UTC`; `GetTimeZoneInformation` reports `TIME_ZONE_ID_UNKNOWN`.
* **Processors and NUMA**: one NUMA node; `GetCurrentProcessorNumber` returns
  0; `GetLogicalProcessorInformation` reports one core per logical processor
  (no cache topology).
* **`PulseEvent`** releases the threads waiting at that moment and leaves the
  event non-signaled; with auto-reset events, every waiter present is released
  (Windows releases one).
* **Unwinding across callbacks**: unwinding stops at the edge of translated
  code. An exception raised inside a callback that a Win32 adapter started
  (for example a filter run by `__C_specific_handler`) is searched through the
  continuation frames, but frames beyond the callback's start are not
  unwound through the native caller.
* **Duplicating handles** shares the object (both handles refer to one
  kernel object), so closing one handle does not invalidate the other.
* **`_set_new_mode`** records the mode; the runtime does not call a new-handler
  on allocation failure.
* **`%n`** in printf is rejected (EINVAL), the UCRT default.
* **strtod/strtol range**: `strtol` family clamps to the 32-bit `long` range
  (`ERANGE` on clamp); `strtod` reports `ERANGE` on overflow and on underflow to
  zero.
* **Constants not verified against an official header**: the values of
  `_ENABLE_PER_THREAD_LOCALE` (1) and `_DISABLE_PER_THREAD_LOCALE` (2) are used
  with the documented semantics (0 queries the current status).
* **Entry return**: returning from the entry point ends the process with
  `eax` as the exit code, as for an `ExitProcess` call.

## Testing

* Unit tests in `a64x-api` cover the heap, VM map, unwinder, format and scan
  engines, conversions, locale, math error classification, command-line
  splitting, file paths, FILETIME conversions, critical sections, events,
  mutexes and blocked-call retry.
* `a64x-rt/tests/manifest.rs` binds the whole import manifest through the loader.
* `a64x-rt/tests/e2e.rs` runs ARM64 programs through the translator: a created
  thread runs and the main thread's wait returns `WAIT_OBJECT_0`; `exit` runs
  its `atexit` handler before terminating; an unhandled `RaiseException`
  terminates with the exception code; the unhandled-exception filter runs as a
  callback before that termination.
* **Not covered end to end**: a scope-table handler (`__C_specific_handler`
  with `__except` filters and `__finally` blocks) runs its scope walk only in
  real MSVC-built binaries. The image builder in `a64x-pe` writes 12-byte
  `.pdata` entries (the x64 layout); ARM64 uses 8-byte entries, so a test image
  with an ARM64 exception table needs a builder change first. The unwinder that
  these handlers rely on is covered by unit tests (packed and full `.xdata`).
