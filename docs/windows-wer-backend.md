# Windows WER Backend

> **Status:** not yet merged upstream. The current fork is a temporary bridge. Treat the first merge as experimental.

This document explains why a dedicated WER backend is needed for .NET apps on Windows, why `crashpad` is not sufficient, what the new backend does, and which limitations remain.

## Problem

WinUI 3 C# apps typically only use `sentry-dotnet` and miss native crash reporting entirely. Most apps don't notice — until they hit WinUI / WinRT stowed exceptions, or start calling into native libraries via P/Invoke. Even when `sentry-native` is added, the default `crashpad` backend has specific gaps for C# apps (detailed below).

| Exception                            | Why it is missed                                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| Access violation `0xC0000005`        | CoreCLR treats it as a corrupted-state exception; `SetUnhandledExceptionFilter` is not reliably called |
| Stack overflow `0xC00000FD`          | Same CoreCLR interception                                                                              |
| `Environment.FailFast`, `abort()`    | Process fast-exits before app-local handlers run                                                       |
| WinUI stowed exceptions `0xC000027B` | Raised through the WinRT stowed-exception path, not the normal SEH path                                |

This also affects **pure C# JIT apps** using P/Invoke — CoreCLR intercepts corrupted-state exceptions before the usual native handler. The older [sentry-dotnet-minidump](https://github.com/getsentry/sentry-dotnet-minidump/issues/1#issue-782438188) project covered this but was deprecated once AOT improved; the JIT gap remains.

Two additional caveats in mixed C# / C++ apps:
- Native C++ exceptions (`std::invalid_argument` etc.) become `SEHException` in C#, losing the original callstack. Let them crash so a dump is created.
- WinUI can silently swallow some non-fatal failures on the main UI thread. Run native code on a separate thread.

Tracking issue: [getsentry/sentry-dotnet#3244](https://github.com/getsentry/sentry-dotnet/issues/3244)

## Why Crashpad Is Not Enough

### 1. Wrong crash-entry model / exception filter gap

Crashpad uses `SetUnhandledExceptionFilter` + an external handler process. CoreCLR intercepts access violations and stack overflows *before* that filter, so Crashpad's main path never sees them.

Crashpad also registers `crashpad_wer.dll` as a WER last-resort, but its exception filter only covers `FAIL_FAST` and `STACK_BUFFER_OVERRUN`. `STATUS_ACCESS_VIOLATION (0xC0000005)` and `STATUS_STACK_OVERFLOW (0xC00000FD)` [are explicitly excluded](https://github.com/chromium/crashpad/blob/cca548be8467ce9d6e854467b366ad3a00c487ee/handler/win/wer/crashpad_wer_main.cc#L39-L42) — correct for pure native apps where Crashpad handles those normally, wrong for C# apps where it does not.

**Widening that filter** (removing the two exclusions) is a valid short-term workaround to close the immediate exception-capture gap. It does not solve the points below.

### 2. Crashpad consumes the WER slot

Once `crashpad_wer.dll` is registered, Windows routes the WER callback to it. Crashpad then [claims the exception and terminates the crashing process](https://github.com/chromium/crashpad/blob/cca548be8467ce9d6e854467b366ad3a00c487ee/handler/win/wer/crashpad_wer_main.cc#L53), causing WER to no longer be able to create a dump itself or document an event for Windows Event Viewer or Windows telemetry.

### 3. Poor managed-frame visibility in dumps

Crashpad-produced minidumps do not reliably yield .NET frame names in Sentry for CoreCLR crashes. The same dump opened in WinDbg or Visual Studio shows managed frames when written via `MiniDumpWriteDump` on the Windows path. ([getsentry/symbolicator#1731](https://github.com/getsentry/symbolicator/issues/1731))

Note: this is partly a server-side symbolication gap (Portable PDB support for native minidumps); better dump creation helps but does not fully solve it.

### 4. MSIX deployment problems

For packaged WinUI 3 apps, two registry/filesystem virtualization issues require explicit workarounds:

1. **Registry virtualization:** Writing `RuntimeExceptionHelperModules` from inside MSIX is virtualized into the package container; `WerFault.exe` reads the real registry. Workaround: invoke `reg.exe` as an external process. (`desktop7:RuntimeExceptionHelperModule` in the manifest does not work — [MicrosoftDocs/winrt-related#394](https://github.com/MicrosoftDocs/winrt-related/issues/394).)
2. **DLL identity:** `WerFault.exe` runs without the app's MSIX package identity and cannot execute the DLL from the package path. Workaround: copy the DLL to a normal writable location and register that path.

### 5. Stowed exceptions

WinUI / WinRT failures surface as stowed exceptions (`0xC000027B`). Crashpad does not handle these. The WER backend preserves the stowed-exception stack in the dump, and as a text sidecar attachment.

### Summary: patching `crashpad_wer.dll` vs. a dedicated backend

Widening Crashpad's WER filter closes the exception-capture gap but still leaves: poor managed-frame dump quality, WER-as-last-resort instead of primary backend, MSIX workarounds, stowed-exception handling, and staged-state / recovery design.

## What The WER Backend Does

The intended setup: `sentry-dotnet` for managed telemetry, `sentry-native --backend=wer` for fatal native crashes.

**At startup**, the backend:
1. Prepares the SDK run directory, crash marker, and staged state (DSN, breadcrumbs, event seed, attachment metadata).
2. Registers `sentry_wer_module.dll` via `WerRegisterRuntimeExceptionModule`.
3. For MSIX: writes the registry entry via `reg.exe`, copies the DLL to a writable non-package path, and registers that path.

**On crash**, Windows launches `WerFault.exe`, which loads `sentry_wer_module.dll`. The module:
1. Reads the staged runtime context from the crashed process via `ReadProcessMemory`.
2. Reads staged event/breadcrumb data from disk.
3. Writes a minidump with `MiniDumpWriteDump`.
4. Writes a stowed-exception stack text sidecar for `0xC000027B` crashes.
5. Uploads immediately via WinHTTP.

**On next startup**, if upload failed: staged artifacts are replayed through the existing old-run envelope path.

---

## Known Limitations

| Area                                                 | First-merge expectation   | Why                                                                 | Follow-up                                                                                       |
| ---------------------------------------------------- | ------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `before_send`, `on_crash`, `before_screenshot` hooks | Not invoked               | Module runs in `WerFault.exe`, not the crashing app                 | Needs explicit bridge design; out of scope for first merge                                      |
| Breadcrumb / scope freshness                         | Staged state only         | WER module can only read what was persisted before the crash        | File-backed staging; shared memory is potential future work                                     |
| Attachments                                          | Must be explicitly staged | In-process state not available after crash                          | Explicit staging + integration tests                                                            |
| Stowed exceptions                                    | Text sidecar attachment   | No server-side stowed payload processing yet                        | Drop sidecar once server-side support exists                                                    |
| Consent, proxy, retry parity                         | Partial                   | Fork duplicates some WinHTTP transport behavior                     | Refactor onto shared upstream transport layer                                                   |
| Server-side .NET symbolication                       | Out of scope              | WER improves dump creation; does not fix server-side PDB resolution | Track in [getsentry/sentry-dotnet#2076](https://github.com/getsentry/sentry-dotnet/issues/2076) |

---

## Key Files

| File                                  | Role                                                                                                                                                                                                                                                                                    |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/backends/sentry_backend_wer.cpp` | Backend entry point. Runs in the app process: stages the runtime context and crash artifacts to disk, registers `sentry_wer_module.dll` via `WerRegisterRuntimeExceptionModule`, and handles recovery of staged runs on the next startup.                                               |
| `src/wer/sentry_wer_module.cpp`       | The DLL loaded by `WerFault.exe` at crash time. Has no dependency on the main SDK — it links the C++ runtime statically and uses only Win32 APIs and WinHTTP directly. Reads staged state from the crashed process via `ReadProcessMemory`, writes a minidump, and uploads immediately. |
| `src/wer/sentry_wer_common.h`         | Shared definitions: the versioned `sentry_wer_runtime_context` struct and crash-artifact filename aliases.                                                                                                                                                                              |
| `src/wer/sentry_wer_stowed.{h,cpp}`   | Stowed-exception (`0xC000027B`) parser: reads the WinRT stowed-exception blob from the crashing process and writes a text stack sidecar, plus collects the relevant memory ranges for the minidump.                                                                                     |
| `src/wer/sentry_wer_long_path.h`      | Long-path helpers for the WER module (extended-length `\\?\` prefix). The WER module cannot use `sentry__path_*`.                                                                                                                                                                       |
| `src/wer/sentry_wer_winhttp.{h,c}`    | Minimal WinHTTP wrapper used by the WER module to upload the crash envelope without depending on the main transport layer.                                                                                                                                                              |
| `src/sentry_crash_artifacts.h`        | Canonical crash-artifact filenames shared across backends.                                                                                                                                                                                                                              |

---

## Architecture Notes

**Why keep separate from `native` for now:** The `native` backend starts from an app-local handler + IPC daemon. The WER backend starts from `WerFault.exe`. They share `MiniDumpWriteDump` but not the crash-entry model or the ability to run app callbacks. Merging them now adds coupling without removing the real boundary.

**Long-term direction:** A hybrid model where the normal out-of-process handler owns the common path and the WER module is a true fallback for crashes only WER can catch, with both paths converging on the same durable envelope format.

**Low-churn sharing targets** (extract without modifying existing backends):
- Crash artifact name constants (`__sentry-event`, `last_crash`, etc.)
- Windows `MiniDumpWriteDump` helper layer
- Attachment metadata helpers
- Envelope item writers
- Durable recovery / old-run replay path

Keep backend-specific for now: WER registration/deployment, `WerFault.exe` callback, `native` daemon lifecycle, any app-local callback logic.

---

## First Merge Scope

In scope:
- Register WER module with versioned runtime context
- Capture access violation, fail-fast, stack overflow, and stowed-exception crash classes
- Reuse run-folder, crash-marker, and WinHTTP behavior
- Stage enough state for the WER module to build a crash report and recover on restart
- Document all unsupported behavior explicitly

Out of scope:
- Running user callbacks (`before_send`, `on_crash`) inside `WerFault.exe`
- Server-side .NET symbolication
- Full parity with all existing backends
