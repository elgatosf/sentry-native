# Sample app for .NET Native Error Handling with Sentry
Relates to issue https://github.com/getsentry/sentry-dotnet/issues/3244

This sample is vendored into the local `sentry-native` workspace so it can be used directly against the WER backend implemented in this fork.

## Description
Currently it's not possible to catch native exceptions from .NET using Sentry, for example in case of access violations, stack overflow, fail-fast exceptions; or even any kind of C++/native exception because .NET adds its own vectored exception handler etc. This makes the usual Crashpad handler backend unsuitable.

Using WerRegisterRuntimeExceptionModule, a custom exception handler can be loaded by Windows Error Reporting, allowing to inspect any kind of unhandled exception, even fail-fast exceptions.

This can be used from a .NET app to make native exception handling work with Sentry.

## Local workspace usage

The sample now supports consuming native binaries directly from this repo instead of manually copying them into the .NET project.

Preferred flow from the `sentry-native` workspace root:

* Build the local WER runtime into a predictable folder by running:
	`pwsh ./examples/SentryDotNetNativeCrash/Prepare-LocalSentryNative.ps1 -Configuration Debug`
* Set a DSN for the current shell session:
	`set SENTRY_DSN=https://PUBLIC@o0.ingest.sentry.io/0`
	or in PowerShell:
	`$env:SENTRY_DSN = "https://PUBLIC@o0.ingest.sentry.io/0"`
* Open `examples/SentryDotNetNativeCrash/SentryDotNetNativeCrash.slnx` in Visual Studio.
* Build and run `SentryWinUI3NativeCrash`.

By default, the sample looks for `sentry.dll` and `sentry_wer_module.dll` in `build-dotnet-wer/<Configuration>`.
If you build `sentry-native` somewhere else, set `SENTRY_NATIVE_RUNTIME_DIR` to the directory that contains those binaries before building the .NET projects.

## Steps to reproduce
How to build the test .NET app that can upload a minidump on fail-fast exception to Sentry:

* Ensure Visual Studio has the WinUI 3 / Windows App SDK tooling installed.
* From the workspace root, run `pwsh ./examples/SentryDotNetNativeCrash/Prepare-LocalSentryNative.ps1 -Configuration Debug`.
* Set `SENTRY_DSN` in your shell environment.
* Launch `examples/SentryDotNetNativeCrash/SentryDotNetNativeCrash.slnx` in Visual Studio.
* Build the solution.
* Go to the output directory `examples/SentryDotNetNativeCrash/SentryWinUI3NativeCrash/bin/x64/Debug/net8.0-windows10.0.19041.0`.
* Upload all symbols from this directory to Sentry using `sentry-cli.exe`.
* Optional: start *Sysinternals DebugView* to inspect debug logs from the WER handler running inside `WerFault.exe`.
* Start `SentryWinUI3NativeCrash`.
* Click **Fail Fast** to trigger the WER crash path.
* Verify in `%LOCALAPPDATA%\SentryNative\SentryWinUI3NativeCrash\sentry-cache` that a `.dmp` file was created.
* Check on Sentry whether the minidump arrived.
* Optional: open the `.dmp` file in `WinDbg` and run `!analyze -v`.

## Known issues
Currently, Sentry is not able to symbolicate minidumps that contain .NET functions and methods in the stack. They will be simply displayed as `<unknown>`. The information is available in the dump file itself however, as WinDbg or Visual Studio are able to show all the .NET methods. Additional handling on Sentry backend side may be necessary.

Sentry stack trace:  

```
OS Version: Windows 10.0.26200 (6901)
Report Version: 104

Crashed Thread: 42708

Application Specific Information:
Fatal Error: unknown 0x80131623 / 0x7ff8932eba48

Thread 42708 Crashed:
0   coreclr.dll                     0x7ff8f2f64515      EEPolicy::HandleFatalError (eepolicy.cpp:777)
1   coreclr.dll                     0x7ff8f3094c2b      SystemNative::GenericFailFast (system.cpp:285)
2   coreclr.dll                     0x7ff8f3094771      SystemNative::FailFast (system.cpp:304)
3   <unknown>                       0x7ff8932eba48      <unknown>
4   <unknown>                       0x6d1037ec78        <unknown>
```


WinDbg stack trace:  

```
coreclr!EEPolicy::HandleFatalError+0x7d   
coreclr!SystemNative::GenericFailFast+0x2b0   
coreclr!SystemNative::FailFast+0x92   
SentryDotNetNativeCrash!SentryDotNetNativeCrash.Program.CrashInStack1+0x28   
SentryDotNetNativeCrash!SentryDotNetNativeCrash.Program.CrashInStack2+0x1e   
SentryDotNetNativeCrash!SentryDotNetNativeCrash.Program.CrashInStack3+0x1e   
SentryDotNetNativeCrash!SentryDotNetNativeCrash.Program.Main+0x2f7   
coreclr!CallDescrWorkerInternal+0x83   
coreclr!CallDescrWorkerWithHandler+0x55   
coreclr!MethodDescCallSite::CallTargetWorker+0x2a6   
coreclr!MethodDescCallSite::Call+0xb   
coreclr!RunMainInternal+0x11f   
coreclr!RunMain+0xe0   
coreclr!Assembly::ExecuteMainMethod+0x1ab   
coreclr!CorHost2::ExecuteAssembly+0x246   
coreclr!coreclr_execute_assembly+0xde   
hostpolicy!coreclr_t::execute_assembly+0x29   
hostpolicy!run_app_for_context+0x5ea   
hostpolicy!run_app+0x3c   
hostpolicy!corehost_main+0x171   
hostfxr!execute_app+0x2bb   
hostfxr!`anonymous namespace'::read_config_and_execute+0xac   
hostfxr!fx_muxer_t::handle_exec_host_command+0x1d6   
hostfxr!fx_muxer_t::execute+0x2ad   
hostfxr!hostfxr_main_startupinfo+0xa8   
SentryDotNetNativeCrash_exe!exe_start+0x7fc   
SentryDotNetNativeCrash_exe!wmain+0x156   
SentryDotNetNativeCrash_exe!invoke_main+0x22   
SentryDotNetNativeCrash_exe!__scrt_common_main_seh+0x10c   
kernel32!BaseThreadInitThunk+0x17   
ntdll!RtlUserThreadStart+0x2c   
```



