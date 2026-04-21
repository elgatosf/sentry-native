using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.Storage;

namespace SentryDotNetCommon
{
    public partial class SentryNative
    {
        public static bool InitializeForDotNet(string cacheFolder, string? release = null, string? environment = null, bool debug = true)
        {
            var sentryDsn = Environment.GetEnvironmentVariable("SENTRY_DSN");
            if (string.IsNullOrEmpty(sentryDsn))
            {
                Debug.WriteLine("[Sentry] Please set the SENTRY_DSN environment variable before running.");
                return false;
            }

            // .NET registers its custom exception module first and takes precedence
            // https://github.com/dotnet/runtime/blob/82ce59a6f6d415a3df5edd94b7917ab7d13a7b0c/src/coreclr/vm/dwreport.cpp#L112
            // Therefore unregister it so our handler is called
            var runtimeDirectory = RuntimeEnvironment.GetRuntimeDirectory();
            var dotNetExceptionModule = System.IO.Path.Combine(runtimeDirectory, "mscordaccore.dll");
            var clrModuleBase = GetModuleHandleW("coreclr.dll");

            if (clrModuleBase != IntPtr.Zero)
            {
                WerUnregisterRuntimeExceptionModule(dotNetExceptionModule, clrModuleBase);
            }

            var cacheDirectory = System.IO.Path.Combine(cacheFolder, "sentry-cache");
            System.IO.Directory.CreateDirectory(cacheDirectory);

            var handlerPath = System.IO.Path.Combine(AppContext.BaseDirectory, "sentry_wer_module.dll");
            if (!System.IO.File.Exists(handlerPath))
            {
                Debug.WriteLine($"[Sentry] Could not find sentry_wer_module.dll next to the app: {handlerPath}");
                return false;
            }

            // Will internally register custom WER handler
            return Initialize(sentryDsn, cacheDirectory, handlerPath, release, environment, debug);
        }

        private const string SentryLibrary = "sentry.dll";

        // Opaque pointer types represented as IntPtr
        public struct SentryOptions { }
        public struct SentryValue
        {
            public ulong Bits;
        }

        // Enums
        public enum SentryLevel
        {
            Debug = -1,
            Info = 0,
            Warning = 1,
            Error = 2,
            Fatal = 3
        }

        // Core options functions
        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial nint sentry_options_new();

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_free(nint opts);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_dsn(nint opts, string dsn);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_database_path(nint opts, string path);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Utf16)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_database_pathw(nint opts, string path);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Utf16)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_handler_pathw(nint opts, string path);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_release(nint opts, string release);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_environment(nint opts, string environment);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_debug(nint opts, int debug);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_sample_rate(nint opts, double sample_rate);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_options_set_auto_session_tracking(nint opts, int val);

        // Core SDK functions
        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial int sentry_init(nint options);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial int sentry_close();

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial int sentry_flush(ulong timeout);

        // Event capture functions
        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_value_new_event();

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_value_new_message_event(SentryLevel level, string? logger, string text);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_value_new_string(string value);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_capture_event(SentryValue evt);

        // Tag and context functions
        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_set_tag(string key, string value);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_set_extra(string key, SentryValue value);

        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_set_context(string key, SentryValue value);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_set_level(SentryLevel level);

        // User functions
        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_value_new_user(string id, string username, string email, string ip_address);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_set_user(SentryValue user);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_remove_user();

        // Breadcrumb functions
        [LibraryImport(SentryLibrary, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial SentryValue sentry_value_new_breadcrumb(string type, string message);

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_add_breadcrumb(SentryValue breadcrumb);

        // Session functions
        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_start_session();

        [LibraryImport(SentryLibrary)]
        [UnmanagedCallConv(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
        public static partial void sentry_end_session();

        // Windows API
        [LibraryImport("Kernel32", StringMarshalling = StringMarshalling.Utf16, SetLastError = false)]
        public static partial int WerUnregisterRuntimeExceptionModule(string pwszOutOfProcessCallbackDll, IntPtr pContext);

        [LibraryImport("kernel32", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        public static partial IntPtr GetModuleHandleW(string lpModuleName);

        // Helper method to initialize Sentry with basic configuration
        public static bool Initialize(string dsn, string databasePath, string handlerPath,
            string? release = null, string? environment = null, bool debug = false)
        {
            try
            {
                var options = sentry_options_new();
                if (options == nint.Zero)
                    return false;

                sentry_options_set_dsn(options, dsn);
                sentry_options_set_database_pathw(options, databasePath);
                sentry_options_set_handler_pathw(options, handlerPath);

                if (!string.IsNullOrEmpty(release))
                    sentry_options_set_release(options, release);

                if (!string.IsNullOrEmpty(environment))
                    sentry_options_set_environment(options, environment);

                sentry_options_set_debug(options, debug ? 1 : 0);
                sentry_options_set_auto_session_tracking(options, 1);

                return sentry_init(options) == 0;
            }
            catch
            {
                return false;
            }
        }

        // Helper method to capture a simple message
        public static void CaptureMessage(string message, SentryLevel level = SentryLevel.Info)
        {
            try
            {
                var evt = sentry_value_new_message_event(level, null, message);
                sentry_capture_event(evt);
            }
            catch
            {
                // Silently fail to avoid crashing the application
            }
        }

        // Helper method to shutdown Sentry
        public static void Shutdown()
        {
            try
            {
                sentry_close();
            }
            catch
            {
                // Silently fail
            }
        }
    }
}
