using Microsoft.UI.Xaml;
using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Windows.Storage;

namespace SentryWinUI3NativeCrash
{
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void WrongThreadButton_Click(object sender, RoutedEventArgs e)
        {
            Task.Run(() => WrongThreadButton.Content = "abc");
        }

        private void InvalidPathButton_Click(object sender, RoutedEventArgs e)
        {
            DispatcherQueue.TryEnqueue(async () =>
            {
                await TriggerStowedExceptionInvalidPath();
            });
        }

        private void FailFastButton_Click(object sender, RoutedEventArgs e)
        {
            CrashInStack3();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public async System.Threading.Tasks.Task TriggerStowedExceptionInvalidPath()
        {
            // The exception from GetFileFromPathAsync is unhandled inside the async
            // DispatcherQueue delegate (the Task it returns is never awaited by the
            // dispatcher). WinUI propagates unhandled dispatcher exceptions through
            // the WinRT error model, which raises a stowed exception (0xC000027B).
            var invalidPath = @"C:\Invalid<>Path|?.txt";
            var file = await StorageFile.GetFileFromPathAsync(invalidPath);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void CrashInStack3()
        {
            CrashInStack2();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void CrashInStack2()
        {
            CrashInStack1();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void CrashInStack1()
        {
            Environment.FailFast("Failing fast for Sentry!");
        }
    }
}
