using Microsoft.UI.Xaml;
using SentryDotNetCommon;
using Windows.Storage;

namespace SentryWinUI3NativeCrash
{
    public partial class App : Application
    {
        private MainWindow? _window;

        public App()
        {
            InitializeComponent();
            InitializeSentry();
        }

        private void InitializeSentry()
        {
            bool wasInitialized = SentryNative.InitializeForDotNet(
                ApplicationData.Current.LocalFolder.Path,
                "1.0.42",
                "debug",
                true);

            if (!wasInitialized)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[Sentry] Initialization failed. Check SENTRY_DSN and that sentry_wer_module.dll is present.");
            }
        }

        /// <summary>
        /// Invoked when the application is launched.
        /// </summary>
        /// <param name="args">Details about the launch request and process.</param>
        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            _window = new MainWindow();
            _window.Activate();
        }
    }
}
