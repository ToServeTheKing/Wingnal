using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Wingnal
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// </summary>
    public partial class App : Application
    {
        private Window? _window;

        /// <summary>The window's top-level navigation frame (set by MainWindow). Lets pages hosted
        /// inside the shell's inner frame (e.g. ChatPage's unlink) navigate the whole window.</summary>
        public static Frame? RootFrame { get; set; }

        /// <summary>Set by MainWindow; lets the shell show/hide the title-bar contact search so it only
        /// appears on the Chats destination, not on Calls/Stories/Settings.</summary>
        public static Action<bool>? SearchVisibilitySink { get; set; }

        /// <summary>Set by the shell; lets ChatPage publish the total unread count onto the Chats rail item.</summary>
        public static Action<int>? UnreadSink { get; set; }

        /// <summary>Set by MainWindow; applies a Light/Dark/System theme to the system caption buttons so
        /// the min/max/close glyphs follow a forced theme, not the OS app mode.</summary>
        public static Action<ElementTheme>? TitleBarThemeSink { get; set; }

        /// <summary>In-memory mirror of the "Enter sends" preference, so ChatPage's hot keydown path
        /// doesn't read a file per keypress. Initialised at startup, updated by SettingsPage.</summary>
        public static bool EnterToSend { get; set; } = true;

        /// <summary>
        /// Initializes the singleton application object.  This is the first line of authored code
        /// executed, and as such is the logical equivalent of main() or WinMain().
        /// </summary>
        public App()
        {
            InitializeComponent();
            UnhandledException += OnUnhandledException;
        }

        private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
        {
            // Log before the framework tears the app down, so crashes leave a trail in wingnal.log.
            Service.Diagnostics.FileLog.Write($"UNHANDLED: {e.Exception}");
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
