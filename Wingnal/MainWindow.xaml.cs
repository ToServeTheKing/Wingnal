using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Graphics;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Wingnal
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        // Smallest usable window for the three-pane (rail · list · thread) layout, physical pixels.
        private const int MinWidth = 860;
        private const int MinHeight = 540;

        // Backs the title-bar contact search (reads the same contacts.db the chat list uses).
        private readonly ContactsStore _contacts = new();

        public MainWindow()
        {
            InitializeComponent();

            // Native custom title bar (per the WinUI "Notes" tutorial): extend content under the
            // caption buttons and hand the system our drag region so the app icon + title look built-in.
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(AppTitleBar);

            // AppWindow.TitleBar customizations aren't supported on every OS build (e.g. Win10 1809),
            // so guard them — the SetTitleBar drag region above still works everywhere.
            if (AppWindowTitleBar.IsCustomizationSupported())
            {
                // Tall title bar: recommended when the bar hosts interactive content like a search box.
                AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
            }

            // Reopen where the user left off; fall back to a roomy default on first launch.
            RestoreWindowPlacement();
            // Real minimum size via WM_GETMINMAXINFO (drag stops at the floor instead of snapping back).
            WindowMinSize.Enforce(WinRT.Interop.WindowNative.GetWindowHandle(this), MinWidth, MinHeight);
            AppWindow.Closing += OnAppWindowClosing;    // remember placement on exit

            // Apply the saved appearance (Light/Dark/System) to the window content + the caption buttons.
            ElementTheme savedTheme = UiSettings.LoadTheme();
            if (Content is FrameworkElement rootContent)
                rootContent.RequestedTheme = savedTheme;
            App.TitleBarThemeSink = ApplyTitleBarTheme;
            ApplyTitleBarTheme(savedTheme);
            App.EnterToSend = UiSettings.LoadBool("enter-to-send", true);

            // Dim the title text when the window isn't focused, matching the system caption buttons.
            Activated += OnActivated;

            App.RootFrame = RootFrame;
            // The title-bar search only makes sense on the Chats destination; the shell drives it via the
            // sink, and we hide it whenever we leave the shell entirely (e.g. the link screen).
            App.SearchVisibilitySink = visible =>
                TitleSearch.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
            RootFrame.Navigated += (_, e) =>
            {
                if (e.SourcePageType != typeof(ShellPage))
                    TitleSearch.Visibility = Visibility.Collapsed;
            };

            var accountStore = new AccountStore();
            if (accountStore.Exists)
                RootFrame.Navigate(typeof(ShellPage));
            else
                RootFrame.Navigate(typeof(LinkDevicePage));
        }

        /// <summary>Makes the system caption buttons (min/max/close) follow a forced Light/Dark theme,
        /// instead of the OS app mode, so they match a theme chosen in Settings.</summary>
        private void ApplyTitleBarTheme(ElementTheme theme)
        {
            if (!AppWindowTitleBar.IsCustomizationSupported()) return;
            AppWindow.TitleBar.PreferredTheme = theme switch
            {
                ElementTheme.Light => TitleBarTheme.Light,
                ElementTheme.Dark => TitleBarTheme.Dark,
                _ => TitleBarTheme.UseDefaultAppMode,
            };
        }

        // ── window placement & minimum size ──

        private void RestoreWindowPlacement()
        {
            WindowPlacement? p = WindowStateStore.Load();
            if (p is not null && p.Width >= MinWidth && p.Height >= MinHeight)
                AppWindow.MoveAndResize(new RectInt32(p.X, p.Y, p.Width, p.Height));
            else
                AppWindow.Resize(new SizeInt32(1100, 720));
        }

        private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args) =>
            WindowStateStore.Save(new WindowPlacement(
                sender.Position.X, sender.Position.Y, sender.Size.Width, sender.Size.Height));

        private void OnActivated(object sender, WindowActivatedEventArgs args)
        {
            string key = args.WindowActivationState == WindowActivationState.Deactivated
                ? "WindowCaptionForegroundDisabled"
                : "WindowCaptionForeground";
            if (Application.Current.Resources[key] is Brush brush)
                AppTitleText.Foreground = brush;
        }

        private void OnSearchAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
        {
            if (TitleSearch.Visibility == Visibility.Visible)
            {
                TitleSearch.Focus(FocusState.Programmatic);
                args.Handled = true;
            }
        }

        // ── title-bar contact search ──

        private void OnTitleSearchTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
            sender.ItemsSource = _contacts.Search(sender.Text)
                .Select(c => new ContactSuggestion(c.Name ?? c.Number ?? c.Aci, c.Aci))
                .ToList();
        }

        private void OnTitleSearchSuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
        {
            if (args.SelectedItem is ContactSuggestion s) Open(s.Aci);
        }

        private void OnTitleSearchQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
        {
            if (args.ChosenSuggestion is ContactSuggestion chosen) { Open(chosen.Aci); return; }

            // Fall back to the first matching contact, or a raw ACI UUID if one was typed.
            ContactSuggestion? match = _contacts.Search(args.QueryText)
                .Select(c => new ContactSuggestion(c.Name ?? c.Number ?? c.Aci, c.Aci)).FirstOrDefault();
            if (match is not null) { Open(match.Aci); return; }

            RecipientResolver.Result resolved = RecipientResolver.Resolve(args.QueryText);
            if (resolved.Ok) Open(resolved.ServiceId!);
        }

        private void Open(string aci)
        {
            TitleSearch.Text = "";
            TitleSearch.ItemsSource = null;
            ShellPage.Current?.OpenChat(aci);
        }
    }
}
