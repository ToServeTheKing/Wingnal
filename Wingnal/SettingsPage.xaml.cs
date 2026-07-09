using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;

namespace Wingnal
{
    /// <summary>Settings: shows the linked account and lets the user unlink (wiping local state).</summary>
    public sealed partial class SettingsPage : Page
    {
        private bool _themeReady;

        public SettingsPage() => InitializeComponent();

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);

            // Appearance + behavior + version don't need an account.
            ThemeRadios.SelectedIndex = UiSettings.LoadTheme() switch
            {
                ElementTheme.Light => 1,
                ElementTheme.Dark => 2,
                _ => 0,
            };
            EnterToSendToggle.IsOn = UiSettings.LoadBool("enter-to-send", true);
            _themeReady = true;
            VersionText.Text = AppVersion();

            SignalAccount? account = new AccountStore().Load();
            if (account is null) return;

            AccountExpander.Header = account.Number;
            AccountExpander.Description = $"Linked device · #{account.DeviceId}";
            DetailNumber.Text = account.Number;
            DetailDevice.Text = account.DeviceId.ToString();
            DetailAci.Text = account.Aci;
        }

        private void OnThemeChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_themeReady) return;
            string? tag = (ThemeRadios.SelectedItem as RadioButton)?.Tag as string;
            ElementTheme theme = tag switch
            {
                "Light" => ElementTheme.Light,
                "Dark" => ElementTheme.Dark,
                _ => ElementTheme.Default,
            };
            UiSettings.SaveTheme(theme);
            // Apply live to the whole window content (pages) + the system caption buttons.
            if (App.RootFrame?.XamlRoot?.Content is FrameworkElement root)
                root.RequestedTheme = theme;
            App.TitleBarThemeSink?.Invoke(theme);
        }

        private void OnEnterToSendToggled(object sender, RoutedEventArgs e)
        {
            if (!_themeReady) return;
            App.EnterToSend = EnterToSendToggle.IsOn;
            UiSettings.SaveBool("enter-to-send", EnterToSendToggle.IsOn);
        }

        private static string AppVersion()
        {
            try
            {
                Windows.ApplicationModel.PackageVersion v = Windows.ApplicationModel.Package.Current.Id.Version;
                return $"Wingnal {v.Major}.{v.Minor}.{v.Build}";
            }
            catch { return "Wingnal"; }
        }

        private async void OnUnlinkClick(object sender, RoutedEventArgs e)
        {
            var dialog = new ContentDialog
            {
                Title = "Unlink this device?",
                Content = "Wingnal will be removed from this device and the messages, contacts and "
                        + "encryption sessions stored here will be deleted. You'll need to scan the QR "
                        + "code again to relink.\n\nAlso remove “Wingnal” from Linked devices on your phone.",
                PrimaryButtonText = "Unlink",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            // The chat connection now outlives tab switches, so stop it explicitly before wiping its DB.
            ChatPage.Live?.Shutdown();

            // Wipe ALL local state, not just the account: sessions are tied to the old identity keys and
            // must not survive into a re-link. Stores open per-call, so this is safe even though ChatPage
            // built its own instances (it was already torn down when we navigated here).
            SignalAccount? account = new AccountStore().Load();
            try { if (account is not null) new SqliteSignalProtocolStore(account, "protocol.db").Clear(); } catch { }
            try { new MessageStore().Clear(); } catch { }
            try { new ContactsStore().Clear(); } catch { }
            try { new ProfileKeyStore().Clear(); } catch { }
            try { new ProfileNameStore().Clear(); } catch { }                  // resolved profile names
            try { new SqliteSenderKeyStore().Clear(); } catch { }              // group sender keys (GroupsV2)
            try { new Wingnal.Service.Groups.GroupStore().Clear(); } catch { } // group state (GroupsV2)
            new AccountStore().Delete();

            // Leave the shell entirely, back to the full-window link screen.
            (App.RootFrame ?? Frame)?.Navigate(typeof(LinkDevicePage));
        }
    }
}
