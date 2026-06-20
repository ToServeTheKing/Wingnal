using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Navigation;
using QRCoder;
using Wingnal.Service.Account;
using Wingnal.Service.Linking;
using Wingnal.Service.Net;

namespace Wingnal
{
    /// <summary>Displays the linking QR code and drives the secondary-device link to completion.</summary>
    public sealed partial class LinkDevicePage : Page
    {
        private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
        private readonly CancellationTokenSource _cts = new();

        public LinkDevicePage()
        {
            InitializeComponent();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            _ = RunLinkAsync();
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            _cts.Cancel();
        }

        private async Task RunLinkAsync()
        {
            var accountStore = new AccountStore();
            using var rest = new SignalRestClient();
            var linker = new LinkingManager(accountStore, rest);

            try
            {
                SignalAccount account = await Task.Run(
                    () => linker.LinkAsync(OnQrReadyAsync, _cts.Token), _cts.Token);

                _dispatcher.TryEnqueue(() =>
                {
                    StatusText.Text = $"Linked as device {account.DeviceId}.";
                    // Enter the app shell (Chats / Calls / Stories / Settings rail).
                    (App.RootFrame ?? Frame)?.Navigate(typeof(ShellPage));
                });
            }
            catch (OperationCanceledException)
            {
                // Page navigated away; nothing to do.
            }
            catch (Exception ex)
            {
                _dispatcher.TryEnqueue(() =>
                {
                    QrSpinner.IsActive = false;
                    StatusText.Text = $"Linking failed: {ex.Message}";
                });
            }
        }

        private Task OnQrReadyAsync(string qrUri)
        {
            byte[] png = RenderQrPng(qrUri);
            _dispatcher.TryEnqueue(async () =>
            {
                var bitmap = new BitmapImage();
                using var stream = new MemoryStream(png);
                await bitmap.SetSourceAsync(stream.AsRandomAccessStream());
                QrImage.Source = bitmap;
                QrSpinner.IsActive = false;
                StatusText.Text = "Scan this code with Signal on your phone.";
            });
            return Task.CompletedTask;
        }

        private static byte[] RenderQrPng(string content)
        {
            using var generator = new QRCodeGenerator();
            using QRCodeData data = generator.CreateQrCode(content, QRCodeGenerator.ECCLevel.M);
            var png = new PngByteQRCode(data);
            return png.GetGraphic(10);
        }
    }
}
