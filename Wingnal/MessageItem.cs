using System;
using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Wingnal.Service.Messaging;

namespace Wingnal
{
    /// <summary>Delivery state of an outgoing message (None for received messages). Progresses
    /// Sending → Sent → Delivered → Read as receipts arrive; Failed is terminal until retried.</summary>
    public enum SendStatus { None, Sending, Sent, Delivered, Read, Failed }

    /// <summary>View model for one chat bubble. Mutable so an optimistic outgoing bubble can flip
    /// from "Sending…" to sent/failed without rebuilding the list.</summary>
    public sealed class MessageItem : INotifyPropertyChanged
    {
        private SendStatus _status;
        private bool _showCaption = true;

        public required string Body { get; init; }
        public required bool Outgoing { get; init; }
        public required long Timestamp { get; init; }

        /// <summary>Local file path of a downloaded attachment (null for text-only messages).</summary>
        public string? MediaPath { get; init; }

        private bool HasImage => MediaPath is { } p &&
            (p.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase) ||
             p.EndsWith(".png", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".gif", StringComparison.OrdinalIgnoreCase) ||
             p.EndsWith(".webp", StringComparison.OrdinalIgnoreCase));

        /// <summary>Inline image for image attachments (null otherwise → the text placeholder shows instead).</summary>
        public ImageSource? ImageSource => HasImage ? new BitmapImage(new Uri(MediaPath!)) : null;
        public Visibility ImageVisibility => HasImage ? Visibility.Visible : Visibility.Collapsed;
        public Visibility BodyVisibility => HasImage ? Visibility.Collapsed : Visibility.Visible;

        /// <summary>True when this bubble continues a run from the same sender within the grouping window;
        /// drives tight spacing. Set once before the item is added to the list.</summary>
        public bool IsContinuation { get; set; }

        /// <summary>Only the last bubble of a group keeps its timestamp (set by the page as a group grows).</summary>
        public bool ShowCaption
        {
            get => _showCaption;
            set { if (_showCaption == value) return; _showCaption = value; OnChanged(nameof(CaptionVisibility)); }
        }

        /// <summary>Tight top margin within a group, a larger gap between groups.</summary>
        public Thickness BubbleMargin => IsContinuation ? new Thickness(0, 1, 0, 0) : new Thickness(0, 8, 0, 0);

        /// <summary>Hidden for grouped messages, but always shown while sending or when delivery failed.</summary>
        public Visibility CaptionVisibility =>
            _showCaption || _status is SendStatus.Sending or SendStatus.Failed
                ? Visibility.Visible : Visibility.Collapsed;

        public SendStatus Status
        {
            get => _status;
            set
            {
                if (_status == value) return;
                _status = value;
                OnChanged(nameof(Status));
                OnChanged(nameof(Caption));
                OnChanged(nameof(CaptionBrush));
                OnChanged(nameof(CaptionVisibility));
            }
        }

        public HorizontalAlignment Alignment => Outgoing ? HorizontalAlignment.Right : HorizontalAlignment.Left;

        /// <summary>Accent fill for our messages, neutral control fill for the peer's.</summary>
        public Brush BubbleBrush => (Brush)Application.Current.Resources[
            Outgoing ? "AccentFillColorDefaultBrush" : "ControlFillColorDefaultBrush"];

        /// <summary>Readable text colour on top of the bubble fill.</summary>
        public Brush Foreground => (Brush)Application.Current.Resources[
            Outgoing ? "TextOnAccentFillColorPrimaryBrush" : "TextFillColorPrimaryBrush"];

        /// <summary>Asymmetric "tail" corners, Signal/Teams style: the corner nearest the sender is squared.</summary>
        public CornerRadius BubbleCorner => Outgoing
            ? new CornerRadius(16, 16, 4, 16)
            : new CornerRadius(16, 16, 16, 4);

        /// <summary>Time, plus a delivery glyph for outgoing messages (✓ sent, ✓✓ delivered/read).</summary>
        public string Caption => _status switch
        {
            SendStatus.Sending => "Sending…",
            SendStatus.Failed => "Not delivered",
            SendStatus.Sent => $"{FormatTime(Timestamp)}  ✓",
            SendStatus.Delivered or SendStatus.Read => $"{FormatTime(Timestamp)}  ✓✓",
            _ => FormatTime(Timestamp),
        };

        public Brush CaptionBrush => (Brush)Application.Current.Resources[
            _status == SendStatus.Failed ? "SystemFillColorCriticalBrush" :
            _status == SendStatus.Read ? "AccentTextFillColorPrimaryBrush" :   // read = accented ✓✓
            "TextFillColorTertiaryBrush"];

        /// <summary>Rank for monotonic status advancement (a late DELIVERED never downgrades a READ).</summary>
        public static int Rank(SendStatus s) => s switch
        {
            SendStatus.Read => 4,
            SendStatus.Delivered => 3,
            SendStatus.Sent => 2,
            SendStatus.Sending => 1,
            _ => 0,
        };

        public static MessageItem From(StoredMessage m) => new()
        {
            Body = m.Body,
            Outgoing = m.Outgoing,
            Timestamp = m.Timestamp,
            MediaPath = m.MediaPath,
            Status = SendStatus.None,
        };

        /// <summary>Time only for today's messages, short date + time for older ones.</summary>
        private static string FormatTime(long unixMs)
        {
            DateTime local = DateTimeOffset.FromUnixTimeMilliseconds(unixMs).LocalDateTime;
            return local.Date == DateTime.Now.Date ? local.ToString("t") : local.ToString("g");
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    /// <summary>A "Today / Yesterday / June 14, 2026" divider inserted between days in a thread.</summary>
    public sealed class DaySeparatorItem
    {
        public required string Label { get; init; }

        public static DaySeparatorItem For(DateTime day) => new() { Label = LabelFor(day) };

        public static string LabelFor(DateTime day)
        {
            DateTime today = DateTime.Now.Date;
            if (day == today) return "Today";
            if (day == today.AddDays(-1)) return "Yesterday";
            return day.Year == today.Year ? day.ToString("MMMM d") : day.ToString("MMMM d, yyyy");
        }
    }
}
