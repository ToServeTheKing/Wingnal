using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using Windows.UI.Text;
using Wingnal.Service.Messaging;

namespace Wingnal
{
    /// <summary>View model for one row in the conversation (peer) list.</summary>
    public sealed class ConversationItem : INotifyPropertyChanged
    {
        // Deterministic per-contact avatar palette (like Signal's per-recipient colors).
        private static readonly Color[] AvatarPalette =
        {
            Color.FromArgb(0xFF, 0x4B, 0x6E, 0xFF), // blue
            Color.FromArgb(0xFF, 0x17, 0x9D, 0x86), // teal
            Color.FromArgb(0xFF, 0x7A, 0x5C, 0xFF), // violet
            Color.FromArgb(0xFF, 0xC2, 0x4D, 0x9B), // magenta
            Color.FromArgb(0xFF, 0xCF, 0x66, 0x33), // orange
            Color.FromArgb(0xFF, 0x3E, 0x9E, 0x4A), // green
            Color.FromArgb(0xFF, 0xC0, 0x4A, 0x4A), // red
            Color.FromArgb(0xFF, 0x5A, 0x6B, 0x7B), // slate
        };
        private static readonly Dictionary<int, SolidColorBrush> _brushCache = new();

        private string _preview = "";
        private long _lastTimestamp;
        private string _title = "";
        private int _unreadCount;

        public required string Peer { get; init; }

        public required string Title
        {
            get => _title;
            set { _title = value; OnChanged(nameof(Title)); OnChanged(nameof(Glyph)); }
        }

        /// <summary>Unread message count; drives the badge + bold title.</summary>
        public int UnreadCount
        {
            get => _unreadCount;
            set
            {
                if (_unreadCount == value) return;
                _unreadCount = value;
                OnChanged(nameof(UnreadCount));
                OnChanged(nameof(HasUnread));
                OnChanged(nameof(UnreadVisibility));
                OnChanged(nameof(TitleFontWeight));
            }
        }

        public bool HasUnread => _unreadCount > 0;
        public Visibility UnreadVisibility => _unreadCount > 0 ? Visibility.Visible : Visibility.Collapsed;
        public FontWeight TitleFontWeight => _unreadCount > 0 ? FontWeights.SemiBold : FontWeights.Normal;

        public string Preview
        {
            get => _preview;
            set { _preview = value; OnChanged(nameof(Preview)); }
        }

        public long LastTimestamp
        {
            get => _lastTimestamp;
            set { _lastTimestamp = value; OnChanged(nameof(Subtitle)); }
        }

        /// <summary>Initials/avatar glyph — first character of the title.</summary>
        public string Glyph => Title.Length > 0 ? Title[..1].ToUpperInvariant() : "?";

        /// <summary>Stable avatar colour for this peer.</summary>
        public Brush AvatarBrush => BrushFor(Peer);

        /// <summary>Deterministic avatar colour for a peer key (shared by the list rows and the thread
        /// header so the same contact is always the same colour). Cached per palette slot. In High
        /// Contrast, custom colours break the system's contrast guarantees, so every avatar uses the
        /// system highlight brush instead (paired with AvatarForegroundBrush on the initial).</summary>
        public static Brush BrushFor(string key)
        {
            if (IsHighContrast() &&
                Application.Current.Resources["SystemColorHighlightColorBrush"] is Brush hc)
                return hc;

            int hash = 0;
            foreach (char c in key) hash = unchecked(hash * 31 + c);
            int idx = (int)((uint)hash % (uint)AvatarPalette.Length);
            if (!_brushCache.TryGetValue(idx, out SolidColorBrush? brush))
                _brushCache[idx] = brush = new SolidColorBrush(AvatarPalette[idx]);
            return brush;
        }

        private static bool? _highContrast;
        private static bool IsHighContrast()
        {
            if (_highContrast is null)
            {
                try { _highContrast = new Windows.UI.ViewManagement.AccessibilitySettings().HighContrast; }
                catch { _highContrast = false; }
            }
            return _highContrast.Value;
        }

        public string Subtitle => _lastTimestamp == 0
            ? Peer
            : DateTimeOffset.FromUnixTimeMilliseconds(_lastTimestamp).LocalDateTime.ToString("g");

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        /// <summary>Builds a display title for a peer service id: "Note to Self" for our own ACI,
        /// otherwise a shortened UUID. (Real contact names arrive with Task 3 sync.)</summary>
        public static string TitleFor(string peer, string ownAci) =>
            string.IsNullOrWhiteSpace(peer) ? "Unknown"
            : string.Equals(peer, ownAci, StringComparison.OrdinalIgnoreCase) ? "Note to Self"
            : peer.Length > 8 ? peer[..8] + "…" : peer;
    }

    /// <summary>A contact-search suggestion: the display name and the ACI to start a chat with.</summary>
    public sealed record ContactSuggestion(string Display, string Aci)
    {
        public override string ToString() => Display;   // AutoSuggestBox fallback text
    }
}
