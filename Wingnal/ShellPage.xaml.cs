using System;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace Wingnal
{
    /// <summary>App shell once linked: a Signal-style NavigationView rail hosting the Chats, Calls,
    /// Stories and Settings destinations in an inner content frame.</summary>
    public sealed partial class ShellPage : Page
    {
        /// <summary>The live shell, so the title-bar search (hosted in MainWindow) can route a chosen
        /// contact into the Chats destination.</summary>
        public static ShellPage? Current { get; private set; }

        public ShellPage()
        {
            InitializeComponent();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            Current = this;
            // Total unread (from any tab) rides on the Chats rail item as an InfoBadge.
            App.UnreadSink = count =>
                ChatsItem.InfoBadge = count > 0 ? new InfoBadge { Value = count } : null;
            // Default to Chats. Assigning SelectedItem raises SelectionChanged, which navigates.
            if (Nav.SelectedItem is null)
                Nav.SelectedItem = ChatsItem;
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            if (Current == this) Current = null;
        }

        /// <summary>Switches to the Chats destination and opens the conversation with the given ACI.</summary>
        public void OpenChat(string aci)
        {
            Nav.SelectedItem = ChatsItem;   // ensures Chats is selected + ChatPage is loaded (synchronous)
            if (ContentFrame.Content is ChatPage chat)
                chat.OpenConversation(aci);
        }

        private void OnNavSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            string? tag = (args.SelectedItem as NavigationViewItem)?.Tag as string;
            Type? target = args.IsSettingsSelected
                ? typeof(SettingsPage)
                : tag switch
                {
                    "chats" => typeof(ChatPage),
                    "calls" => typeof(CallsPage),
                    "stories" => typeof(StoriesPage),
                    _ => null,
                };

            // The title-bar contact search belongs to Chats only.
            App.SearchVisibilitySink?.Invoke(target == typeof(ChatPage));

            // Avoid re-navigating to the page we're already on. Suppress the frame's content
            // transition: its entrance animation competes with the rail's selection-indicator
            // animation on the UI thread, which made the indicator stutter between tabs.
            if (target is not null && ContentFrame.CurrentSourcePageType != target)
                ContentFrame.Navigate(target, null, new SuppressNavigationTransitionInfo());
        }
    }
}
