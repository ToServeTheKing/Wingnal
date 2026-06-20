using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Input;
using Windows.UI.Core;
using Wingnal.Protocol.Identity;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Messaging;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;
using Wingnal.Service.Sync;

namespace Wingnal
{
    /// <summary>Home once linked: lists per-peer conversations, connects the chat socket, and routes
    /// sent and received 1:1 texts to the selected peer's thread.</summary>
    public sealed partial class ChatPage : Page
    {
        /// <summary>The live ChatPage, so an unlink from SettingsPage can stop its connection.</summary>
        internal static ChatPage? Live;

        private enum Conn { Connecting, Connected, Offline }

        private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
        // Holds MessageItem bubbles and DaySeparatorItem dividers (chosen by ChatItemTemplateSelector).
        private readonly ObservableCollection<object> _messages = new();
        private readonly ObservableCollection<ConversationItem> _conversations = new();
        private readonly Dictionary<string, ConversationItem> _byPeer = new(StringComparer.OrdinalIgnoreCase);
        private readonly MessageStore _store = new();
        private readonly ContactsStore _contacts = new();
        private readonly ProfileKeyStore _profileKeys = new();
        private readonly SqliteSenderKeyStore _senderKeys = new();   // GroupsV2 G1 receive
        private readonly Wingnal.Service.Groups.GroupStore _groups = new();   // GroupsV2 group state
        private readonly Wingnal.Service.Attachments.AttachmentService _attachments = new();

        private CancellationTokenSource? _cts;
        private CancellationTokenSource? _importCts;
        private SignalAccount? _account;
        private SignalRestClient? _rest;
        private SyncProcessor? _syncProcessor;
        // One durable per-peer session store shared by BOTH send and receive (sessions keyed by peer
        // address, so a single store serves the whole conversation without initiator/responder clobber).
        private SqliteSignalProtocolStore? _protocolStore;
        private string? _selectedPeer;
        private bool _historyImportStarted;
        private bool _initialized;
        private DateTime? _lastShownDay;   // day of the last bubble in the open thread (for separators)
        private Action? _retryAction;
        private bool _identityDialogOpen;  // only one ContentDialog may be shown at a time
        private bool _isNarrow;
        private bool _narrowShowThread;
        private const double NarrowThreshold = 640;

        public ChatPage()
        {
            InitializeComponent();
            // Cache the page so flipping Chats ⇆ Calls ⇆ Stories doesn't tear down (and reconnect) the chat.
            NavigationCacheMode = NavigationCacheMode.Required;
            MessageList.ItemsSource = _messages;
            ConversationList.ItemsSource = _conversations;
            SizeChanged += OnPageSizeChanged;   // collapse to a single pane on narrow windows
            // handledEventsToo: a multiline TextBox handles Enter's KeyDown itself (to insert a newline),
            // so a plain XAML KeyDown handler never fires for Enter. This lets us still send on Enter.
            ComposeBox.AddHandler(UIElement.KeyDownEvent, new KeyEventHandler(OnComposeKeyDown), true);
        }

        // ── adaptive (single-pane) layout ──

        private void OnPageSizeChanged(object sender, SizeChangedEventArgs e)
        {
            bool narrow = e.NewSize.Width < NarrowThreshold;
            if (narrow == _isNarrow) return;
            _isNarrow = narrow;
            ApplyPaneLayout();
        }

        private void ApplyPaneLayout()
        {
            if (!_isNarrow)
            {
                SidebarColumn.Width = new GridLength(300);
                ThreadColumn.Width = new GridLength(1, GridUnitType.Star);
                SidebarPane.Visibility = Visibility.Visible;
                ThreadPane.Visibility = Visibility.Visible;
                BackButton.Visibility = Visibility.Collapsed;
                return;
            }
            // Narrow: show the list, or the open thread (with a Back affordance).
            bool showThread = _narrowShowThread && _selectedPeer is not null;
            SidebarColumn.Width = showThread ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
            ThreadColumn.Width = showThread ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            SidebarPane.Visibility = showThread ? Visibility.Collapsed : Visibility.Visible;
            ThreadPane.Visibility = showThread ? Visibility.Visible : Visibility.Collapsed;
            BackButton.Visibility = showThread ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OnBackClick(object sender, RoutedEventArgs e)
        {
            _narrowShowThread = false;
            ApplyPaneLayout();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            Live = this;
            if (_initialized) return;   // returning to a cached Chats page — keep the live connection

            SignalAccount? account = new AccountStore().Load();
            if (account is null)
            {
                (App.RootFrame ?? Frame)?.Navigate(typeof(LinkDevicePage));
                return;
            }
            _initialized = true;

            _account = account;
            _protocolStore = new SqliteSignalProtocolStore(account, "protocol.db",
                onChanged: () => new AccountStore().Save(account));
            _syncProcessor = new SyncProcessor(_contacts);

            _store.Deduplicate();   // clean up any duplicate rows left by an earlier double-import

            // Conversations() is newest-first; AddOrUpdateConversation inserts each at the top, so feed
            // it oldest-first to leave the most-recently-active chat on top.
            foreach (Conversation c in _store.Conversations().Reverse())
                AddOrUpdateConversation(c.Peer, c.LastBody, c.LastTimestamp, c.LastOutgoing);

            if (_conversations.Count > 0)
                ConversationList.SelectedIndex = 0;
            else if (!UiSettings.FlagSet("newchat-tip"))
            {
                // First run with no chats yet — point the user at how to start one (once).
                UiSettings.SetFlag("newchat-tip");
                _dispatcher.TryEnqueue(DispatcherQueuePriority.Low, () => NewChatTip.IsOpen = true);
            }

            _cts = new CancellationTokenSource();
            _ = StartReceiveAsync(account, _protocolStore, _cts.Token);
            // Ask the primary to push contacts/blocked/configuration so the list can show names.
            _ = RequestSyncAsync(account, _protocolStore, _cts.Token);
            // If this device was just re-linked with link+sync, show the import screen + backfill once.
            if (account.EphemeralBackupKey is { Length: 32 })
                ImportOverlay.Visibility = Visibility.Visible;
            _ = ImportHistoryAsync(account, _cts.Token);
        }

        /// <summary>Stops the live connection + import. Called by SettingsPage before an unlink wipe.</summary>
        public void Shutdown()
        {
            _cts?.Cancel();
            _importCts?.Cancel();
            _rest?.Dispose();
            _rest = null;
            if (Live == this) Live = null;
        }

        // ── conversation selection / creation ──

        private void OnConversationSelected(object sender, SelectionChangedEventArgs e)
        {
            if (ConversationList.SelectedItem is not ConversationItem item) return;
            SelectPeer(item.Peer, item.Title);
        }

        private void SelectPeer(string peer, string title)
        {
            _selectedPeer = peer;
            ThreadTitle.Text = title;
            ComposeBox.IsEnabled = true;
            SendButton.IsEnabled = true;
            ErrorBar.IsOpen = false;

            // Header avatar (same deterministic colour as the sidebar row).
            ThreadAvatar.Background = ConversationItem.BrushFor(peer);
            ThreadAvatarText.Text = title.Length > 0 ? title[..1].ToUpperInvariant() : "?";
            ThreadAvatar.Visibility = Visibility.Visible;
            VerifyButton.Visibility = Visibility.Visible;
            ThreadMenuButton.Visibility = Visibility.Visible;
            EmptyState.Visibility = Visibility.Collapsed;

            HideTyping();   // a fresh thread starts with no typing indicator

            bool hadUnread = _byPeer.TryGetValue(peer, out ConversationItem? conv) && conv.UnreadCount > 0;
            if (conv is not null)
            {
                conv.UnreadCount = 0;   // opening the thread marks it read
                UpdateUnreadBadge();
            }

            _messages.Clear();
            _lastShownDay = null;
            long lastInbound = 0;
            foreach (StoredMessage m in _store.Recent(peer))
            {
                AddMessageItem(MessageItem.From(m));
                if (!m.Outgoing) lastInbound = Math.Max(lastInbound, m.Timestamp);
            }
            // Opening a thread with unread messages tells the peer we've now read them.
            if (hadUnread && lastInbound != 0 && !IsSelf(peer))
                FireAndForgetSend(peer, Receipts.Read(lastInbound));
            ThreadEmptyHint.Visibility = _messages.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ScrollToBottom();   // open on the newest message
            ComposeBox.Focus(FocusState.Programmatic);   // ready to type immediately

            // In narrow (single-pane) mode, opening a chat swaps the list out for the thread.
            _narrowShowThread = true;
            if (_isNarrow) ApplyPaneLayout();
        }

        // ── start a chat ──

        /// <summary>Opens (creating if needed) the conversation with the given ACI and selects it.
        /// Called by the shell when a contact is chosen from the title-bar search.</summary>
        public void OpenConversation(string aci) => StartChatWith(aci);

        private void StartChatWith(string aci)
        {
            ConversationItem item = AddOrUpdateConversation(aci, preview: "", timestamp: 0, outgoing: false);
            ConversationList.SelectedItem = item;     // raises OnConversationSelected
            SelectPeer(aci, item.Title);              // ensure the thread opens even if already selected
        }

        // ── message / conversation context actions (right-click menu + swipe) ──

        private void OnCopyMessage(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.DataContext is not MessageItem item) return;
            var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
            data.SetText(item.Body);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
        }

        private void OnDeleteMessage(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.DataContext is not MessageItem item || _selectedPeer is null) return;
            _store.DeleteMessage(_selectedPeer, item.Timestamp, item.Outgoing);
            _messages.Remove(item);
            if (_messages.OfType<MessageItem>().Any() is false)
                ThreadEmptyHint.Visibility = Visibility.Visible;
        }

        private void OnMarkConversationRead(object sender, RoutedEventArgs e) =>
            MarkRead(PeerFrom(sender));

        private void MarkRead(string? peer)
        {
            if (peer is not null && _byPeer.TryGetValue(peer, out ConversationItem? c))
            {
                c.UnreadCount = 0;
                UpdateUnreadBadge();
            }
        }

        private async void OnDeleteConversation(object sender, RoutedEventArgs e) =>
            await ConfirmDeleteConversationAsync(PeerFrom(sender));

        /// <summary>The conversation a context-menu item belongs to (its DataContext), or the open thread.</summary>
        private string? PeerFrom(object sender) =>
            (sender as FrameworkElement)?.DataContext is ConversationItem c ? c.Peer : _selectedPeer;

        private async Task ConfirmDeleteConversationAsync(string? peer)
        {
            if (peer is null) return;
            var dialog = new ContentDialog
            {
                Title = "Delete conversation?",
                Content = "This removes the messages stored on this PC. It won't delete them on your phone.",
                PrimaryButtonText = "Delete",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = XamlRoot,
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            _store.DeleteConversation(peer);
            if (_byPeer.TryGetValue(peer, out ConversationItem? item))
            {
                _conversations.Remove(item);
                _byPeer.Remove(peer);
            }
            UpdateUnreadBadge();

            if (_selectedPeer == peer)
            {
                _selectedPeer = null;
                _messages.Clear();
                ThreadTitle.Text = "Select or start a conversation";
                ThreadAvatar.Visibility = Visibility.Collapsed;
                ThreadMenuButton.Visibility = Visibility.Collapsed;
                VerifyButton.Visibility = Visibility.Collapsed;
                ComposeBox.IsEnabled = false;
                SendButton.IsEnabled = false;
                ThreadEmptyHint.Visibility = Visibility.Collapsed;
                EmptyState.Visibility = Visibility.Visible;
            }
        }

        /// <summary>"New chat" affordance: a small dialog to search a contact (or paste an account ID).</summary>
        private async void OnNewChatClick(object sender, RoutedEventArgs e)
        {
            var box = new AutoSuggestBox
            {
                PlaceholderText = "Search a contact, or paste an account ID",
                QueryIcon = new SymbolIcon(Symbol.Find),
                DisplayMemberPath = "Display",
                TextMemberPath = "Display",
            };
            string? chosen = null;
            box.TextChanged += (s, a) =>
            {
                if (a.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
                s.ItemsSource = _contacts.Search(s.Text)
                    .Select(c => new ContactSuggestion(c.Name ?? c.Number ?? c.Aci, c.Aci)).ToList();
            };
            box.SuggestionChosen += (s, a) => { if (a.SelectedItem is ContactSuggestion cs) chosen = cs.Aci; };

            var dialog = new ContentDialog
            {
                Title = "New chat",
                PrimaryButtonText = "Start",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = XamlRoot,
                Content = box,
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            string? aci = chosen ?? ResolveQuery(box.Text);
            if (aci is not null) StartChatWith(aci);
            else ShowError("Enter a known contact, or a valid account ID.");
        }

        /// <summary>Resolves a free-text query to an ACI: a matching contact, else a raw account ID.</summary>
        private string? ResolveQuery(string? query)
        {
            if (string.IsNullOrWhiteSpace(query)) return null;
            Contact? match = _contacts.Search(query).FirstOrDefault();
            if (match is not null) return match.Aci;
            RecipientResolver.Result r = RecipientResolver.Resolve(query);
            return r.Ok ? r.ServiceId : null;
        }

        // ── send ──

        private void OnComposeKeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key != Windows.System.VirtualKey.Enter) return;
            // Shift+Enter always inserts a newline.
            if (InputKeyboardSource.GetKeyStateForCurrentThread(Windows.System.VirtualKey.Shift)
                    .HasFlag(CoreVirtualKeyStates.Down))
                return;
            // Honour the "Enter to send" preference; when off, Ctrl+Enter still sends.
            bool ctrl = InputKeyboardSource.GetKeyStateForCurrentThread(Windows.System.VirtualKey.Control)
                .HasFlag(CoreVirtualKeyStates.Down);
            if (!App.EnterToSend && !ctrl) return;   // off: keep the newline the TextBox just inserted

            // This handler runs handledEventsToo, i.e. AFTER the TextBox already inserted the newline.
            // SendAsync captures Text.Trim() (dropping that trailing newline) and clears the box; if there's
            // nothing to send, just drop the stray newline so the box doesn't accumulate blank lines.
            e.Handled = true;
            if (string.IsNullOrWhiteSpace(ComposeBox.Text))
                ComposeBox.Text = "";
            else
                _ = SendAsync();
        }

        private void OnSendClick(object sender, RoutedEventArgs e) => _ = SendAsync();

        private void OnRetryClick(object sender, RoutedEventArgs e)
        {
            ErrorBar.IsOpen = false;
            Action? retry = _retryAction;
            _retryAction = null;
            retry?.Invoke();
        }

        private async Task SendAsync()
        {
            if (_account is null || _protocolStore is null || _selectedPeer is null) return;
            string text = ComposeBox.Text?.Trim() ?? "";
            if (text.Length == 0) return;

            string peer = _selectedPeer;
            ComposeBox.Text = "";   // optimistic: clear the box and show the bubble immediately
            _lastTypingSentTick = 0;
            if (!IsSelf(peer)) FireAndForgetSend(peer, Receipts.Typing(started: false, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));

            long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var item = new MessageItem { Body = text, Outgoing = true, Timestamp = ts, Status = SendStatus.Sending };
            if (peer == _selectedPeer) AppendBubble(item);
            AddOrUpdateConversation(peer, text, ts, outgoing: true);

            await TrySendAsync(peer, text, ts, item);
        }

        /// <summary>Sends (or re-sends) one message, flipping the bubble between Sending/Sent/Failed.
        /// The message is persisted only once the server accepts it.</summary>
        private async Task TrySendAsync(string peer, string text, long ts, MessageItem item)
        {
            item.Status = SendStatus.Sending;
            try
            {
                _rest ??= new SignalRestClient();
                var sender = new MessageSender(_account!, _protocolStore!, _rest, _profileKeys);

                FileLog.Write($"send: -> {peer} (len={text.Length})");
                MessageSender.SendResult result = await Task.Run(() =>
                    sender.SendTextAsync(peer, text)).ConfigureAwait(true);
                FileLog.Write($"send: ok={result.Ok} devices={result.DeviceCount} detail={result.Detail}");

                if (result.Ok)
                {
                    item.Status = SendStatus.Sent;
                    _store.Add(new StoredMessage(peer, text, ts, Outgoing: true));
                }
                else
                {
                    item.Status = SendStatus.Failed;
                    ShowError("Message not sent. Check your connection and try again.",
                        retry: () => _ = TrySendAsync(peer, text, ts, item));
                }
            }
            catch (UntrustedIdentityException uie)
            {
                // The recipient's identity key changed — don't send until the user verifies + approves.
                FileLog.Write($"send: untrusted identity for {uie.Address.Name}");
                item.Status = SendStatus.Failed;
                await HandleIdentityChangeAsync(uie.Address, uie.Identity,
                    onApproved: () => _ = TrySendAsync(peer, text, ts, item));
            }
            catch (Exception ex)
            {
                FileLog.Write($"send: EXCEPTION {ex.GetType().Name}: {ex.Message}");
                item.Status = SendStatus.Failed;
                ShowError("Message not sent. Check your connection and try again.",
                    retry: () => _ = TrySendAsync(peer, text, ts, item));
            }
        }

        // ── identity-change / safety numbers ──

        private void OnIdentityChange(UntrustedIdentityException uie) =>
            _dispatcher.TryEnqueue(() => _ = HandleIdentityChangeAsync(uie.Address, uie.Identity, onApproved: null));

        /// <summary>Warns that a peer's identity key changed, shows the new safety number for out-of-band
        /// verification, and on approval forgets the old key + sessions so the new one is trusted.</summary>
        private Task HandleIdentityChangeAsync(SignalProtocolAddress address, IdentityKey newIdentity, Action? onApproved) =>
            ShowSafetyNumberDialogAsync(address.Name, newIdentity, changed: true, onApproved);

        /// <summary>"View safety number" affordance for the open conversation (proactive verification).</summary>
        private async void OnVerifySafetyNumberClick(object sender, RoutedEventArgs e)
        {
            if (_selectedPeer is null || _protocolStore is null) return;
            IdentityKey? id = PeerIdentity(_selectedPeer);
            if (id is null) { ShowError("No secure session yet — send a message first, then verify."); return; }
            await ShowSafetyNumberDialogAsync(_selectedPeer, id, changed: false, onApproved: null);
        }

        /// <summary>Shows the safety number for a peer. When <paramref name="changed"/>, frames it as a
        /// warning with an "approve" action; otherwise it's a read-only verification view.</summary>
        private async Task ShowSafetyNumberDialogAsync(string peer, IdentityKey peerIdentity, bool changed, Action? onApproved)
        {
            if (_identityDialogOpen || _protocolStore is null) return;
            _identityDialogOpen = true;
            try
            {
                string who = DisplayTitle(peer);
                var body = new StackPanel { Spacing = 12 };
                body.Children.Add(new TextBlock
                {
                    TextWrapping = TextWrapping.Wrap,
                    Text = changed
                        ? $"The safety number with {who} has changed. This happens if they reinstalled " +
                          "Signal or switched devices — but it can also mean someone is intercepting your " +
                          "messages. Compare this number with them over a trusted channel before approving."
                        : $"To verify your conversation with {who} is private, compare this number with the " +
                          "one shown on their device. They should match exactly.",
                });
                body.Children.Add(new TextBlock
                {
                    Text = TryComputeSafetyNumber(peer, peerIdentity),
                    FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
                    TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true,
                });

                var dialog = new ContentDialog
                {
                    XamlRoot = XamlRoot,
                    Title = changed ? "Safety number changed" : "Verify safety number",
                    Content = body,
                    PrimaryButtonText = changed ? "Verify & approve" : null,
                    CloseButtonText = changed ? "Not now" : "Done",
                    DefaultButton = ContentDialogButton.Close,
                };
                if (await dialog.ShowAsync() == ContentDialogResult.Primary && changed)
                {
                    _protocolStore.ResetPeer(peer);   // forget old identity + dead sessions
                    FileLog.Write($"identity: approved new identity for {peer}");
                    onApproved?.Invoke();
                }
            }
            finally { _identityDialogOpen = false; }
        }

        /// <summary>The stored identity key for a peer (same across their devices), or null if no session yet.</summary>
        private IdentityKey? PeerIdentity(string peer)
        {
            if (_protocolStore is null) return null;
            foreach (uint dev in _protocolStore.GetSubDeviceSessions(peer))
            {
                IdentityKey? id = _protocolStore.GetIdentity(new SignalProtocolAddress(peer, dev));
                if (id is not null) return id;
            }
            return _protocolStore.GetIdentity(new SignalProtocolAddress(peer, 1));
        }

        private string TryComputeSafetyNumber(string peerAci, IdentityKey peerIdentity)
        {
            if (_account is null || !Guid.TryParse(_account.Aci, out Guid me) || !Guid.TryParse(peerAci, out Guid them))
                return "(safety number unavailable)";
            string digits = SafetyNumber.GenerateForAci(me, _account.AciIdentityKeyPair.PublicKey, them, peerIdentity);
            return SafetyNumber.FormatForDisplay(digits);
        }

        // ── receive ──

        private async Task RequestSyncAsync(SignalAccount account, ISignalProtocolStore store, CancellationToken ct)
        {
            try
            {
                _rest ??= new SignalRestClient();
                var sender = new MessageSender(account, store, _rest);
                await Task.Run(() => sender.SendSyncRequestsAsync(new[]
                {
                    SyncMessage.Types.Request.Types.Type.Contacts,
                    SyncMessage.Types.Request.Types.Type.Blocked,
                    SyncMessage.Types.Request.Types.Type.Configuration,
                }, ct), ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                FileLog.Write($"sync request failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private async Task ImportHistoryAsync(SignalAccount account, CancellationToken ct)
        {
            if (account.EphemeralBackupKey is not { Length: 32 }) return;   // not a fresh link+sync
            if (_historyImportStarted) return;                              // never run two imports at once
            _historyImportStarted = true;
            _importCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            try
            {
                _rest ??= new SignalRestClient();
                var importer = new MessageHistoryImporter(account, _rest, _store, _contacts);

                MessageHistoryImporter.Result result = await Task.Run(
                    () => importer.ImportAsync(ct: _importCts.Token), _importCts.Token);

                // Clear the one-time key only on a definitive outcome (imported, or the primary truly has
                // no archive). On a transient failure (timeout/network) KEEP it so the next launch retries
                // — otherwise the one chance at history is lost forever.
                if (!result.ShouldRetry)
                {
                    account.EphemeralBackupKey = null;
                    new AccountStore().Save(account);
                }

                FileLog.Write($"history import: imported={result.Imported} retry={result.ShouldRetry} {result.Detail}");
                _dispatcher.TryEnqueue(() =>
                {
                    if (result.Imported) ReloadConversations();
                    ImportOverlay.Visibility = Visibility.Collapsed;
                });
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                // Unexpected error: keep the key (do NOT clear) so a relaunch can retry.
                FileLog.Write($"history import failed: {ex.GetType().Name}: {ex.Message}");
                _dispatcher.TryEnqueue(() => ImportOverlay.Visibility = Visibility.Collapsed);
            }
            finally
            {
                _historyImportStarted = false;
            }
        }

        /// <summary>Skip the one-time history import (the phone may never send an archive). Don't retry it.</summary>
        private void OnSkipImportClick(object sender, RoutedEventArgs e)
        {
            _importCts?.Cancel();
            ImportOverlay.Visibility = Visibility.Collapsed;
            if (_account is not null)
            {
                _account.EphemeralBackupKey = null;
                new AccountStore().Save(_account);
            }
        }

        /// <summary>Rebuilds the conversation list + current thread from the stores (after a bulk import).</summary>
        private void ReloadConversations()
        {
            _conversations.Clear();
            _byPeer.Clear();
            // Oldest-first so each top-insert leaves the most-recently-active chat on top (see OnNavigatedTo).
            foreach (Conversation c in _store.Conversations().Reverse())
                AddOrUpdateConversation(c.Peer, c.LastBody, c.LastTimestamp, c.LastOutgoing);
            if (_selectedPeer is not null && _byPeer.ContainsKey(_selectedPeer))
                SelectPeer(_selectedPeer, DisplayTitle(_selectedPeer));
            else if (_conversations.Count > 0)
                ConversationList.SelectedIndex = 0;
        }

        private int _reconnectDelayMs;
        private CancellationTokenSource? _reconnectWaitCts;

        /// <summary>Keeps the chat socket up: reconnects automatically with exponential backoff (2s→30s)
        /// whenever it drops, until cancelled.</summary>
        private async Task StartReceiveAsync(SignalAccount account, ISignalProtocolStore store, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                _dispatcher.TryEnqueue(() => SetConnection(Conn.Connecting));
                try
                {
                    var receiver = new ChatReceiver(account, store, _profileKeys, _senderKeys);
                    await Task.Run(() => receiver.ReceiveAsync(OnMessage, OnError, ct, OnSync, OnReceipt, OnTyping), ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    FileLog.Write($"receive: {ex.GetType().Name}: {ex.Message}");
                }
                if (ct.IsCancellationRequested) break;

                // Dropped — back off then reconnect automatically (Retry skips the wait).
                _reconnectDelayMs = _reconnectDelayMs == 0 ? 2000 : Math.Min(_reconnectDelayMs * 2, 30000);
                int seconds = _reconnectDelayMs / 1000;
                _dispatcher.TryEnqueue(() =>
                {
                    SetConnection(Conn.Offline);
                    ShowError($"Disconnected. Reconnecting in {seconds}s…", retry: ReconnectNow);
                });

                _reconnectWaitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                try { await Task.Delay(_reconnectDelayMs, _reconnectWaitCts.Token); }
                catch (OperationCanceledException) { if (ct.IsCancellationRequested) break; }
            }
        }

        /// <summary>"Retry" on the offline bar: skip the backoff wait and reconnect immediately.</summary>
        private void ReconnectNow()
        {
            _reconnectDelayMs = 0;
            _reconnectWaitCts?.Cancel();
        }

        private async Task OnMessage(DecryptedMessage message)
        {
            // Download + decrypt any media to a local file first (best-effort; null leaves the placeholder).
            string? mediaPath = message.Attachment is { } ptr
                ? await _attachments.SaveAsync(ptr).ConfigureAwait(false)
                : null;

            // Group messages are keyed by the group (so they form their own thread), 1:1 by the peer ACI.
            string convKey = message.GroupId is { } gid ? GroupKey(gid) : message.PeerServiceId;
            if (message.GroupId is { } g && message.GroupMasterKey is { } mk) EnsureGroupKnown(g, mk);

            var stored = new StoredMessage(convKey, message.Body, message.Timestamp, message.Outgoing)
            {
                MediaPath = mediaPath,
            };
            _store.Add(stored);

            // Acknowledge inbound 1:1 messages: READ if the thread is open in front of the user, else
            // DELIVERED. (Group messages + Note-to-Self / our own synced sends don't get 1:1 receipts.)
            if (!stored.Outgoing && !IsSelf(stored.Peer) && !IsGroupKey(stored.Peer))
            {
                bool open = stored.Peer == _selectedPeer;
                FireAndForgetSend(stored.Peer, open
                    ? Receipts.Read(stored.Timestamp)
                    : Receipts.Delivery(stored.Timestamp));
            }

            _dispatcher.TryEnqueue(() =>
            {
                _reconnectDelayMs = 0;   // healthy connection — reset backoff
                SetConnection(Conn.Connected);
                if (stored.Peer == _selectedPeer) HideTyping();   // a message ends "typing…"
                ConversationItem conv = AddOrUpdateConversation(stored.Peer, stored.Body, stored.Timestamp, stored.Outgoing);
                if (stored.Peer == _selectedPeer)
                    AppendBubble(MessageItem.From(stored));
                else if (!stored.Outgoing)
                    conv.UnreadCount++;   // only badge messages not already shown in the open thread
                UpdateUnreadBadge();

                // Heard from someone we have no name for? Re-request contacts so a newly-added contact
                // resolves to a name (debounced — the response refreshes ALL titles via OnSync).
                if (!stored.Outgoing && !IsGroupKey(stored.Peer)
                    && !string.Equals(stored.Peer, _account?.Aci, StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrEmpty(_contacts.NameFor(stored.Peer)))
                    MaybeResyncContacts();
            });
        }

        private long _lastContactsResyncTick;

        private void MaybeResyncContacts()
        {
            long now = Environment.TickCount64;
            if (now - _lastContactsResyncTick < 60_000) return;   // at most once a minute
            _lastContactsResyncTick = now;
            if (_account is null || _protocolStore is null || _cts is null) return;
            _ = RequestSyncAsync(_account, _protocolStore, _cts.Token);
        }

        /// <summary>Publishes the total unread count to the Chats rail badge.</summary>
        private void UpdateUnreadBadge() =>
            App.UnreadSink?.Invoke(_conversations.Sum(c => c.UnreadCount));

        private void OnError(Envelope envelope, Exception ex)
        {
            if (ex is UntrustedIdentityException uie)
            {
                // A contact's identity key changed — prompt to verify; the message redelivers once approved.
                FileLog.Write($"receive: untrusted identity for {uie.Address.Name}");
                OnIdentityChange(uie);
                return;
            }
            FileLog.Write($"decrypt failed ({envelope.Type}): {ex.GetType().Name}: {ex.Message}");
            _dispatcher.TryEnqueue(() => ShowError("Couldn't read an incoming message."));
        }

        private async Task OnSync(SyncMessage sync)
        {
            if (_syncProcessor is null) return;
            await _syncProcessor.ProcessAsync(sync).ConfigureAwait(false);
            // Contacts may now have names — refresh conversation titles on the UI thread.
            _dispatcher.TryEnqueue(RefreshTitles);
        }

        // ── delivery/read receipts + typing ──

        /// <summary>A peer reported they got (DELIVERY) or read (READ) our message(s). Advance the matching
        /// outgoing bubble's ✓/✓✓ — only for the open thread, since per-message statuses aren't persisted.</summary>
        private Task OnReceipt(string sender, ReceiptMessage receipt)
        {
            SendStatus status = receipt.Type == ReceiptMessage.Types.Type.Read ? SendStatus.Read : SendStatus.Delivered;
            var stamps = receipt.Timestamp.Select(t => (long)t).ToHashSet();
            _dispatcher.TryEnqueue(() =>
            {
                if (sender != _selectedPeer) return;
                foreach (MessageItem m in _messages.OfType<MessageItem>())
                    if (m.Outgoing && stamps.Contains(m.Timestamp)
                        && m.Status != SendStatus.Failed
                        && MessageItem.Rank(status) > MessageItem.Rank(m.Status))
                        m.Status = status;
            });
            return Task.CompletedTask;
        }

        /// <summary>The peer started/stopped typing — show or hide the indicator for the open thread.</summary>
        private Task OnTyping(string sender, TypingMessage typing)
        {
            bool started = typing.Action == TypingMessage.Types.Action.Started;
            _dispatcher.TryEnqueue(() =>
            {
                if (sender != _selectedPeer) return;
                if (started) ShowTyping(sender); else HideTyping();
            });
            return Task.CompletedTask;
        }

        private DispatcherTimer? _typingTimer;

        private void ShowTyping(string peer)
        {
            TypingIndicatorText.Text = $"{DisplayTitle(peer)} is typing…";
            TypingIndicator.Visibility = Visibility.Visible;
            (_typingTimer ??= CreateTypingTimer()).Stop();
            _typingTimer.Start();   // auto-clear if no STOPPED arrives (the sender went idle)
        }

        private void HideTyping()
        {
            _typingTimer?.Stop();
            TypingIndicator.Visibility = Visibility.Collapsed;
        }

        private DispatcherTimer CreateTypingTimer()
        {
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(6) };
            timer.Tick += (_, _) => HideTyping();
            return timer;
        }

        private long _lastTypingSentTick;

        /// <summary>While the user types, tell the peer (throttled to once per 5s so we don't spam).</summary>
        private void OnComposeTextChanged(object sender, TextChangedEventArgs e)
        {
            if (_selectedPeer is null || IsSelf(_selectedPeer) || string.IsNullOrEmpty(ComposeBox.Text)) return;
            long now = Environment.TickCount64;
            if (now - _lastTypingSentTick < 5000) return;
            _lastTypingSentTick = now;
            FireAndForgetSend(_selectedPeer, Receipts.Typing(started: true, now));
        }

        private bool IsSelf(string peer) =>
            string.Equals(peer, _account?.Aci, StringComparison.OrdinalIgnoreCase);

        /// <summary>Sends a sideband Content (receipt/typing) to a peer, best-effort and off the UI thread.
        /// Never surfaces errors — these are advisory and must not disrupt the conversation.</summary>
        private void FireAndForgetSend(string peer, Content content)
        {
            if (_account is null || _protocolStore is null) return;
            SignalAccount account = _account;
            SqliteSignalProtocolStore store = _protocolStore;
            _ = Task.Run(async () =>
            {
                try
                {
                    _rest ??= new SignalRestClient();
                    var sender = new MessageSender(account, store, _rest, _profileKeys);
                    long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    await sender.SendContentAsync(peer, content, ts).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    FileLog.Write($"sideband: send to {peer} failed {ex.GetType().Name}: {ex.Message}");
                }
            });
        }

        private void RefreshTitles()
        {
            foreach (ConversationItem item in _conversations)
                item.Title = DisplayTitle(item.Peer);
            if (_selectedPeer is not null)
            {
                string title = DisplayTitle(_selectedPeer);
                ThreadTitle.Text = title;
                ThreadAvatarText.Text = title.Length > 0 ? title[..1].ToUpperInvariant() : "?";
            }
        }

        // ── thread helpers ──

        /// <summary>Appends a bubble to the open thread (with a day divider + grouping) and scrolls.</summary>
        private void AppendBubble(MessageItem item)
        {
            ThreadEmptyHint.Visibility = Visibility.Collapsed;
            AddMessageItem(item);
            ScrollToBottom();
        }

        // Group consecutive same-sender messages sent within this window (tight spacing, one timestamp).
        private const long GroupWindowMs = 3 * 60 * 1000;

        /// <summary>Adds a bubble with a day divider when the day changes, and grouping vs. the previous
        /// bubble: continuations get tight spacing, and only the last bubble of a group keeps its timestamp.</summary>
        private void AddMessageItem(MessageItem item)
        {
            MaybeAddDaySeparator(item.Timestamp);

            MessageItem? prev = _messages.OfType<MessageItem>().LastOrDefault();
            bool continues = prev is not null
                && prev.Outgoing == item.Outgoing
                && SameLocalDay(prev.Timestamp, item.Timestamp)
                && item.Timestamp - prev.Timestamp <= GroupWindowMs;

            item.IsContinuation = continues;
            if (continues) prev!.ShowCaption = false;   // the newest message in a group carries the time
            _messages.Add(item);
        }

        private static bool SameLocalDay(long a, long b) =>
            DateTimeOffset.FromUnixTimeMilliseconds(a).LocalDateTime.Date ==
            DateTimeOffset.FromUnixTimeMilliseconds(b).LocalDateTime.Date;

        private void MaybeAddDaySeparator(long timestamp)
        {
            DateTime day = DateTimeOffset.FromUnixTimeMilliseconds(timestamp).LocalDateTime.Date;
            if (_lastShownDay != day)
            {
                _messages.Add(DaySeparatorItem.For(day));
                _lastShownDay = day;
            }
        }

        /// <summary>Scrolls the message list to the newest (last) item.</summary>
        private void ScrollToBottom()
        {
            if (_messages.Count == 0) return;
            // Defer so the ListView has laid out the freshly-added/loaded items first.
            _dispatcher.TryEnqueue(DispatcherQueuePriority.Low,
                () => { if (_messages.Count > 0) MessageList.ScrollIntoView(_messages[^1]); });
        }

        // ── status / errors ──

        private void SetConnection(Conn state)
        {
            (string text, string brushKey) = state switch
            {
                Conn.Connected => ("Connected", "SystemFillColorSuccessBrush"),
                Conn.Offline => ("Offline", "SystemFillColorCriticalBrush"),
                _ => ("Connecting…", "SystemFillColorCautionBrush"),
            };
            StatusText.Text = text;
            if (Application.Current.Resources[brushKey] is Brush brush)
                ConnectionDot.Fill = brush;
        }

        private void ShowError(string message, Action? retry = null)
        {
            ErrorBar.Title = "";
            ErrorBar.Message = message;
            _retryAction = retry;
            RetryButton.Visibility = retry is null ? Visibility.Collapsed : Visibility.Visible;
            ErrorBar.IsOpen = true;
        }

        /// <summary>Contact name if we've synced one, else "Note to Self"/shortened ACI.</summary>
        private string DisplayTitle(string peer)
        {
            if (IsGroupKey(peer))
            {
                string gid = peer["group:".Length..];
                string? title = _groups.Load(gid)?.Group.Title;
                return string.IsNullOrWhiteSpace(title) ? $"Group {gid[..Math.Min(8, gid.Length)]}" : title;
            }
            string? name = _contacts.NameFor(peer);
            return string.IsNullOrWhiteSpace(name)
                ? ConversationItem.TitleFor(peer, _account?.Aci ?? "")
                : name;
        }

        // ── GroupsV2 conversation helpers ──

        private static string GroupKey(string groupIdHex) => "group:" + groupIdHex;
        private static bool IsGroupKey(string peer) => peer.StartsWith("group:", StringComparison.Ordinal);

        /// <summary>Records a newly-seen group (its master key) so it persists + can later be fetched/named
        /// from the storage service. Stores an empty placeholder state until that fetch fills in title/roster.</summary>
        private void EnsureGroupKnown(string groupId, byte[] masterKey)
        {
            try
            {
                if (_groups.Load(groupId) is not null) return;
                _groups.Save(groupId, masterKey, new Wingnal.Service.Groups.DecryptedGroup(
                    Title: "", Description: null, Revision: 0,
                    Members: new List<Wingnal.Service.Groups.DecryptedGroupMember>()));
            }
            catch { /* best-effort; a missing group row just shows the short-id title */ }
        }

        // ── conversation-list helpers ──

        /// <summary>Ensures a conversation row exists for <paramref name="peer"/>, refreshes its preview
        /// and moves it to the top (most-recent-first). Must run on the UI thread.</summary>
        private ConversationItem AddOrUpdateConversation(string peer, string preview, long timestamp, bool outgoing)
        {
            if (!_byPeer.TryGetValue(peer, out ConversationItem? item))
            {
                item = new ConversationItem
                {
                    Peer = peer,
                    Title = DisplayTitle(peer),
                };
                _byPeer[peer] = item;
                _conversations.Insert(0, item);
            }

            if (timestamp >= item.LastTimestamp)
            {
                if (preview.Length > 0) item.Preview = (outgoing ? "You: " : "") + preview;
                item.LastTimestamp = timestamp;

                int idx = _conversations.IndexOf(item);
                if (idx > 0) _conversations.Move(idx, 0);
            }
            return item;
        }
    }
}
