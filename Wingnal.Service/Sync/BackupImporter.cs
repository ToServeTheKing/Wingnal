using Google.Protobuf;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos.Backup;
using BackupContact = Wingnal.Service.Protos.Backup.Contact;
using StoreContact = Wingnal.Service.Account.Contact;

namespace Wingnal.Service.Sync;

/// <summary>
/// Imports a decrypted Signal Backup into Wingnal's stores: 1:1 <see cref="Contact"/> recipients become
/// named contacts (<see cref="ContactsStore"/>) and each text <see cref="ChatItem"/> becomes a stored
/// message (<see cref="MessageStore"/>) in the right peer's thread. Group/story/call frames and
/// non-text message types are skipped (1:1 text history is the goal — see docs/SYNC.md). Pure (no
/// network), so it's offline-testable end-to-end.
/// </summary>
public sealed class BackupImporter
{
    private readonly MessageStore _messages;
    private readonly ContactsStore _contacts;
    private readonly string _ownAci;

    public BackupImporter(MessageStore messages, ContactsStore contacts, string ownAci)
    {
        _messages = messages;
        _contacts = contacts;
        _ownAci = ownAci.ToLowerInvariant();
    }

    public sealed record ImportSummary(int Contacts, int Messages);

    /// <summary>One conversational peer resolved from a Recipient frame.</summary>
    private sealed record ResolvedPeer(string ServiceId, string? Name);

    public ImportSummary Import(BackupContents backup) => Import(backup.Frames);

    public ImportSummary Import(IReadOnlyList<Frame> frames)
    {
        // Pass 1: recipientId -> peer (only 1:1 contacts + self are conversational here).
        var recipients = new Dictionary<ulong, ResolvedPeer>();
        int contactCount = 0;
        foreach (Frame f in frames)
        {
            if (f.ItemCase != Frame.ItemOneofCase.Recipient) continue;
            Recipient r = f.Recipient;

            switch (r.DestinationCase)
            {
                case Recipient.DestinationOneofCase.Self:
                    recipients[r.Id] = new ResolvedPeer(_ownAci, "Note to Self");
                    break;
                case Recipient.DestinationOneofCase.Contact:
                    string? aci = AciFromBinary(r.Contact.HasAci ? r.Contact.Aci : ByteString.Empty);
                    if (aci is null) break; // ACI-less (e164-only) contact: can't key a 1:1 thread
                    string? name = NameOf(r.Contact);
                    recipients[r.Id] = new ResolvedPeer(aci, name);
                    string? number = r.Contact.E164 != 0 ? "+" + r.Contact.E164 : null;
                    _contacts.Upsert(new StoreContact(aci, number, name, InboxPosition: 0));
                    contactCount++;
                    break;
                default:
                    break; // group / distribution list / call link / release notes — not a 1:1 thread
            }
        }

        // Pass 2: chatId -> recipientId.
        var chatToRecipient = new Dictionary<ulong, ulong>();
        foreach (Frame f in frames)
            if (f.ItemCase == Frame.ItemOneofCase.Chat)
                chatToRecipient[f.Chat.Id] = f.Chat.RecipientId;

        // Pass 3: text chat items -> stored messages. Skip any we've already stored so a re-import (or a
        // retried import) doesn't duplicate history.
        HashSet<string> existing = _messages.ExistingKeys();
        int messageCount = 0;
        foreach (Frame f in frames)
        {
            if (f.ItemCase != Frame.ItemOneofCase.ChatItem) continue;
            ChatItem item = f.ChatItem;
            if (item.ItemCase != ChatItem.ItemOneofCase.StandardMessage) continue;
            string body = item.StandardMessage.Text?.Body ?? "";
            if (body.Length == 0) continue;

            if (!chatToRecipient.TryGetValue(item.ChatId, out ulong recipientId)) continue;
            if (!recipients.TryGetValue(recipientId, out ResolvedPeer? peer)) continue;

            bool outgoing = item.DirectionalDetailsCase == ChatItem.DirectionalDetailsOneofCase.Outgoing;
            long ts = (long)item.DateSent;
            string key = MessageStore.KeyOf(peer.ServiceId, ts, outgoing, body);
            if (!existing.Add(key)) continue;   // duplicate — already stored

            _messages.Add(new StoredMessage(peer.ServiceId, body, ts, outgoing));
            messageCount++;
        }

        return new ImportSummary(contactCount, messageCount);
    }

    private static string? NameOf(BackupContact c)
    {
        string? Join(string? given, string? family)
        {
            string s = string.Join(' ', new[] { given, family }.Where(p => !string.IsNullOrWhiteSpace(p)));
            return s.Length == 0 ? null : s;
        }

        return Join(c.SystemGivenName, c.SystemFamilyName)
            ?? Join(c.ProfileGivenName, c.ProfileFamilyName)
            ?? (c.Nickname is { } n ? Join(n.Given, n.Family) : null)
            ?? (string.IsNullOrWhiteSpace(c.Username) ? null : c.Username);
    }

    private static string? AciFromBinary(ByteString aci) => ServiceIds.StringFromBinary(aci.Span);
}
