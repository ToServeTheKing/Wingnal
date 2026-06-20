using System.Linq;
using Google.Protobuf;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos.Backup;
using Wingnal.Service.Sync;
using Xunit;

namespace Wingnal.Tests.Sync;

/// <summary>
/// End-to-end (offline) validation of the backup importer: a synthetic backup with a Self thread + a
/// 1:1 contact thread imports into the ContactsStore (names) and MessageStore (per-peer text history,
/// correct direction). Field numbers come from the vendored libsignal backup.proto, so a passing import
/// exercises the real schema.
/// </summary>
public class BackupImporterTests
{
    private const string OwnAci = "00000000-0000-0000-0000-000000000001";
    private const string AliceAci = "aaaaaaaa-1111-2222-3333-444444444444";

    private static MessageStore TempMessages() =>
        new(Path.Combine(Path.GetTempPath(), "wingnal-bkmsg-" + Guid.NewGuid().ToString("N") + ".db"));
    private static ContactsStore TempContacts() =>
        new(Path.Combine(Path.GetTempPath(), "wingnal-bkc-" + Guid.NewGuid().ToString("N") + ".db"));

    private static ByteString Aci16(string uuid) =>
        ByteString.CopyFrom(BackupKey.UuidToRfc4122(Guid.Parse(uuid)));

    [Fact]
    public void Import_PopulatesContactsAndPerPeerMessages()
    {
        // Recipients: 1 = self, 2 = Alice (contact). Chats: 100 -> self, 200 -> Alice.
        var frames = new List<Frame>
        {
            new() { Recipient = new Recipient { Id = 1, Self = new Self() } },
            new()
            {
                Recipient = new Recipient
                {
                    Id = 2,
                    Contact = new Wingnal.Service.Protos.Backup.Contact
                    {
                        Aci = Aci16(AliceAci),
                        SystemGivenName = "Alice",
                        SystemFamilyName = "Example",
                        E164 = 15555550101,
                    },
                },
            },
            new() { Chat = new Chat { Id = 100, RecipientId = 1 } },
            new() { Chat = new Chat { Id = 200, RecipientId = 2 } },
            // Note to Self.
            new() { ChatItem = TextItem(chatId: 100, authorId: 1, dateSent: 1000, "note to self", outgoing: true) },
            // 1:1 with Alice: she sends one, we reply.
            new() { ChatItem = TextItem(chatId: 200, authorId: 2, dateSent: 2000, "hi from alice", outgoing: false) },
            new() { ChatItem = TextItem(chatId: 200, authorId: 1, dateSent: 2001, "hey alice", outgoing: true) },
            // A non-text item is ignored.
            new() { ChatItem = new ChatItem { ChatId = 200, AuthorId = 1, DateSent = 2002,
                Outgoing = new ChatItem.Types.OutgoingMessageDetails(),
                RemoteDeletedMessage = new RemoteDeletedMessage() } },
        };

        MessageStore messages = TempMessages();
        ContactsStore contacts = TempContacts();
        var importer = new BackupImporter(messages, contacts, OwnAci);

        BackupImporter.ImportSummary summary = importer.Import(frames);

        Assert.Equal(1, summary.Contacts);
        Assert.Equal(3, summary.Messages);   // remote-deleted item skipped

        // Contact name persisted.
        Assert.Equal("Alice Example", contacts.NameFor(AliceAci));

        // Per-peer threads.
        var selfThread = messages.Recent(OwnAci);
        Assert.Single(selfThread);
        Assert.Equal("note to self", selfThread[0].Body);
        Assert.True(selfThread[0].Outgoing);

        var aliceThread = messages.Recent(AliceAci).ToList();
        Assert.Equal(new[] { "hi from alice", "hey alice" }, aliceThread.Select(m => m.Body).ToArray());
        Assert.False(aliceThread[0].Outgoing);   // incoming
        Assert.True(aliceThread[1].Outgoing);    // our reply
    }

    [Fact]
    public void Import_IsIdempotent_NoDuplicatesOnReimport()
    {
        var frames = new List<Frame>
        {
            new() { Recipient = new Recipient { Id = 1, Self = new Self() } },
            new() { Chat = new Chat { Id = 100, RecipientId = 1 } },
            new() { ChatItem = TextItem(100, 1, 1000, "note one", outgoing: true) },
            new() { ChatItem = TextItem(100, 1, 1001, "note two", outgoing: true) },
        };

        MessageStore messages = TempMessages();
        ContactsStore contacts = TempContacts();
        var importer = new BackupImporter(messages, contacts, OwnAci);

        BackupImporter.ImportSummary first = importer.Import(frames);
        BackupImporter.ImportSummary second = importer.Import(frames);   // same archive again

        Assert.Equal(2, first.Messages);
        Assert.Equal(0, second.Messages);                  // nothing re-added
        Assert.Equal(2, messages.Recent(OwnAci).Count);    // still just two
    }

    private static ChatItem TextItem(ulong chatId, ulong authorId, ulong dateSent, string body, bool outgoing)
    {
        var item = new ChatItem
        {
            ChatId = chatId,
            AuthorId = authorId,
            DateSent = dateSent,
            StandardMessage = new StandardMessage { Text = new Text { Body = body } },
        };
        if (outgoing) item.Outgoing = new ChatItem.Types.OutgoingMessageDetails();
        else item.Incoming = new ChatItem.Types.IncomingMessageDetails { DateReceived = dateSent };
        return item;
    }
}
