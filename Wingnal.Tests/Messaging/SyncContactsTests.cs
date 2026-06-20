using System.Text;
using Google.Protobuf;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Offline validation of contacts sync: a synthetic contacts blob (the DeviceContacts stream format —
/// length-delimited ContactDetails records with inline avatar bytes) parses correctly and imports into
/// the ContactsStore so conversations can be named.
/// </summary>
public class SyncContactsTests
{
    private static ContactsStore TempStore() =>
        new(Path.Combine(Path.GetTempPath(), "wingnal-contacts-" + Guid.NewGuid().ToString("N") + ".db"));

    private static byte[] BuildBlob(out byte[] avatarBytes)
    {
        avatarBytes = Encoding.UTF8.GetBytes("FAKE-JPEG-BYTES");

        var alice = new ContactDetails
        {
            Aci = "11111111-1111-1111-1111-111111111111",
            Number = "+15555550101",
            Name = "Alice Example",
            InboxPosition = 0,
        };
        var bob = new ContactDetails
        {
            Aci = "22222222-2222-2222-2222-222222222222",
            Number = "+15555550102",
            Name = "Bob Example",
            InboxPosition = 1,
            Avatar = new ContactDetails.Types.Avatar { ContentType = "image/jpeg", Length = (uint)avatarBytes.Length },
        };

        using var ms = new MemoryStream();
        alice.WriteDelimitedTo(ms);
        bob.WriteDelimitedTo(ms);
        ms.Write(avatarBytes, 0, avatarBytes.Length);  // inline avatar follows bob's record
        return ms.ToArray();
    }

    [Fact]
    public void ContactRecordStream_ParsesRecordsAndInlineAvatar()
    {
        byte[] blob = BuildBlob(out byte[] avatarBytes);

        IReadOnlyList<ContactRecord> records = ContactRecordStream.Parse(blob);

        Assert.Equal(2, records.Count);
        Assert.Equal("Alice Example", records[0].Details.Name);
        Assert.Null(records[0].Avatar);
        Assert.Equal("Bob Example", records[1].Details.Name);
        Assert.Equal(avatarBytes, records[1].Avatar);
    }

    [Fact]
    public void ImportContacts_PersistsNamesForConversationTitles()
    {
        byte[] blob = BuildBlob(out _);
        ContactsStore store = TempStore();
        var processor = new SyncProcessor(store);

        int imported = processor.ImportContacts(blob);

        Assert.Equal(2, imported);
        Assert.Equal("Alice Example", store.NameFor("11111111-1111-1111-1111-111111111111"));
        Assert.Equal("Bob Example", store.NameFor("22222222-2222-2222-2222-222222222222"));
        Assert.Equal(2, store.All().Count);
    }
}
