using Google.Protobuf;
using Wingnal.Protocol.ZkGroup;
using Wingnal.Service.Account;
using Wingnal.Service.Groups;
using Wingnal.Service.Protos.Groups;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// GV2 Phase F gate: applying a <c>GroupChange.Actions</c> delta to a decrypted group state (add / remove /
/// promote members, role + title changes) yields the expected roster + revision, decrypting the change's
/// encrypted fields with the group secret params. Plus a GroupStore persistence round-trip. Offline.
/// </summary>
public class GroupChangeTests
{
    private static GroupSecretParams Gsp()
    {
        var mk = new byte[32];
        for (int i = 0; i < 32; i++) mk[i] = (byte)(i * 3 + 5);
        return GroupSecretParams.DeriveFromMasterKey(mk);
    }

    private static ServiceId Aci(string guid) =>
        ServiceId.Aci(Guid.Parse(guid).ToByteArray(bigEndian: true));

    private const string Alice = "11111111-1111-1111-1111-111111111111";
    private const string Bob = "22222222-2222-2222-2222-222222222222";
    private const string Carol = "33333333-3333-3333-3333-333333333333";

    [Fact]
    public void Apply_AddRemoveModifyRole_AndTitle()
    {
        var gsp = Gsp();
        var baseGroup = new DecryptedGroup("Old Title", null, 4, new List<DecryptedGroupMember>
        {
            new(Alice, false, GroupMemberRole.Administrator, 0),
            new(Bob, false, GroupMemberRole.Default, 1),
        });

        byte[] newTitle = gsp.EncryptBlobWithPadding(
            new byte[32], new GroupAttributeBlob { Title = "New Title" }.ToByteArray(), 0);

        var actions = new GroupChange.Types.Actions
        {
            Version = 5,
            AddMembers =
            {
                new GroupChange.Types.Actions.Types.AddMemberAction
                {
                    Added = new Member
                    {
                        UserId = ByteString.CopyFrom(gsp.EncryptServiceId(Aci(Carol)).Serialize()),
                        Role = Member.Types.Role.Default,
                    },
                },
            },
            DeleteMembers =
            {
                new GroupChange.Types.Actions.Types.DeleteMemberAction
                { DeletedUserId = ByteString.CopyFrom(gsp.EncryptServiceId(Aci(Bob)).Serialize()) },
            },
            ModifyMemberRoles =
            {
                new GroupChange.Types.Actions.Types.ModifyMemberRoleAction
                {
                    UserId = ByteString.CopyFrom(gsp.EncryptServiceId(Aci(Alice)).Serialize()),
                    Role = Member.Types.Role.Default,
                },
            },
            ModifyTitle = new GroupChange.Types.Actions.Types.ModifyTitleAction
            { Title = ByteString.CopyFrom(newTitle) },
        };

        DecryptedGroup result = GroupChangeApplier.Apply(baseGroup, actions, gsp);

        Assert.Equal(5u, result.Revision);
        Assert.Equal("New Title", result.Title);
        Assert.DoesNotContain(result.Members, m => m.ServiceId == Bob);          // removed
        Assert.Contains(result.Members, m => m.ServiceId == Carol);             // added
        Assert.Equal(GroupMemberRole.Default,
            result.Members.Single(m => m.ServiceId == Alice).Role);            // demoted
        Assert.Equal(5u, result.Members.Single(m => m.ServiceId == Carol).JoinedAtRevision);
    }

    [Fact]
    public void GroupStore_PersistsAndReloads()
    {
        string path = Path.Combine(Path.GetTempPath(), $"wingnal-groups-{Guid.NewGuid():N}.db");
        try
        {
            var cipher = new LocalCipher(new byte[32]);
            var store = new GroupStore(path, cipher);
            var mk = new byte[32];
            for (int i = 0; i < 32; i++) mk[i] = (byte)i;
            var group = new DecryptedGroup("My Group", "desc", 7, new List<DecryptedGroupMember>
            {
                new(Alice, false, GroupMemberRole.Administrator, 0),
            });

            store.Save("abc123", mk, group);

            StoredGroup? loaded = new GroupStore(path, cipher).Load("abc123");
            Assert.NotNull(loaded);
            Assert.Equal(mk, loaded!.MasterKey);
            Assert.Equal("My Group", loaded.Group.Title);
            Assert.Equal(7u, loaded.Group.Revision);
            Assert.Single(loaded.Group.Members);
            Assert.Equal(Alice, loaded.Group.Members[0].ServiceId);
            Assert.Equal(GroupMemberRole.Administrator, loaded.Group.Members[0].Role);
            Assert.Contains("abc123", new GroupStore(path, cipher).AllGroupIds());
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
