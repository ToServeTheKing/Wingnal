using Google.Protobuf;
using Wingnal.Protocol.ZkGroup;
using Wingnal.Service.Groups;
using Wingnal.Service.Protos.Groups;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// GV2 Phase E gate (read path): a storage-service <c>Group</c> blob encrypted under a group's secret params
/// decodes back to the plaintext title + roster. Exercises the full member-hiding ciphertext layer (UID
/// ciphertext decrypt) + the AES-256-GCM-SIV title blob through the real codec. Offline.
/// </summary>
public class GroupStateCodecTests
{
    [Fact]
    public void Decode_RecoversTitleAndRoster()
    {
        var masterKey = new byte[32];
        for (int i = 0; i < 32; i++) masterKey[i] = (byte)(i * 7 + 1);
        var gsp = GroupSecretParams.DeriveFromMasterKey(masterKey);

        var alice = ServiceId.Aci(Guid.Parse("11111111-2222-3333-4444-555555555555").ToByteArray(bigEndian: true));
        var bob = ServiceId.Aci(Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa").ToByteArray(bigEndian: true));

        byte[] titleBlob = gsp.EncryptBlobWithPadding(
            new byte[32], new GroupAttributeBlob { Title = "Team Wingnal" }.ToByteArray(), 0);

        var group = new Group
        {
            PublicKey = ByteString.CopyFrom(gsp.PublicParamsSerialized()),
            Title = ByteString.CopyFrom(titleBlob),
            Version = 5,
            Members =
            {
                new Member { UserId = ByteString.CopyFrom(gsp.EncryptServiceId(alice).Serialize()),
                    Role = Member.Types.Role.Administrator, JoinedAtVersion = 0 },
                new Member { UserId = ByteString.CopyFrom(gsp.EncryptServiceId(bob).Serialize()),
                    Role = Member.Types.Role.Default, JoinedAtVersion = 3 },
            },
        };

        DecryptedGroup decoded = GroupStateCodec.Decode(group, gsp);

        Assert.Equal("Team Wingnal", decoded.Title);
        Assert.Equal(5u, decoded.Revision);
        Assert.Equal(2, decoded.Members.Count);
        Assert.Equal("11111111-2222-3333-4444-555555555555", decoded.Members[0].ServiceId);
        Assert.Equal(GroupMemberRole.Administrator, decoded.Members[0].Role);
        Assert.Equal("66666666-7777-8888-9999-aaaaaaaaaaaa", decoded.Members[1].ServiceId);
        Assert.Equal(GroupMemberRole.Default, decoded.Members[1].Role);
        Assert.Equal(3u, decoded.Members[1].JoinedAtRevision);
    }

    [Fact]
    public void AuthHeader_IsBasicBase64OfHexUserAndPassword()
    {
        byte[] pub = { 0xAB, 0xCD };
        byte[] pres = { 0x01, 0x02, 0x03 };
        string header = Wingnal.Service.Groups.GroupsApiClient.AuthHeader(pub, pres);
        // base64("abcd:010203")
        Assert.Equal(Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("abcd:010203")), header);
    }
}
