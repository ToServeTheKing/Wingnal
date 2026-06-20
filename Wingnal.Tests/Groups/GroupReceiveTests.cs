using System.Text;
using Google.Protobuf;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;
using Wingnal.Protocol.ZkGroup;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// GV2 Phase G1 gate (receive-only groups): the receive-side wiring of the Sender Key primitive. A sender
/// distributes their sender key, then sends a group <c>Content</c> (carrying a GroupContextV2 master key);
/// the receiver installs the distribution and decrypts the message, and the decryptor routes it to the
/// correct group id (derived from the master key — no zkgroup credentials needed to receive).
/// </summary>
public class GroupReceiveTests
{
    private static readonly SignalProtocolAddress Sender = new("aaaaaaaa-1111-2222-3333-444444444444", 1);

    [Fact]
    public void GroupIdHex_MatchesGroupSecretParamsDerivation()
    {
        var masterKey = new byte[32];
        for (int i = 0; i < 32; i++) masterKey[i] = (byte)i;
        string expected = Convert.ToHexString(
            GroupSecretParams.DeriveFromMasterKey(masterKey).GroupIdentifier).ToLowerInvariant();
        Assert.Equal(expected, GroupMessageProcessor.GroupIdHex(masterKey));
    }

    [Fact]
    public void DistributeThenDecrypt_RoutesToGroupThread()
    {
        Guid distId = Guid.NewGuid();
        var masterKey = new byte[32];
        for (int i = 0; i < 32; i++) masterKey[i] = (byte)(31 - i);
        string groupId = GroupMessageProcessor.GroupIdHex(masterKey);

        // Sender builds the group sender key + the wire SKDM, then encrypts a group Content.
        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);

        var content = new Content
        {
            DataMessage = new DataMessage
            {
                Body = "hello group",
                Timestamp = 1718600000000,
                GroupV2 = new GroupContextV2 { MasterKey = ByteString.CopyFrom(masterKey), Revision = 3 },
            },
        };
        byte[] plaintext = content.ToByteArray();
        byte[] senderKeyMessage = new GroupSessionCipher(senderStore).Encrypt(Sender, distId, plaintext).Serialize();

        // Receiver installs the distribution, then decrypts the group message via the processor.
        var receiverStore = new InMemorySenderKeyStore();
        var processor = new GroupMessageProcessor(receiverStore);
        processor.ProcessDistribution(Sender, skdm.Serialize());

        byte[] decrypted = processor.DecryptGroupMessage(Sender, senderKeyMessage);
        var got = Content.Parser.ParseFrom(decrypted);

        Assert.Equal("hello group", got.DataMessage.Body);
        Assert.Equal(groupId, GroupMessageProcessor.GroupIdHex(got.DataMessage.GroupV2.MasterKey.ToByteArray()));
    }
}
