using Google.Protobuf;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// GV2 Phase G2 gate: the offline 3-member send→receive loopback. The sender assembles the single group
/// ciphertext via <see cref="GroupSendBuilder"/> (encrypt-once) and distributes its SKDM; two receivers
/// install the distribution and decrypt the same ciphertext through <see cref="GroupMessageProcessor"/>,
/// recovering the body and routing to the right group id — including a late-joiner who installs the SKDM
/// only after the message was sent.
/// </summary>
public class GroupSendReceiveLoopbackTests
{
    private static readonly SignalProtocolAddress Sender = new("aaaaaaaa-0000-0000-0000-000000000001", 1);

    [Fact]
    public void EncryptOnce_TwoReceiversDecrypt_IncludingLateJoiner()
    {
        Guid distId = Guid.NewGuid();
        var masterKey = new byte[32];
        for (int i = 0; i < 32; i++) masterKey[i] = (byte)(i + 9);
        string groupId = GroupMessageProcessor.GroupIdHex(masterKey);

        // Sender: create the group sender key + the single group ciphertext.
        var senderStore = new InMemorySenderKeyStore();
        var send = new GroupSendBuilder(senderStore, Sender, distId);
        SenderKeyDistributionMessage skdm = send.CreateDistribution();

        var content = new Content
        {
            DataMessage = new DataMessage
            {
                Body = "hi everyone",
                Timestamp = 1718600001000,
                GroupV2 = new GroupContextV2 { MasterKey = ByteString.CopyFrom(masterKey), Revision = 1 },
            },
        };
        byte[] groupCiphertext = send.EncryptMessage(content);

        // Bob installs the distribution before the message; Carol (late joiner) installs it after.
        var bob = new GroupMessageProcessor(new InMemorySenderKeyStore());
        bob.ProcessDistribution(Sender, skdm.Serialize());

        AssertDecrypts(bob, groupCiphertext, "hi everyone", groupId);

        var carol = new GroupMessageProcessor(new InMemorySenderKeyStore());
        carol.ProcessDistribution(Sender, skdm.Serialize());   // late joiner gets the same SKDM
        AssertDecrypts(carol, groupCiphertext, "hi everyone", groupId);
    }

    private static void AssertDecrypts(GroupMessageProcessor member, byte[] groupCiphertext, string body, string groupId)
    {
        byte[] padded = member.DecryptGroupMessage(Sender, groupCiphertext);
        var content = Content.Parser.ParseFrom(MessagePadding.Strip(padded));
        Assert.Equal(body, content.DataMessage.Body);
        Assert.Equal(groupId, GroupMessageProcessor.GroupIdHex(content.DataMessage.GroupV2.MasterKey.ToByteArray()));
    }
}
