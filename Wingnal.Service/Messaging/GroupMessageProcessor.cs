using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;
using Wingnal.Protocol.ZkGroup;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Phase G1 (receive-only groups): wires the Sender Key messaging primitive into the receive path. Processes
/// an inbound Sender Key Distribution Message (so we can decrypt that sender's future group messages),
/// decrypts an inbound group Sender Key message to its plaintext <c>Content</c>, and derives the 32-byte
/// group identifier from a group master key (to route the message into the right group thread). No zkgroup
/// credential machinery is needed to *receive* — only the group-id derivation (<see cref="GroupSecretParams"/>).
/// </summary>
public sealed class GroupMessageProcessor
{
    private readonly GroupSessionBuilder _builder;
    private readonly GroupSessionCipher _cipher;

    public GroupMessageProcessor(ISenderKeyStore store)
    {
        _builder = new GroupSessionBuilder(store);
        _cipher = new GroupSessionCipher(store);
    }

    /// <summary>Installs a sender's distribution (their sender key) so their group messages can be decrypted.</summary>
    public void ProcessDistribution(SignalProtocolAddress sender, byte[] skdmBytes) =>
        _builder.Process(sender, SenderKeyDistributionMessage.Parse(skdmBytes));

    /// <summary>Decrypts a received group Sender Key message to its (still padding-wrapped) plaintext.</summary>
    public byte[] DecryptGroupMessage(SignalProtocolAddress sender, byte[] senderKeyMessageBytes) =>
        _cipher.Decrypt(sender, SenderKeyMessage.Parse(senderKeyMessageBytes));

    /// <summary>The lowercase-hex group identifier derived from a 32-byte group master key
    /// (<c>GroupContextV2.masterKey</c>), used to key a group conversation.</summary>
    public static string GroupIdHex(byte[] masterKey) =>
        Convert.ToHexString(GroupSecretParams.DeriveFromMasterKey(masterKey).GroupIdentifier).ToLowerInvariant();
}
