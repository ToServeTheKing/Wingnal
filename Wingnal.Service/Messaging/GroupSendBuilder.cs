using Google.Protobuf;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Phase G2 (send) crypto assembly: builds the one group ciphertext that every member decrypts. The body is
/// encrypted ONCE with our group Sender Key (<see cref="GroupSessionCipher"/>); the caller then fans the
/// resulting <c>SenderKeyMessage</c> out to each member device wrapped as sealed-sender (type 7), after
/// distributing our <c>SenderKeyDistributionMessage</c> (1:1, sealed) to members who don't have our key yet.
/// The fan-out/transport itself lives in the live send path; this type is the offline-testable core.
/// </summary>
public sealed class GroupSendBuilder
{
    private readonly SignalProtocolAddress _self;
    private readonly Guid _distributionId;
    private readonly GroupSessionBuilder _builder;
    private readonly GroupSessionCipher _cipher;

    public GroupSendBuilder(ISenderKeyStore store, SignalProtocolAddress self, Guid distributionId)
    {
        _self = self;
        _distributionId = distributionId;
        _builder = new GroupSessionBuilder(store);
        _cipher = new GroupSessionCipher(store);
    }

    /// <summary>Creates (or recreates) our sender key and returns the distribution message to send 1:1 to
    /// members so they can decrypt our group messages.</summary>
    public SenderKeyDistributionMessage CreateDistribution() => _builder.Create(_self, _distributionId);

    /// <summary>Encrypts a group <see cref="Content"/> into the wire <c>SenderKeyMessage</c> bytes that go,
    /// once, to every member device (the caller attaches the GroupContextV2 to the Content beforehand).</summary>
    public byte[] EncryptMessage(Content content)
    {
        byte[] padded = MessagePadding.Add(content.ToByteArray());
        return _cipher.Encrypt(_self, _distributionId, padded).Serialize();
    }
}
