using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Groups;

/// <summary>
/// Sets up sender-key sessions. The sender calls <see cref="Create"/> once per group/distribution to
/// produce a SenderKeyDistributionMessage (fanned out 1:1 to members); each member calls
/// <see cref="Process"/> on that SKDM to install a receiving state. Mirrors libsignal's
/// GroupSessionBuilder.
/// </summary>
public sealed class GroupSessionBuilder
{
    private const int MessageVersion = SenderKeyWire.CurrentVersion;

    private readonly ISenderKeyStore _store;

    public GroupSessionBuilder(ISenderKeyStore store) => _store = store;

    /// <summary>
    /// Creates (or returns) our outgoing sender-key state for <paramref name="sender"/> +
    /// <paramref name="distributionId"/> and returns the SKDM describing it. If no state exists yet,
    /// a fresh chain (random 32-byte chain key, iteration 0), a random 31-bit chain id, and a new
    /// signing key pair are generated.
    /// </summary>
    public SenderKeyDistributionMessage Create(SignalProtocolAddress sender, Guid distributionId)
    {
        SenderKeyRecord record = _store.LoadSenderKey(sender, distributionId) ?? new SenderKeyRecord();

        if (record.IsEmpty)
        {
            // 31-bit chain id (Java-compatible: top bit cleared) per libsignal.
            uint chainId = RandomUInt32() >> 1;
            byte[] chainKey = RandomNumberGenerator.GetBytes(32);
            ECKeyPair signingKey = Curve25519.GenerateKeyPair();

            record.AddState(chainId, MessageVersion, iteration: 0, chainKey,
                signingKey.PublicKey, signingKey.PrivateKey);
            _store.StoreSenderKey(sender, distributionId, record);
        }

        SenderKeyState state = record.State;
        return new SenderKeyDistributionMessage(state.MessageVersion, distributionId, state.ChainId,
            state.ChainKey.Iteration, state.ChainKey.Seed, state.SigningKeyPublic);
    }

    /// <summary>Installs the receiving state described by <paramref name="skdm"/> for the given
    /// sender + the SKDM's distribution id.</summary>
    public void Process(SignalProtocolAddress sender, SenderKeyDistributionMessage skdm)
    {
        SenderKeyRecord record = _store.LoadSenderKey(sender, skdm.DistributionId) ?? new SenderKeyRecord();
        record.AddState(skdm.ChainId, skdm.MessageVersion, skdm.Iteration, skdm.ChainKey,
            skdm.SigningKeyPublic, signingKeyPrivate: null);
        _store.StoreSenderKey(sender, skdm.DistributionId, record);
    }

    private static uint RandomUInt32() => BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
}
