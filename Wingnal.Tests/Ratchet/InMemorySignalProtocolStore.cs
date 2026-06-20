using System.Linq;
using Wingnal.Protocol.State;

namespace Wingnal.Tests.Ratchet;

/// <summary>In-memory implementation of all Signal protocol stores, for ratchet tests.</summary>
internal sealed class InMemorySignalProtocolStore : ISignalProtocolStore
{
    private readonly IdentityKeyPair _identityKeyPair;
    private readonly uint _registrationId;
    private readonly Dictionary<SignalProtocolAddress, IdentityKey> _identities = new();
    private readonly Dictionary<uint, PreKeyRecord> _preKeys = new();
    private readonly Dictionary<uint, SignedPreKeyRecord> _signedPreKeys = new();
    private readonly Dictionary<uint, KyberPreKeyRecord> _kyberPreKeys = new();
    private readonly Dictionary<SignalProtocolAddress, SessionRecord> _sessions = new();

    public InMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, uint registrationId)
    {
        _identityKeyPair = identityKeyPair;
        _registrationId = registrationId;
    }

    public IdentityKeyPair GetIdentityKeyPair() => _identityKeyPair;
    public uint GetLocalRegistrationId() => _registrationId;

    public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identity)
    {
        bool changed = _identities.TryGetValue(address, out IdentityKey? existing)
                       && !existing!.PublicKey.AsSpan().SequenceEqual(identity.PublicKey);
        _identities[address] = identity;
        return changed;
    }

    public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identity) =>
        !_identities.TryGetValue(address, out IdentityKey? existing)
        || existing!.PublicKey.AsSpan().SequenceEqual(identity.PublicKey);

    public IdentityKey? GetIdentity(SignalProtocolAddress address) =>
        _identities.TryGetValue(address, out IdentityKey? id) ? id : null;

    public PreKeyRecord LoadPreKey(uint preKeyId) => _preKeys[preKeyId];
    public void StorePreKey(uint preKeyId, PreKeyRecord record) => _preKeys[preKeyId] = record;
    public bool ContainsPreKey(uint preKeyId) => _preKeys.ContainsKey(preKeyId);
    public void RemovePreKey(uint preKeyId) => _preKeys.Remove(preKeyId);

    public SignedPreKeyRecord LoadSignedPreKey(uint id) => _signedPreKeys[id];
    public void StoreSignedPreKey(uint id, SignedPreKeyRecord record) => _signedPreKeys[id] = record;
    public bool ContainsSignedPreKey(uint id) => _signedPreKeys.ContainsKey(id);

    public KyberPreKeyRecord LoadKyberPreKey(uint id) => _kyberPreKeys[id];
    public void StoreKyberPreKey(uint id, KyberPreKeyRecord record) => _kyberPreKeys[id] = record;
    public bool ContainsKyberPreKey(uint id) => _kyberPreKeys.ContainsKey(id);
    public void MarkKyberPreKeyUsed(uint id) { /* last-resort keys are kept; no-op for tests */ }

    public SessionRecord LoadSession(SignalProtocolAddress address) =>
        _sessions.TryGetValue(address, out SessionRecord? record) ? record : new SessionRecord();
    public bool ContainsSession(SignalProtocolAddress address) => _sessions.ContainsKey(address);
    public void StoreSession(SignalProtocolAddress address, SessionRecord record) => _sessions[address] = record;
    public void DeleteSession(SignalProtocolAddress address) => _sessions.Remove(address);

    public IReadOnlyList<uint> GetSubDeviceSessions(string name) =>
        _sessions.Keys.Where(a => a.Name == name).Select(a => a.DeviceId).ToList();
}
