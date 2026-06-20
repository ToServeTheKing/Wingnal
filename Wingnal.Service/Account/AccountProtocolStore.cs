using System.Linq;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Service.Account;

/// <summary>
/// Signal protocol store for the linked account, seeded from the persisted <see cref="SignalAccount"/>
/// (ACI identity + the signed/kyber prekeys registered at link time). Sessions and learned remote
/// identities live in memory for the process lifetime (see SHORTCUTS.md: not yet persisted across runs).
/// </summary>
public sealed class AccountProtocolStore : ISignalProtocolStore
{
    private readonly IdentityKeyPair _identityKeyPair;
    private readonly uint _registrationId;
    private readonly Dictionary<SignalProtocolAddress, IdentityKey> _identities = new();
    private readonly Dictionary<uint, PreKeyRecord> _preKeys = new();
    private readonly Dictionary<uint, SignedPreKeyRecord> _signedPreKeys = new();
    private readonly Dictionary<uint, KyberPreKeyRecord> _kyberPreKeys = new();
    private readonly Dictionary<SignalProtocolAddress, SessionRecord> _sessions = new();
    private readonly SignalAccount _account;
    private readonly Action? _onChanged;

    /// <param name="onChanged">Invoked after a one-time prekey is consumed (removed from
    /// <see cref="SignalAccount.AciOneTimePreKeys"/>) so the caller can re-persist the account. Null =
    /// no persistence (tests / ephemeral use).</param>
    public AccountProtocolStore(SignalAccount account, Action? onChanged = null)
    {
        _account = account;
        _onChanged = onChanged;
        _identityKeyPair = account.AciIdentityKeyPair;
        _registrationId = account.AciRegistrationId;

        RegisteredPreKeys pk = account.AciPreKeys;
        _signedPreKeys[pk.SignedPreKeyId] = new SignedPreKeyRecord(
            pk.SignedPreKeyId,
            new ECKeyPair(pk.SignedPreKeyPrivate, pk.SignedPreKeyPublic),
            pk.SignedPreKeySignature, timestamp: 0);
        _kyberPreKeys[pk.KyberPreKeyId] = new KyberPreKeyRecord(
            pk.KyberPreKeyId,
            new KyberKeyPair(pk.KyberPreKeyPublic, pk.KyberPreKeyPrivate),
            pk.KyberPreKeySignature, timestamp: 0);

        foreach (OneTimePreKey otp in account.AciOneTimePreKeys)
            _preKeys[otp.Id] = new PreKeyRecord(otp.Id, new ECKeyPair(otp.Private, otp.Public));
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

    public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identity)
    {
        if (!_identities.TryGetValue(address, out IdentityKey? existing)) return true; // first use
        return existing!.PublicKey.AsSpan().SequenceEqual(identity.PublicKey);
    }

    public IdentityKey? GetIdentity(SignalProtocolAddress address) =>
        _identities.TryGetValue(address, out IdentityKey? id) ? id : null;

    public PreKeyRecord LoadPreKey(uint preKeyId) => _preKeys[preKeyId];
    public void StorePreKey(uint preKeyId, PreKeyRecord record) => _preKeys[preKeyId] = record;
    public bool ContainsPreKey(uint preKeyId) => _preKeys.ContainsKey(preKeyId);
    public void RemovePreKey(uint preKeyId)
    {
        _preKeys.Remove(preKeyId);
        // Persist consumption: a used one-time prekey must never be reused.
        int removed = _account.AciOneTimePreKeys.RemoveAll(k => k.Id == preKeyId);
        if (removed > 0) _onChanged?.Invoke();
    }

    public SignedPreKeyRecord LoadSignedPreKey(uint id) => _signedPreKeys[id];
    public void StoreSignedPreKey(uint id, SignedPreKeyRecord record) => _signedPreKeys[id] = record;
    public bool ContainsSignedPreKey(uint id) => _signedPreKeys.ContainsKey(id);

    public KyberPreKeyRecord LoadKyberPreKey(uint id) => _kyberPreKeys[id];
    public void StoreKyberPreKey(uint id, KyberPreKeyRecord record) => _kyberPreKeys[id] = record;
    public bool ContainsKyberPreKey(uint id) => _kyberPreKeys.ContainsKey(id);
    public void MarkKyberPreKeyUsed(uint id) { /* last-resort key: kept */ }

    public SessionRecord LoadSession(SignalProtocolAddress address) =>
        _sessions.TryGetValue(address, out SessionRecord? record) ? record : new SessionRecord();
    public bool ContainsSession(SignalProtocolAddress address) => _sessions.ContainsKey(address);
    public void StoreSession(SignalProtocolAddress address, SessionRecord record) => _sessions[address] = record;
    public void DeleteSession(SignalProtocolAddress address) => _sessions.Remove(address);

    /// <summary>Device ids of <paramref name="name"/> that already have an established session — used to
    /// reuse active sessions on send (Sesame) instead of re-fetching a prekey bundle every time.</summary>
    public IReadOnlyList<uint> GetSubDeviceSessions(string name) =>
        _sessions.Keys.Where(a => a.Name == name).Select(a => a.DeviceId).ToList();
}
