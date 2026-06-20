namespace Wingnal.Protocol.State;

/// <summary>
/// Store contracts mirroring libsignal's. Implementations are in-memory (tests) or SQLite-backed
/// (app, added later). Kept synchronous to match libsignal's reference semantics.
/// </summary>
public interface IIdentityKeyStore
{
    IdentityKeyPair GetIdentityKeyPair();
    uint GetLocalRegistrationId();

    /// <summary>Stores a remote identity. Returns true if it replaced a different existing key.</summary>
    bool SaveIdentity(SignalProtocolAddress address, IdentityKey identity);

    /// <summary>Trust-on-first-use: an identity is trusted if we have none stored for the address yet,
    /// or the presented one matches what we stored. A DIFFERENT key for a known address is untrusted
    /// (until the user verifies + approves it, which overwrites the stored key via SaveIdentity).</summary>
    bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identity);

    IdentityKey? GetIdentity(SignalProtocolAddress address);
}

public interface IPreKeyStore
{
    PreKeyRecord LoadPreKey(uint preKeyId);
    void StorePreKey(uint preKeyId, PreKeyRecord record);
    bool ContainsPreKey(uint preKeyId);
    void RemovePreKey(uint preKeyId);
}

public interface ISignedPreKeyStore
{
    SignedPreKeyRecord LoadSignedPreKey(uint signedPreKeyId);
    void StoreSignedPreKey(uint signedPreKeyId, SignedPreKeyRecord record);
    bool ContainsSignedPreKey(uint signedPreKeyId);
}

public interface IKyberPreKeyStore
{
    KyberPreKeyRecord LoadKyberPreKey(uint kyberPreKeyId);
    void StoreKyberPreKey(uint kyberPreKeyId, KyberPreKeyRecord record);
    bool ContainsKyberPreKey(uint kyberPreKeyId);
    void MarkKyberPreKeyUsed(uint kyberPreKeyId);
}

public interface ISessionStore
{
    SessionRecord LoadSession(SignalProtocolAddress address);
    bool ContainsSession(SignalProtocolAddress address);
    void StoreSession(SignalProtocolAddress address, SessionRecord record);
    void DeleteSession(SignalProtocolAddress address);

    /// <summary>Device ids of <paramref name="name"/> that already have a session (for active-session
    /// reuse on send, so we avoid re-fetching a prekey bundle every time).</summary>
    IReadOnlyList<uint> GetSubDeviceSessions(string name);
}

/// <summary>The full protocol store an application provides to the session layer.</summary>
public interface ISignalProtocolStore
    : IIdentityKeyStore, IPreKeyStore, ISignedPreKeyStore, IKyberPreKeyStore, ISessionStore
{
}
