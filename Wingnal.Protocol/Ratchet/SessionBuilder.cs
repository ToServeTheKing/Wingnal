using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Ratchet;

/// <summary>
/// Establishes sessions: from a fetched <see cref="PreKeyBundle"/> (initiator) or from an inbound
/// <see cref="PreKeySignalMessage"/> (responder). Verifies prekey signatures with XEdDSA.
/// </summary>
public sealed class SessionBuilder
{
    private readonly ISessionStore _sessionStore;
    private readonly IPreKeyStore _preKeyStore;
    private readonly ISignedPreKeyStore _signedPreKeyStore;
    private readonly IKyberPreKeyStore _kyberPreKeyStore;
    private readonly IIdentityKeyStore _identityStore;
    private readonly SignalProtocolAddress _remoteAddress;

    public SessionBuilder(ISessionStore sessionStore, IPreKeyStore preKeyStore,
        ISignedPreKeyStore signedPreKeyStore, IKyberPreKeyStore kyberPreKeyStore,
        IIdentityKeyStore identityStore, SignalProtocolAddress remoteAddress)
    {
        _sessionStore = sessionStore;
        _preKeyStore = preKeyStore;
        _signedPreKeyStore = signedPreKeyStore;
        _kyberPreKeyStore = kyberPreKeyStore;
        _identityStore = identityStore;
        _remoteAddress = remoteAddress;
    }

    /// <summary>Initiator: build an outgoing session from a fetched bundle.</summary>
    public void Process(PreKeyBundle bundle)
    {
        // Refuse to build a session to an identity that doesn't match the one we already trust (MITM /
        // reinstall). The caller surfaces this so the user can verify the safety number + approve.
        if (!_identityStore.IsTrustedIdentity(_remoteAddress, bundle.IdentityKey))
            throw new UntrustedIdentityException(_remoteAddress, bundle.IdentityKey);

        if (!XEd25519.VerifySignature(bundle.IdentityKey.PublicKey,
                Curve25519.EncodePoint(bundle.SignedPreKeyPublic), bundle.SignedPreKeySignature))
            throw new InvalidMessageException("invalid signed prekey signature");

        byte[]? kyberCiphertext = null, kyberSharedSecret = null;
        if (bundle.KyberPreKeyPublic is not null)
        {
            if (bundle.KyberPreKeySignature is null ||
                !XEd25519.VerifySignature(bundle.IdentityKey.PublicKey,
                    KemKeySerialization.Serialize(bundle.KyberPreKeyPublic), bundle.KyberPreKeySignature))
                throw new InvalidMessageException("invalid kyber prekey signature");

            KyberEncapsulation encapsulation = Kyber.Encapsulate(bundle.KyberPreKeyPublic);
            // The wire carries the libsignal-serialized (type-prefixed) ciphertext.
            kyberCiphertext = KemKeySerialization.Serialize(encapsulation.CipherText);
            kyberSharedSecret = encapsulation.SharedSecret;
        }

        ECKeyPair ourBaseKey = Curve25519.GenerateKeyPair();

        var parameters = new AliceParameters
        {
            OurIdentityKey = _identityStore.GetIdentityKeyPair(),
            OurBaseKey = ourBaseKey,
            TheirIdentityKey = bundle.IdentityKey,
            TheirSignedPreKey = bundle.SignedPreKeyPublic,
            TheirRatchetKey = bundle.SignedPreKeyPublic,
            TheirOneTimePreKey = bundle.PreKeyPublic,
            KyberSharedSecret = kyberSharedSecret,
        };

        SessionRecord record = _sessionStore.ContainsSession(_remoteAddress)
            ? _sessionStore.LoadSession(_remoteAddress)
            : new SessionRecord();
        record.ArchiveCurrentState();

        RatchetingSession.InitializeAlice(record.State, parameters);

        record.State.PendingPreKey = new PendingPreKey(bundle.PreKeyId, bundle.SignedPreKeyId,
            bundle.KyberPreKeyId, kyberCiphertext, ourBaseKey.PublicKey);
        record.State.LocalRegistrationId = _identityStore.GetLocalRegistrationId();
        record.State.RemoteRegistrationId = bundle.RegistrationId;

        _identityStore.SaveIdentity(_remoteAddress, bundle.IdentityKey);
        _sessionStore.StoreSession(_remoteAddress, record);
    }

    /// <summary>
    /// Responder: initialize the session from an inbound PreKeySignalMessage (mutates the given
    /// record). Returns the one-time prekey id consumed, if any, so the caller can delete it.
    /// </summary>
    public uint? Process(SessionRecord record, PreKeySignalMessage message)
    {
        if (record.State.AliceBaseKey is not null && record.State.AliceBaseKey.AsSpan().SequenceEqual(message.BaseKey))
            return null; // already processed this prekey message

        // Don't accept a session from an identity we don't trust (changed key) until the user approves.
        if (!_identityStore.IsTrustedIdentity(_remoteAddress, message.IdentityKey))
            throw new UntrustedIdentityException(_remoteAddress, message.IdentityKey);

        SignedPreKeyRecord signedPreKey = _signedPreKeyStore.LoadSignedPreKey(message.SignedPreKeyId);

        ECKeyPair? oneTimePreKey = null;
        if (message.PreKeyId.HasValue)
            oneTimePreKey = _preKeyStore.LoadPreKey(message.PreKeyId.Value).KeyPair;

        byte[]? kyberSharedSecret = null;
        if (message.KyberPreKeyId.HasValue)
        {
            KyberPreKeyRecord kyberRecord = _kyberPreKeyStore.LoadKyberPreKey(message.KyberPreKeyId.Value);
            kyberSharedSecret = Kyber.Decapsulate(kyberRecord.KeyPair.PrivateKey,
                KemKeySerialization.Deserialize(message.KyberCiphertext!));
        }

        var parameters = new BobParameters
        {
            OurIdentityKey = _identityStore.GetIdentityKeyPair(),
            OurSignedPreKey = signedPreKey.KeyPair,
            OurRatchetKey = signedPreKey.KeyPair,
            OurOneTimePreKey = oneTimePreKey,
            TheirIdentityKey = message.IdentityKey,
            TheirBaseKey = message.BaseKey,
            KyberSharedSecret = kyberSharedSecret,
        };

        record.ArchiveCurrentState();
        RatchetingSession.InitializeBob(record.State, parameters);

        record.State.LocalRegistrationId = _identityStore.GetLocalRegistrationId();
        record.State.RemoteRegistrationId = message.RegistrationId;
        record.State.AliceBaseKey = message.BaseKey;

        _identityStore.SaveIdentity(_remoteAddress, message.IdentityKey);

        if (message.KyberPreKeyId.HasValue)
            _kyberPreKeyStore.MarkKyberPreKeyUsed(message.KyberPreKeyId.Value);

        return message.PreKeyId;
    }
}
