using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Keys;
using Xunit;

namespace Wingnal.Tests.Identity;

/// <summary>
/// Verifies trust-on-first-use + identity-change blocking: a new key for a known address is rejected
/// (UntrustedIdentityException) until the user approves it (overwrites the stored key).
/// </summary>
public class IdentityTrustTests
{
    private static readonly SignalProtocolAddress Peer = new("bbbbbbbb-1111-2222-3333-444444444444", 1);

    [Fact]
    public void FirstUseTrusted_ChangedKeyUntrusted_UntilApproved()
    {
        SignalAccount me = BuildAccount();
        var store = new AccountProtocolStore(me);

        IdentityKey original = IdentityKeyPair.Generate().PublicKey;
        IdentityKey rotated = IdentityKeyPair.Generate().PublicKey;

        Assert.True(store.IsTrustedIdentity(Peer, original));   // nothing stored yet → trusted
        store.SaveIdentity(Peer, original);
        Assert.True(store.IsTrustedIdentity(Peer, original));   // same key → trusted
        Assert.False(store.IsTrustedIdentity(Peer, rotated));   // different key → NOT trusted

        store.SaveIdentity(Peer, rotated);                      // user approves the new key
        Assert.True(store.IsTrustedIdentity(Peer, rotated));
    }

    [Fact]
    public void SessionBuilder_RejectsUntrustedIdentity()
    {
        SignalAccount me = BuildAccount();
        var store = new AccountProtocolStore(me);

        IdentityKey trusted = IdentityKeyPair.Generate().PublicKey;
        store.SaveIdentity(Peer, trusted);

        // A bundle arrives for the same peer but with a DIFFERENT identity key → must be rejected before
        // any session is built (the trust check runs before signature validation).
        IdentityKey attacker = IdentityKeyPair.Generate().PublicKey;
        var bundle = new PreKeyBundle(
            registrationId: 1, deviceId: 1, preKeyId: null, preKeyPublic: null,
            signedPreKeyId: 1, signedPreKeyPublic: Curve25519.GenerateKeyPair().PublicKey,
            signedPreKeySignature: new byte[64], identityKey: attacker);

        var builder = new SessionBuilder(store, store, store, store, store, Peer);
        Assert.Throws<UntrustedIdentityException>(() => builder.Process(bundle));
    }

    private static SignalAccount BuildAccount()
    {
        IdentityKeyPair aci = IdentityKeyPair.Generate();
        IdentityKeyPair pni = IdentityKeyPair.Generate();
        SignedPreKeyRecord signed = PreKeyHelper.GenerateSignedPreKey(aci.PrivateKey, 1);
        KyberPreKeyRecord kyber = PreKeyHelper.GenerateKyberPreKey(aci.PrivateKey, 1);
        return new SignalAccount
        {
            Aci = "aaaaaaaa-0000-0000-0000-000000000000",
            Pni = "00000000-0000-0000-0000-0000000000ff",
            Number = "+15555550100",
            DeviceId = 2,
            Password = "pw",
            AciRegistrationId = 1234,
            PniRegistrationId = 5678,
            AciIdentityPublic = aci.PublicKey.Serialize(),
            AciIdentityPrivate = aci.PrivateKey,
            PniIdentityPublic = pni.PublicKey.Serialize(),
            PniIdentityPrivate = pni.PrivateKey,
            ProfileKey = RandomNumberGenerator.GetBytes(32),
            AciPreKeys = Material(signed, kyber),
            PniPreKeys = Material(signed, kyber),
        };
    }

    private static RegisteredPreKeys Material(SignedPreKeyRecord signed, KyberPreKeyRecord kyber) => new()
    {
        SignedPreKeyId = signed.Id,
        SignedPreKeyPublic = signed.KeyPair.PublicKey,
        SignedPreKeyPrivate = signed.KeyPair.PrivateKey,
        SignedPreKeySignature = signed.Signature,
        KyberPreKeyId = kyber.Id,
        KyberPreKeyPublic = kyber.KeyPair.PublicKey,
        KyberPreKeyPrivate = kyber.KeyPair.PrivateKey,
        KyberPreKeySignature = kyber.Signature,
    };
}
