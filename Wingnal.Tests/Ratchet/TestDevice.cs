using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Tests.Ratchet;

/// <summary>A test fixture representing one Signal device: its identity, stores, and the ability to
/// publish a <see cref="PreKeyBundle"/> (storing the corresponding private records locally).</summary>
internal sealed class TestDevice
{
    public InMemorySignalProtocolStore Store { get; }
    public IdentityKeyPair Identity { get; }
    public uint RegistrationId { get; }

    private uint _nextId = 1;

    public TestDevice()
    {
        Identity = IdentityKeyPair.Generate();
        RegistrationId = (uint)RandomNumberGenerator.GetInt32(1, 16384);
        Store = new InMemorySignalProtocolStore(Identity, RegistrationId);
    }

    public PreKeyBundle CreateBundle(bool includeOneTimePreKey = true, bool includeKyber = true)
    {
        uint signedPreKeyId = _nextId++;
        ECKeyPair signedPreKey = Curve25519.GenerateKeyPair();
        byte[] signedPreKeySignature = XEd25519.CalculateSignature(
            Identity.PrivateKey, Curve25519.EncodePoint(signedPreKey.PublicKey), RandomNumberGenerator.GetBytes(64));
        Store.StoreSignedPreKey(signedPreKeyId, new SignedPreKeyRecord(signedPreKeyId, signedPreKey, signedPreKeySignature, 0));

        uint? preKeyId = null;
        byte[]? preKeyPublic = null;
        if (includeOneTimePreKey)
        {
            preKeyId = _nextId++;
            PreKeyRecord preKey = PreKeyRecord.Generate(preKeyId.Value);
            Store.StorePreKey(preKeyId.Value, preKey);
            preKeyPublic = preKey.KeyPair.PublicKey;
        }

        uint? kyberPreKeyId = null;
        byte[]? kyberPreKeyPublic = null;
        byte[]? kyberPreKeySignature = null;
        if (includeKyber)
        {
            kyberPreKeyId = _nextId++;
            KyberKeyPair kyberKeyPair = Kyber.GenerateKeyPair();
            kyberPreKeySignature = XEd25519.CalculateSignature(
                Identity.PrivateKey, KemKeySerialization.Serialize(kyberKeyPair.PublicKey),
                RandomNumberGenerator.GetBytes(64));
            Store.StoreKyberPreKey(kyberPreKeyId.Value,
                new KyberPreKeyRecord(kyberPreKeyId.Value, kyberKeyPair, kyberPreKeySignature, 0));
            kyberPreKeyPublic = kyberKeyPair.PublicKey;
        }

        return new PreKeyBundle(RegistrationId, 1, preKeyId, preKeyPublic, signedPreKeyId,
            signedPreKey.PublicKey, signedPreKeySignature, Identity.PublicKey,
            kyberPreKeyId, kyberPreKeyPublic, kyberPreKeySignature);
    }
}
