using Wingnal.Protocol.Curve;

namespace Wingnal.Protocol.State;

/// <summary>Identifies a remote party + device, e.g. ("+15551234567" or an ACI uuid, deviceId).</summary>
public readonly record struct SignalProtocolAddress(string Name, uint DeviceId);

/// <summary>A public identity key (long-term Curve25519 key used for X3DH and signatures).</summary>
public sealed class IdentityKey
{
    /// <summary>Raw 32-byte Montgomery public key.</summary>
    public byte[] PublicKey { get; }

    public IdentityKey(byte[] publicKey) => PublicKey = publicKey;

    /// <summary>33-byte DjbECPublicKey serialization (0x05 || u).</summary>
    public byte[] Serialize() => Curve25519.EncodePoint(PublicKey);

    public static IdentityKey Decode(ReadOnlySpan<byte> serialized) => new(Curve25519.DecodePoint(serialized));
}

public sealed class IdentityKeyPair
{
    public IdentityKey PublicKey { get; }
    public byte[] PrivateKey { get; }   // raw 32

    public IdentityKeyPair(IdentityKey publicKey, byte[] privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    public static IdentityKeyPair Generate()
    {
        ECKeyPair kp = Curve25519.GenerateKeyPair();
        return new IdentityKeyPair(new IdentityKey(kp.PublicKey), kp.PrivateKey);
    }
}

public sealed class PreKeyRecord
{
    public uint Id { get; }
    public ECKeyPair KeyPair { get; }

    public PreKeyRecord(uint id, ECKeyPair keyPair)
    {
        Id = id;
        KeyPair = keyPair;
    }

    public static PreKeyRecord Generate(uint id) => new(id, Curve25519.GenerateKeyPair());
}

public sealed class SignedPreKeyRecord
{
    public uint Id { get; }
    public ECKeyPair KeyPair { get; }
    public byte[] Signature { get; }
    public long Timestamp { get; }

    public SignedPreKeyRecord(uint id, ECKeyPair keyPair, byte[] signature, long timestamp)
    {
        Id = id;
        KeyPair = keyPair;
        Signature = signature;
        Timestamp = timestamp;
    }
}

public sealed class KyberPreKeyRecord
{
    public uint Id { get; }
    public KyberKeyPair KeyPair { get; }
    public byte[] Signature { get; }
    public long Timestamp { get; }

    public KyberPreKeyRecord(uint id, KyberKeyPair keyPair, byte[] signature, long timestamp)
    {
        Id = id;
        KeyPair = keyPair;
        Signature = signature;
        Timestamp = timestamp;
    }
}

/// <summary>
/// The bundle of public keys an initiator fetches for a recipient device (GET /v2/keys), used to
/// build an outgoing X3DH/PQXDH session. The one-time prekey is optional; the Kyber prekey is
/// present for PQXDH.
/// </summary>
public sealed class PreKeyBundle
{
    public uint RegistrationId { get; }
    public uint DeviceId { get; }
    public uint? PreKeyId { get; }
    public byte[]? PreKeyPublic { get; }            // raw 32
    public uint SignedPreKeyId { get; }
    public byte[] SignedPreKeyPublic { get; }       // raw 32
    public byte[] SignedPreKeySignature { get; }
    public IdentityKey IdentityKey { get; }
    public uint? KyberPreKeyId { get; }
    public byte[]? KyberPreKeyPublic { get; }       // ML-KEM-1024 encoded
    public byte[]? KyberPreKeySignature { get; }

    public PreKeyBundle(uint registrationId, uint deviceId, uint? preKeyId, byte[]? preKeyPublic,
        uint signedPreKeyId, byte[] signedPreKeyPublic, byte[] signedPreKeySignature, IdentityKey identityKey,
        uint? kyberPreKeyId = null, byte[]? kyberPreKeyPublic = null, byte[]? kyberPreKeySignature = null)
    {
        RegistrationId = registrationId;
        DeviceId = deviceId;
        PreKeyId = preKeyId;
        PreKeyPublic = preKeyPublic;
        SignedPreKeyId = signedPreKeyId;
        SignedPreKeyPublic = signedPreKeyPublic;
        SignedPreKeySignature = signedPreKeySignature;
        IdentityKey = identityKey;
        KyberPreKeyId = kyberPreKeyId;
        KyberPreKeyPublic = kyberPreKeyPublic;
        KyberPreKeySignature = kyberPreKeySignature;
    }
}
