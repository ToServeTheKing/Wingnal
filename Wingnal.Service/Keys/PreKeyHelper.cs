using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Service.Keys;

/// <summary>Generates the prekeys a freshly linked device must register with the server.</summary>
public static class PreKeyHelper
{
    /// <summary>A 14-bit Signal registration id (1..16383).</summary>
    public static uint GenerateRegistrationId() => (uint)RandomNumberGenerator.GetInt32(1, 16384);

    /// <summary>A signed prekey whose public key is signed with the given identity private key.</summary>
    public static SignedPreKeyRecord GenerateSignedPreKey(byte[] identityPrivateKey, uint id)
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();
        byte[] signature = XEd25519.CalculateSignature(
            identityPrivateKey, Curve25519.EncodePoint(keyPair.PublicKey), RandomNumberGenerator.GetBytes(64));
        return new SignedPreKeyRecord(id, keyPair, signature, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    /// <summary>A last-resort ML-KEM prekey signed with the given identity private key.</summary>
    public static KyberPreKeyRecord GenerateKyberPreKey(byte[] identityPrivateKey, uint id)
    {
        KyberKeyPair keyPair = Kyber.GenerateKeyPair();
        byte[] signature = XEd25519.CalculateSignature(
            identityPrivateKey, KemKeySerialization.Serialize(keyPair.PublicKey), RandomNumberGenerator.GetBytes(64));
        return new KyberPreKeyRecord(id, keyPair, signature, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    /// <summary>A batch of one-time prekeys, ids starting at <paramref name="startId"/>.</summary>
    public static List<PreKeyRecord> GenerateOneTimePreKeys(uint startId, int count)
    {
        var result = new List<PreKeyRecord>(count);
        for (uint i = 0; i < count; i++)
            result.Add(PreKeyRecord.Generate(startId + i));
        return result;
    }
}
