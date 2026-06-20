using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Crypto;

/// <summary>
/// Encrypts a linked device's display name to the account's identity key, matching Signal's
/// DeviceNameCipher: ECDH to an ephemeral key, HMAC-derived synthetic IV + cipher key, then
/// AES-256-CTR. The primary device decrypts this to label us in its linked-devices list.
/// </summary>
public static class DeviceNameCipher
{
    public static byte[] EncryptDeviceName(string deviceName, IdentityKeyPair identityKeyPair)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(deviceName);
        ECKeyPair ephemeral = Curve25519.GenerateKeyPair();
        byte[] masterSecret = Curve25519.CalculateAgreement(identityKeyPair.PublicKey.PublicKey, ephemeral.PrivateKey);

        byte[] syntheticIv = ComputeSyntheticIv(masterSecret, plaintext);
        byte[] cipherKey = ComputeCipherKey(masterSecret, syntheticIv);
        // Signal encrypts with a zero CTR IV; the syntheticIv only derives the key and is sent in the proto.
        byte[] ciphertext = CryptoPrimitives.AesCtr(cipherKey, new byte[16], plaintext);

        var message = new DeviceName
        {
            EphemeralPublic = ByteString.CopyFrom(Curve25519.EncodePoint(ephemeral.PublicKey)),
            SyntheticIv = ByteString.CopyFrom(syntheticIv),
            Ciphertext = ByteString.CopyFrom(ciphertext),
        };
        return message.ToByteArray();
    }

    /// <summary>Decrypts a serialized DeviceName proto with the identity key, mirroring Signal's
    /// decrypt (re-derives and verifies the synthetic IV). Returns null if undecryptable/tampered.</summary>
    public static string? DecryptDeviceName(byte[] serialized, IdentityKeyPair identityKeyPair)
    {
        DeviceName message = DeviceName.Parser.ParseFrom(serialized);
        if (message.EphemeralPublic.IsEmpty || message.SyntheticIv.IsEmpty || message.Ciphertext.IsEmpty)
            return null;

        byte[] ephemeralPublic = Curve25519.DecodePoint(message.EphemeralPublic.Span);
        byte[] masterSecret = Curve25519.CalculateAgreement(ephemeralPublic, identityKeyPair.PrivateKey);
        byte[] syntheticIv = message.SyntheticIv.ToByteArray();

        byte[] cipherKey = ComputeCipherKey(masterSecret, syntheticIv);
        byte[] plaintext = CryptoPrimitives.AesCtr(cipherKey, new byte[16], message.Ciphertext.ToByteArray());

        byte[] expectedIv = ComputeSyntheticIv(masterSecret, plaintext);
        if (!CryptographicOperations.FixedTimeEquals(expectedIv, syntheticIv))
            return null;

        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] ComputeSyntheticIv(byte[] masterSecret, byte[] plaintext)
    {
        byte[] keyMaterial = CryptoPrimitives.HmacSha256(masterSecret, "auth"u8);
        byte[] mac = CryptoPrimitives.HmacSha256(keyMaterial, plaintext);
        return mac[..16];
    }

    private static byte[] ComputeCipherKey(byte[] masterSecret, byte[] syntheticIv)
    {
        byte[] keyMaterial = CryptoPrimitives.HmacSha256(masterSecret, "cipher"u8);
        return CryptoPrimitives.HmacSha256(keyMaterial, syntheticIv);
    }

}
