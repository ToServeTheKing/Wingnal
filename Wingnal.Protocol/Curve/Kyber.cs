using System.Security.Cryptography;

namespace Wingnal.Protocol.Curve;

/// <summary>An ML-KEM/Kyber key pair (encoded public/private key bytes).</summary>
public sealed class KyberKeyPair
{
    public byte[] PublicKey { get; }
    public byte[] PrivateKey { get; }
    public KyberKeyPair(byte[] publicKey, byte[] privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }
}

/// <summary>Result of an encapsulation: the ciphertext to send and the shared secret.</summary>
public sealed class KyberEncapsulation
{
    public byte[] CipherText { get; }
    public byte[] SharedSecret { get; }
    public KyberEncapsulation(byte[] cipherText, byte[] sharedSecret)
    {
        CipherText = cipherText;
        SharedSecret = sharedSecret;
    }
}

/// <summary>
/// Round-3 Kyber-1024 KEM, used for PQXDH pqkem prekeys. This matches libsignal's <c>KYBER_1024</c>
/// (type byte 0x08), so prekeys and ciphertexts interoperate with the Signal ecosystem. The raw
/// public/private/ciphertext encodings here carry no type-byte prefix — see <see cref="KemKeySerialization"/>.
/// </summary>
public static class Kyber
{
    public static KyberKeyPair GenerateKeyPair()
    {
        byte[] d = RandomNumberGenerator.GetBytes(Kyber1024.SymBytes);
        byte[] z = RandomNumberGenerator.GetBytes(Kyber1024.SymBytes);
        Kyber1024.KeyPair(d, z, out byte[] pk, out byte[] sk);
        return new KyberKeyPair(pk, sk);
    }

    /// <summary>Encapsulate to a peer's public key. Returns ciphertext + shared secret.</summary>
    public static KyberEncapsulation Encapsulate(byte[] publicKey)
    {
        byte[] m = RandomNumberGenerator.GetBytes(Kyber1024.SymBytes);
        Kyber1024.Encapsulate(publicKey, m, out byte[] ct, out byte[] ss);
        return new KyberEncapsulation(ct, ss);
    }

    /// <summary>Decapsulate a received ciphertext with our private key. Returns the shared secret.</summary>
    public static byte[] Decapsulate(byte[] privateKey, byte[] cipherText) =>
        Kyber1024.Decapsulate(cipherText, privateKey);
}
