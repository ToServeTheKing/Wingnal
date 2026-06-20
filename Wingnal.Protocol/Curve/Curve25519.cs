using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace Wingnal.Protocol.Curve;

/// <summary>A Curve25519 key pair. Private/public keys are raw 32-byte values.</summary>
public sealed class ECKeyPair
{
    /// <summary>32-byte clamped X25519 private scalar (little-endian).</summary>
    public byte[] PrivateKey { get; }

    /// <summary>32-byte Montgomery u-coordinate public key.</summary>
    public byte[] PublicKey { get; }

    public ECKeyPair(byte[] privateKey, byte[] publicKey)
    {
        PrivateKey = privateKey;
        PublicKey = publicKey;
    }
}

/// <summary>
/// X25519 ECDH plus Signal's DjbECPublicKey (0x05-prefixed, 33-byte) serialization.
/// Private keys are clamped at generation so the same scalar is used consistently for both ECDH
/// and XEdDSA signing (clamping is idempotent, so BouncyCastle re-clamping during agreement is a no-op).
/// </summary>
public static class Curve25519
{
    /// <summary>Signal's type byte for Curve25519 (DJB) public keys.</summary>
    public const byte DjbType = 0x05;

    public static ECKeyPair GenerateKeyPair()
    {
        byte[] priv = RandomNumberGenerator.GetBytes(32);
        Clamp(priv);
        byte[] pub = DerivePublicKey(priv);
        return new ECKeyPair(priv, pub);
    }

    /// <summary>Derives the 32-byte Montgomery public key from a 32-byte private scalar.</summary>
    public static byte[] DerivePublicKey(byte[] privateKey)
    {
        var sk = new X25519PrivateKeyParameters(privateKey, 0);
        return sk.GeneratePublicKey().GetEncoded();
    }

    /// <summary>X25519 ECDH. Returns the 32-byte shared secret.</summary>
    public static byte[] CalculateAgreement(byte[] theirPublicKey, byte[] ourPrivateKey)
    {
        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(ourPrivateKey, 0));
        var secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(new X25519PublicKeyParameters(theirPublicKey, 0), secret, 0);
        return secret;
    }

    /// <summary>Serializes a raw 32-byte public key to a 33-byte DjbECPublicKey (0x05 || u).</summary>
    public static byte[] EncodePoint(byte[] publicKey)
    {
        if (publicKey.Length != 32) throw new ArgumentException("public key must be 32 bytes", nameof(publicKey));
        var encoded = new byte[33];
        encoded[0] = DjbType;
        Array.Copy(publicKey, 0, encoded, 1, 32);
        return encoded;
    }

    /// <summary>Parses a serialized public key (33-byte 0x05-prefixed, or raw 32-byte) to raw 32 bytes.</summary>
    public static byte[] DecodePoint(ReadOnlySpan<byte> serialized)
    {
        if (serialized.Length == 33)
        {
            if (serialized[0] != DjbType) throw new ArgumentException($"unsupported key type {serialized[0]}");
            return serialized.Slice(1, 32).ToArray();
        }
        if (serialized.Length == 32) return serialized.ToArray();
        throw new ArgumentException($"bad public key length {serialized.Length}");
    }

    private static void Clamp(byte[] scalar)
    {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }
}
