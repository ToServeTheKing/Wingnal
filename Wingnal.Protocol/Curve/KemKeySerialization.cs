namespace Wingnal.Protocol.Curve;

/// <summary>
/// libsignal serializes KEM public keys and ciphertexts with a one-byte key-type prefix (analogous
/// to the 0x05 DjbECPublicKey prefix). Kyber-1024 is type 0x08. The signed-prekey signature is
/// computed over this prefixed form, and prekey bundles carry the prefixed public key.
/// </summary>
public static class KemKeySerialization
{
    /// <summary>libsignal KEM key type for Kyber-1024.</summary>
    public const byte Kyber1024Type = 0x08;

    /// <summary>Prepends the Kyber-1024 type byte to a raw public key or ciphertext.</summary>
    public static byte[] Serialize(byte[] raw)
    {
        var serialized = new byte[raw.Length + 1];
        serialized[0] = Kyber1024Type;
        Array.Copy(raw, 0, serialized, 1, raw.Length);
        return serialized;
    }

    /// <summary>Strips the type byte from a serialized Kyber-1024 public key or ciphertext.</summary>
    public static byte[] Deserialize(ReadOnlySpan<byte> serialized)
    {
        if (serialized.Length < 1 || serialized[0] != Kyber1024Type)
            throw new ArgumentException($"unsupported KEM key type {(serialized.Length > 0 ? serialized[0] : -1)}");
        return serialized[1..].ToArray();
    }
}
