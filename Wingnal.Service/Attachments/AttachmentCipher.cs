using System.Security.Cryptography;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Service.Attachments;

/// <summary>Thrown when an attachment fails its MAC or digest check, or is malformed.</summary>
public sealed class InvalidAttachmentException : Exception
{
    public InvalidAttachmentException(string message) : base(message) { }
}

/// <summary>
/// Decrypts a Signal attachment blob. Layout on the CDN is
/// <c>iv[16] || AES-256-CBC(cipherKey, plaintext+padding) || HMAC-SHA256(macKey, iv||ciphertext)[32]</c>.
/// The 64-byte attachment key is <c>cipherKey[32] || macKey[32]</c>; the optional <c>digest</c> is
/// SHA-256 over the WHOLE blob. Mirrors libsignal/Signal-Android AttachmentCipherInputStream.
/// </summary>
public static class AttachmentCipher
{
    private const int IvLength = 16;
    private const int MacLength = 32;

    /// <summary>
    /// Verifies the digest (if given) and the HMAC, then AES-256-CBC decrypts. If
    /// <paramref name="plaintextLength"/> is provided (the AttachmentPointer <c>size</c>), the result is
    /// truncated to it to strip bucket padding.
    /// </summary>
    public static byte[] Decrypt(byte[] blob, byte[] combinedKey, byte[]? digest = null, int? plaintextLength = null)
    {
        if (combinedKey.Length != 64)
            throw new InvalidAttachmentException($"attachment key must be 64 bytes, got {combinedKey.Length}");
        if (blob.Length <= IvLength + MacLength)
            throw new InvalidAttachmentException("attachment blob too short");

        byte[] cipherKey = combinedKey.AsSpan(0, 32).ToArray();
        byte[] macKey = combinedKey.AsSpan(32, 32).ToArray();

        // Whole-blob digest (covers iv + ciphertext + mac).
        if (digest is not null)
        {
            byte[] actual = SHA256.HashData(blob);
            if (!CryptographicOperations.FixedTimeEquals(actual, digest))
                throw new InvalidAttachmentException("attachment digest mismatch");
        }

        int macOffset = blob.Length - MacLength;
        byte[] theirMac = blob.AsSpan(macOffset, MacLength).ToArray();
        byte[] ourMac = CryptoPrimitives.HmacSha256(macKey, blob.AsSpan(0, macOffset));
        if (!CryptographicOperations.FixedTimeEquals(theirMac, ourMac))
            throw new InvalidAttachmentException("attachment MAC mismatch");

        byte[] iv = blob.AsSpan(0, IvLength).ToArray();
        byte[] ciphertext = blob.AsSpan(IvLength, macOffset - IvLength).ToArray();
        byte[] plaintext = CryptoPrimitives.AesCbcDecrypt(cipherKey, iv, ciphertext);

        if (plaintextLength is { } len && len >= 0 && len < plaintext.Length)
            plaintext = plaintext.AsSpan(0, len).ToArray();
        return plaintext;
    }

    /// <summary>
    /// Builds an encrypted attachment blob the way Signal does (for tests / round-trip verification):
    /// <c>iv || AES-256-CBC(cipherKey, plaintext) || HMAC(macKey, iv||ct)</c>, returning the blob and
    /// its SHA-256 digest.
    /// </summary>
    public static (byte[] Blob, byte[] Digest) Encrypt(byte[] plaintext, byte[] combinedKey, byte[] iv)
    {
        if (combinedKey.Length != 64) throw new ArgumentException("key must be 64 bytes", nameof(combinedKey));
        if (iv.Length != IvLength) throw new ArgumentException("iv must be 16 bytes", nameof(iv));

        byte[] cipherKey = combinedKey.AsSpan(0, 32).ToArray();
        byte[] macKey = combinedKey.AsSpan(32, 32).ToArray();

        byte[] ciphertext = CryptoPrimitives.AesCbcEncrypt(cipherKey, iv, plaintext);

        var withoutMac = new byte[IvLength + ciphertext.Length];
        Array.Copy(iv, 0, withoutMac, 0, IvLength);
        Array.Copy(ciphertext, 0, withoutMac, IvLength, ciphertext.Length);

        byte[] mac = CryptoPrimitives.HmacSha256(macKey, withoutMac);
        var blob = new byte[withoutMac.Length + MacLength];
        Array.Copy(withoutMac, 0, blob, 0, withoutMac.Length);
        Array.Copy(mac, 0, blob, withoutMac.Length, MacLength);

        return (blob, SHA256.HashData(blob));
    }
}
