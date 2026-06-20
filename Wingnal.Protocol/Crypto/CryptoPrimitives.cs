using System.Security.Cryptography;

namespace Wingnal.Protocol.Crypto;

/// <summary>Thin wrappers over the .NET BCL for the AEAD/KDF/MAC primitives Signal uses.</summary>
public static class CryptoPrimitives
{
    /// <summary>HKDF-SHA256 (extract + expand). Signal's standard KDF.</summary>
    public static byte[] Hkdf(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int outputLength)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, outputLength, salt, info);
    }

    /// <summary>HMAC-SHA256.</summary>
    public static byte[] HmacSha256(byte[] key, ReadOnlySpan<byte> data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data.ToArray());
    }

    /// <summary>AES-256-CBC encrypt with PKCS7 padding.</summary>
    public static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    /// <summary>AES-256-CBC decrypt with PKCS7 padding.</summary>
    public static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    /// <summary>AES-CTR with a 128-bit big-endian counter starting at <paramref name="iv"/>. Symmetric
    /// (same call encrypts and decrypts). Used by sealed sender (zero IV) and DeviceNameCipher.</summary>
    public static byte[] AesCtr(byte[] key, byte[] iv, byte[] input)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using ICryptoTransform ecb = aes.CreateEncryptor();

        var counter = (byte[])iv.Clone();
        var output = new byte[input.Length];
        var keystream = new byte[16];
        for (int offset = 0; offset < input.Length; offset += 16)
        {
            ecb.TransformBlock(counter, 0, 16, keystream, 0);
            int block = Math.Min(16, input.Length - offset);
            for (int i = 0; i < block; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            for (int i = counter.Length - 1; i >= 0; i--)
                if (++counter[i] != 0) break;
        }
        return output;
    }

    /// <summary>AES-256-GCM encrypt. Returns ciphertext || 16-byte tag.</summary>
    public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[]? associatedData = null)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        var result = new byte[ciphertext.Length + tag.Length];
        Array.Copy(ciphertext, 0, result, 0, ciphertext.Length);
        Array.Copy(tag, 0, result, ciphertext.Length, tag.Length);
        return result;
    }

    /// <summary>AES-256-GCM decrypt. Input is ciphertext || 16-byte tag.</summary>
    public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextAndTag, byte[]? associatedData = null)
    {
        int ctLen = ciphertextAndTag.Length - 16;
        if (ctLen < 0) throw new ArgumentException("ciphertext too short", nameof(ciphertextAndTag));
        var ciphertext = new byte[ctLen];
        var tag = new byte[16];
        Array.Copy(ciphertextAndTag, 0, ciphertext, 0, ctLen);
        Array.Copy(ciphertextAndTag, ctLen, tag, 0, 16);
        var plaintext = new byte[ctLen];
        using var gcm = new AesGcm(key, 16);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}
