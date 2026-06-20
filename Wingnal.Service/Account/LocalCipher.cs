using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Service.Account;

/// <summary>
/// Encrypts sensitive local-database fields at rest (message bodies, contact names) with AES-256-GCM
/// under a per-install key. The key itself is a random 32 bytes wrapped with Windows DPAPI
/// (CurrentUser) on disk, so the SQLite files no longer contain plaintext content. Also provides a
/// deterministic keyed MAC for fields that must remain queryable/dedupable.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LocalCipher
{
    private static readonly byte[] Entropy = "Wingnal.LocalCipher.v1"u8.ToArray();
    private readonly byte[] _key;   // 32 bytes

    public LocalCipher(byte[] key)
    {
        if (key.Length != 32) throw new ArgumentException("key must be 32 bytes", nameof(key));
        _key = key;
    }

    /// <summary>Loads (or creates) the DPAPI-wrapped per-install key at %LOCALAPPDATA%\Wingnal\local.key.</summary>
    public static LocalCipher Default(string? directory = null)
    {
        directory ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
        Directory.CreateDirectory(directory);
        string keyPath = Path.Combine(directory, "local.key");

        byte[] key;
        if (File.Exists(keyPath))
        {
            key = ProtectedData.Unprotect(File.ReadAllBytes(keyPath), Entropy, DataProtectionScope.CurrentUser);
        }
        else
        {
            key = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes(keyPath, ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser));
        }
        return new LocalCipher(key);
    }

    /// <summary>Encrypts a string to base64( nonce[12] ‖ ciphertext ‖ tag[16] ).</summary>
    public string Protect(string plaintext)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ctAndTag = CryptoPrimitives.AesGcmEncrypt(_key, nonce, Encoding.UTF8.GetBytes(plaintext));
        var blob = new byte[nonce.Length + ctAndTag.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
        Buffer.BlockCopy(ctAndTag, 0, blob, nonce.Length, ctAndTag.Length);
        return Convert.ToBase64String(blob);
    }

    /// <summary>Inverse of <see cref="Protect"/>. If <paramref name="stored"/> isn't a value we wrote
    /// (e.g. a legacy plaintext row from before encryption), it's returned unchanged.</summary>
    public string Unprotect(string stored)
    {
        try
        {
            byte[] blob = Convert.FromBase64String(stored);
            if (blob.Length < 12 + 16) return stored;
            byte[] nonce = blob.AsSpan(0, 12).ToArray();
            byte[] ctAndTag = blob.AsSpan(12).ToArray();
            return Encoding.UTF8.GetString(CryptoPrimitives.AesGcmDecrypt(_key, nonce, ctAndTag));
        }
        catch
        {
            return stored;   // legacy plaintext or not ours — leave as-is
        }
    }

    /// <summary>Deterministic keyed identity of a value, for dedup/index columns (hex HMAC-SHA256).</summary>
    public string Mac(string value) =>
        Convert.ToHexString(CryptoPrimitives.HmacSha256(_key, Encoding.UTF8.GetBytes(value)));
}
