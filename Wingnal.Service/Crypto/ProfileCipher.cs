using System;
using System.Text;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Service.Crypto;

/// <summary>
/// Decrypts Signal profile fields (name, about) that a recipient encrypted with their 32-byte profile
/// key. The blob layout matches libsignal's <c>ProfileCipher</c>: <c>nonce(12) || AES-256-GCM ciphertext
/// || tag(16)</c>. The decrypted name plaintext is NUL-separated <c>given \0 family</c>, zero-padded to a
/// fixed bucket length, so decoding strips the padding and rejoins the parts.
/// </summary>
public static class ProfileCipher
{
    /// <summary>Decrypts a base64 profile-name blob to a display name. Returns null when the input is
    /// empty/malformed, the profile key is the wrong length, or GCM authentication fails (a stale or
    /// mismatched profile key) — callers treat that as "no name available".</summary>
    public static string? DecryptName(byte[] profileKey, string? base64Name)
    {
        if (profileKey.Length != 32 || string.IsNullOrEmpty(base64Name)) return null;

        byte[] blob;
        try { blob = Convert.FromBase64String(base64Name); }
        catch (FormatException) { return null; }
        if (blob.Length < 12 + 16) return null;   // must hold at least a nonce and a tag

        var nonce = new byte[12];
        Array.Copy(blob, 0, nonce, 0, 12);
        var ciphertextAndTag = new byte[blob.Length - 12];
        Array.Copy(blob, 12, ciphertextAndTag, 0, ciphertextAndTag.Length);

        byte[] plaintext;
        try { plaintext = CryptoPrimitives.AesGcmDecrypt(profileKey, nonce, ciphertextAndTag); }
        catch { return null; }   // tag mismatch / bad key

        return DecodePaddedName(plaintext);
    }

    /// <summary>Plaintext is <c>given \0 family</c> followed by zero padding. Split on the first NUL (the
    /// family segment may be empty), UTF-8 decode each part, and rejoin. Returns null if the result is
    /// blank.</summary>
    private static string? DecodePaddedName(byte[] plaintext)
    {
        int split = Array.IndexOf(plaintext, (byte)0);
        string given, family;
        if (split < 0)
        {
            given = Encoding.UTF8.GetString(plaintext);
            family = string.Empty;
        }
        else
        {
            given = Encoding.UTF8.GetString(plaintext, 0, split);
            int rest = split + 1;
            int end = Array.IndexOf(plaintext, (byte)0, rest);
            if (end < 0) end = plaintext.Length;
            family = Encoding.UTF8.GetString(plaintext, rest, end - rest);
        }

        string name = $"{given} {family}".Trim();
        return name.Length == 0 ? null : name;
    }
}
