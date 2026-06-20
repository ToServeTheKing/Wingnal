using Wingnal.Protocol.Crypto;

namespace Wingnal.Service.Crypto;

/// <summary>
/// Derives a recipient's "unidentified access key" from their profile key, used to send sealed-sender
/// (metadata-minimized) messages without our own auth credentials. Matches Signal-Android
/// <c>UnidentifiedAccess.deriveAccessKeyFrom</c>: the first 16 bytes of AES-256-GCM(profileKey, iv=0¹²,
/// plaintext=0¹⁶).
/// </summary>
public static class UnidentifiedAccess
{
    public static byte[] DeriveAccessKey(byte[] profileKey)
    {
        if (profileKey.Length != 32) throw new ArgumentException("profile key must be 32 bytes", nameof(profileKey));
        byte[] ctAndTag = CryptoPrimitives.AesGcmEncrypt(profileKey, new byte[12], new byte[16]);
        return ctAndTag.AsSpan(0, 16).ToArray();
    }
}
