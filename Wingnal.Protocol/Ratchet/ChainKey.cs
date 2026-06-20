using System.Text;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Protocol.Ratchet;

/// <summary>
/// A symmetric-ratchet chain key. Each step is HMAC-SHA256(chainKey, 0x02); message keys are
/// derived via HMAC-SHA256(chainKey, 0x01) then HKDF "WhisperMessageKeys".
/// </summary>
public sealed class ChainKey
{
    private static readonly byte[] MessageKeySeed = { 0x01 };
    private static readonly byte[] ChainKeySeed = { 0x02 };
    private static readonly byte[] MessageKeysInfo = Encoding.UTF8.GetBytes("WhisperMessageKeys");

    public byte[] Key { get; }
    public uint Index { get; }

    public ChainKey(byte[] key, uint index)
    {
        Key = key;
        Index = index;
    }

    public ChainKey Next() => new(CryptoPrimitives.HmacSha256(Key, ChainKeySeed), Index + 1);

    /// <summary>The per-message key seed (HMAC(chainKey, 0x01)); the input keying material for
    /// <see cref="DeriveMessageKeys"/>. Cached for skipped messages so the SPQR salt can be applied
    /// lazily when the out-of-order message actually arrives.</summary>
    public byte[] MessageKeySeedBytes => CryptoPrimitives.HmacSha256(Key, MessageKeySeed);

    /// <summary>Derives the AES/HMAC/IV message keys from a seed. <paramref name="pqrSalt"/> is the
    /// SPQR per-message key used as the HKDF salt (null for classic sessions). Matches libsignal
    /// <c>MessageKeys::derive_keys(seed, salt=pqr_key, "WhisperMessageKeys")</c>.</summary>
    public static MessageKeys DeriveMessageKeys(byte[] seed, byte[]? pqrSalt, uint counter)
    {
        byte[] material = CryptoPrimitives.Hkdf(seed, salt: pqrSalt, MessageKeysInfo, 80);
        var cipherKey = material.AsSpan(0, 32).ToArray();
        var macKey = material.AsSpan(32, 32).ToArray();
        var iv = material.AsSpan(64, 16).ToArray();
        return new MessageKeys(cipherKey, macKey, iv, counter);
    }

    public MessageKeys GetMessageKeys(byte[]? pqrSalt = null) =>
        DeriveMessageKeys(MessageKeySeedBytes, pqrSalt, Index);
}
