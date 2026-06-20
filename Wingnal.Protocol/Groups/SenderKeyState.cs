using System.IO;
using System.Text;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Spqr;   // Bin.WriteBlob/ReadBlob length-prefixed helpers

namespace Wingnal.Protocol.Groups;

/// <summary>
/// A per-message symmetric key derived from a sender chain. Mirrors libsignal's
/// <c>SenderMessageKey</c>: HKDF-SHA256 expand of the chain's <c>0x01</c> derivative with info
/// "WhisperGroup" to 48 bytes = iv[16] || cipherKey[32].
/// </summary>
public sealed class SenderMessageKey
{
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("WhisperGroup");

    public uint Iteration { get; }
    public byte[] Seed { get; }        // the 32-byte 0x01-derivative (persisted form)
    public byte[] Iv { get; }          // 16
    public byte[] CipherKey { get; }   // 32

    public SenderMessageKey(uint iteration, byte[] seed)
    {
        Iteration = iteration;
        Seed = seed;
        byte[] derived = CryptoPrimitives.Hkdf(seed, salt: null, Info, 48);
        Iv = derived.AsSpan(0, 16).ToArray();
        CipherKey = derived.AsSpan(16, 32).ToArray();
    }
}

/// <summary>
/// A sender chain key. <c>messageKey = HMAC-SHA256(chainKey, 0x01)</c>; the next chain key is
/// <c>HMAC-SHA256(chainKey, 0x02)</c>. Identical construction to the 1:1 <c>ChainKey</c>, but the
/// message-key seed is expanded with the group info string.
/// </summary>
public sealed class SenderChainKey
{
    private static readonly byte[] MessageKeySeed = { 0x01 };
    private static readonly byte[] ChainKeySeed = { 0x02 };

    public uint Iteration { get; }
    public byte[] Seed { get; }

    public SenderChainKey(uint iteration, byte[] seed)
    {
        Iteration = iteration;
        Seed = seed;
    }

    public SenderMessageKey MessageKey() =>
        new(Iteration, CryptoPrimitives.HmacSha256(Seed, MessageKeySeed));

    public SenderChainKey Next() =>
        new(Iteration + 1, CryptoPrimitives.HmacSha256(Seed, ChainKeySeed));
}

/// <summary>
/// One sender-key state for a (sender, distribution-id) chain: the symmetric chain, the signing key
/// pair (private present only for our own outgoing chain), the chain id, message version, and a
/// bounded FIFO cache of skipped/out-of-order message keys. Mirrors libsignal's SenderKeyState.
/// </summary>
public sealed class SenderKeyState
{
    /// <summary>libsignal <c>consts::MAX_MESSAGE_KEYS</c> — bound on the skipped-key cache.</summary>
    public const int MaxMessageKeys = 2000;

    public uint ChainId { get; }
    public int MessageVersion { get; }
    public byte[] SigningKeyPublic { get; }    // raw 32-byte Montgomery
    public byte[]? SigningKeyPrivate { get; }  // raw 32 (null for receive-only state)
    public SenderChainKey ChainKey { get; set; }

    private readonly List<SenderMessageKey> _messageKeys = new();

    public SenderKeyState(uint chainId, int messageVersion, uint iteration, byte[] chainKeySeed,
        byte[] signingKeyPublic, byte[]? signingKeyPrivate)
    {
        ChainId = chainId;
        MessageVersion = messageVersion;
        SigningKeyPublic = signingKeyPublic;
        SigningKeyPrivate = signingKeyPrivate;
        ChainKey = new SenderChainKey(iteration, chainKeySeed);
    }

    public void AddMessageKey(SenderMessageKey key)
    {
        _messageKeys.Add(key);
        while (_messageKeys.Count > MaxMessageKeys)
            _messageKeys.RemoveAt(0);   // FIFO eviction (oldest first), matching libsignal
    }

    /// <summary>Removes and returns the cached key for <paramref name="iteration"/>, or null if absent
    /// (already used / never skipped).</summary>
    public SenderMessageKey? RemoveMessageKey(uint iteration)
    {
        int idx = _messageKeys.FindIndex(k => k.Iteration == iteration);
        if (idx < 0) return null;
        SenderMessageKey key = _messageKeys[idx];
        _messageKeys.RemoveAt(idx);
        return key;
    }

    // ── durable persistence (local-only binary; never sent to a peer) ──

    internal void Write(BinaryWriter w)
    {
        w.Write(ChainId);
        w.Write(MessageVersion);
        w.WriteBlob(SigningKeyPublic);
        w.Write(SigningKeyPrivate is not null);
        if (SigningKeyPrivate is not null) w.WriteBlob(SigningKeyPrivate);
        w.Write(ChainKey.Iteration);
        w.WriteBlob(ChainKey.Seed);
        w.Write(_messageKeys.Count);
        foreach (SenderMessageKey k in _messageKeys) { w.Write(k.Iteration); w.WriteBlob(k.Seed); }
    }

    internal static SenderKeyState Read(BinaryReader r)
    {
        uint chainId = r.ReadUInt32();
        int messageVersion = r.ReadInt32();
        byte[] signingPublic = r.ReadBlob();
        byte[]? signingPrivate = r.ReadBoolean() ? r.ReadBlob() : null;
        uint iteration = r.ReadUInt32();
        byte[] chainSeed = r.ReadBlob();
        var state = new SenderKeyState(chainId, messageVersion, iteration, chainSeed, signingPublic, signingPrivate);
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++)
            state.AddMessageKey(new SenderMessageKey(r.ReadUInt32(), r.ReadBlob()));
        return state;
    }
}
