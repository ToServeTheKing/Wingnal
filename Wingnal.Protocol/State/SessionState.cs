using System.IO;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.Spqr;

namespace Wingnal.Protocol.State;

/// <summary>The sender's unacknowledged X3DH/PQXDH setup data, replayed in each outgoing message
/// until the peer's first reply confirms the session (then cleared).</summary>
public sealed class PendingPreKey
{
    public uint? PreKeyId { get; }
    public uint SignedPreKeyId { get; }
    public uint? KyberPreKeyId { get; }
    public byte[]? KyberCiphertext { get; }
    public byte[] BaseKey { get; }   // raw 32

    public PendingPreKey(uint? preKeyId, uint signedPreKeyId, uint? kyberPreKeyId, byte[]? kyberCiphertext, byte[] baseKey)
    {
        PreKeyId = preKeyId;
        SignedPreKeyId = signedPreKeyId;
        KyberPreKeyId = kyberPreKeyId;
        KyberCiphertext = kyberCiphertext;
        BaseKey = baseKey;
    }
}

/// <summary>One receiving chain, keyed by the peer's ratchet public key, plus a bounded cache of
/// skipped message keys (out-of-order / dropped messages).</summary>
public sealed class ReceiverChain
{
    private const int MaxMessageKeys = 2000;

    public byte[] RatchetKey { get; }     // raw 32, the peer's ratchet public key
    public ChainKey ChainKey { get; set; }
    // Skipped/out-of-order messages cache the message-key SEED (not the final keys), so the SPQR
    // per-message salt can be applied when the out-of-order message arrives. Counter -> seed.
    private readonly Dictionary<uint, byte[]> _messageSeeds = new();
    private readonly Queue<uint> _order = new();

    public ReceiverChain(byte[] ratchetKey, ChainKey chainKey)
    {
        RatchetKey = ratchetKey;
        ChainKey = chainKey;
    }

    public bool TryTakeMessageSeed(uint counter, out byte[] seed)
    {
        if (_messageSeeds.Remove(counter, out byte[]? found))
        {
            seed = found;
            return true;
        }
        seed = default!;
        return false;
    }

    public void StoreMessageSeed(uint counter, byte[] seed)
    {
        _messageSeeds[counter] = seed;
        _order.Enqueue(counter);
        while (_order.Count > MaxMessageKeys)
            _messageSeeds.Remove(_order.Dequeue());
    }

    internal void Write(BinaryWriter w)
    {
        w.WriteBlob(RatchetKey);
        w.WriteBlob(ChainKey.Key);
        w.Write(ChainKey.Index);
        w.Write(_messageSeeds.Count);
        foreach (KeyValuePair<uint, byte[]> kv in _messageSeeds) { w.Write(kv.Key); w.WriteBlob(kv.Value); }
    }

    internal static ReceiverChain Read(BinaryReader r)
    {
        byte[] ratchetKey = r.ReadBlob();
        var chainKey = new ChainKey(r.ReadBlob(), r.ReadUInt32());
        var chain = new ReceiverChain(ratchetKey, chainKey);
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++) chain.StoreMessageSeed(r.ReadUInt32(), r.ReadBlob());
        return chain;
    }
}

/// <summary>
/// Mutable Double Ratchet session state: root key, current sending chain, recent receiving chains,
/// identities, and (for an initiator) the pending prekey. Mirrors libsignal's SessionState.
/// </summary>
public sealed class SessionState
{
    private const int MaxReceiverChains = 5;

    public int SessionVersion { get; set; }
    public IdentityKey? LocalIdentity { get; set; }
    public IdentityKey? RemoteIdentity { get; set; }
    public uint LocalRegistrationId { get; set; }
    public uint RemoteRegistrationId { get; set; }

    public RootKey? RootKey { get; set; }
    public ECKeyPair? SenderRatchetKeyPair { get; set; }
    public ChainKey? SenderChainKey { get; set; }
    public uint PreviousCounter { get; set; }

    public PendingPreKey? PendingPreKey { get; set; }
    public byte[]? AliceBaseKey { get; set; }   // responder-side dedupe of repeated prekey messages

    /// <summary>The 32-byte SPQR auth_key (3rd HKDF slice from PQXDH); null for classic X3DH sessions.</summary>
    public byte[]? SpqrAuthKey { get; set; }
    /// <summary>The live Sparse Post-Quantum Ratchet (in-memory); null = SPQR disabled (classic session).</summary>
    public SpqrRatchet? Spqr { get; set; }

    private readonly LinkedList<ReceiverChain> _receiverChains = new();

    public bool HasSenderChain => SenderRatchetKeyPair is not null && SenderChainKey is not null;
    public bool IsInitialized => RootKey is not null;

    public ReceiverChain? FindReceiverChain(byte[] ratchetKey)
    {
        foreach (ReceiverChain chain in _receiverChains)
            if (chain.RatchetKey.AsSpan().SequenceEqual(ratchetKey))
                return chain;
        return null;
    }

    public void AddReceiverChain(byte[] ratchetKey, ChainKey chainKey)
    {
        _receiverChains.AddFirst(new ReceiverChain(ratchetKey, chainKey));
        while (_receiverChains.Count > MaxReceiverChains)
            _receiverChains.RemoveLast();
    }

    // ── serialization (durable session persistence) ──

    internal void Write(BinaryWriter w)
    {
        w.Write(SessionVersion);
        WriteId(w, LocalIdentity);
        WriteId(w, RemoteIdentity);
        w.Write(LocalRegistrationId);
        w.Write(RemoteRegistrationId);
        w.Write(RootKey is not null); if (RootKey is not null) w.WriteBlob(RootKey.Key);
        w.Write(SenderRatchetKeyPair is not null);
        if (SenderRatchetKeyPair is not null) { w.WriteBlob(SenderRatchetKeyPair.PrivateKey); w.WriteBlob(SenderRatchetKeyPair.PublicKey); }
        w.Write(SenderChainKey is not null);
        if (SenderChainKey is not null) { w.WriteBlob(SenderChainKey.Key); w.Write(SenderChainKey.Index); }
        w.Write(PreviousCounter);
        w.Write(PendingPreKey is not null); if (PendingPreKey is { } pp) WritePending(w, pp);
        w.Write(AliceBaseKey is not null); if (AliceBaseKey is not null) w.WriteBlob(AliceBaseKey);
        w.Write(SpqrAuthKey is not null); if (SpqrAuthKey is not null) w.WriteBlob(SpqrAuthKey);
        w.Write(Spqr is not null); if (Spqr is not null) w.WriteBlob(Spqr.Serialize());
        w.Write(_receiverChains.Count);
        foreach (ReceiverChain c in _receiverChains) c.Write(w);
    }

    internal static SessionState Read(BinaryReader r)
    {
        var s = new SessionState
        {
            SessionVersion = r.ReadInt32(),
            LocalIdentity = ReadId(r),
            RemoteIdentity = ReadId(r),
            LocalRegistrationId = r.ReadUInt32(),
            RemoteRegistrationId = r.ReadUInt32(),
        };
        if (r.ReadBoolean()) s.RootKey = new RootKey(r.ReadBlob());
        if (r.ReadBoolean()) s.SenderRatchetKeyPair = new ECKeyPair(r.ReadBlob(), r.ReadBlob());
        if (r.ReadBoolean()) s.SenderChainKey = new ChainKey(r.ReadBlob(), r.ReadUInt32());
        s.PreviousCounter = r.ReadUInt32();
        if (r.ReadBoolean()) s.PendingPreKey = ReadPending(r);
        if (r.ReadBoolean()) s.AliceBaseKey = r.ReadBlob();
        if (r.ReadBoolean()) s.SpqrAuthKey = r.ReadBlob();
        if (r.ReadBoolean()) s.Spqr = SpqrRatchet.Deserialize(r.ReadBlob());
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++) s._receiverChains.AddLast(ReceiverChain.Read(r));
        return s;
    }

    private static void WriteId(BinaryWriter w, IdentityKey? id) { w.Write(id is not null); if (id is not null) w.WriteBlob(id.PublicKey); }
    private static IdentityKey? ReadId(BinaryReader r) => r.ReadBoolean() ? new IdentityKey(r.ReadBlob()) : null;

    private static void WritePending(BinaryWriter w, PendingPreKey p)
    {
        w.Write(p.PreKeyId.HasValue); if (p.PreKeyId.HasValue) w.Write(p.PreKeyId.Value);
        w.Write(p.SignedPreKeyId);
        w.Write(p.KyberPreKeyId.HasValue); if (p.KyberPreKeyId.HasValue) w.Write(p.KyberPreKeyId.Value);
        w.Write(p.KyberCiphertext is not null); if (p.KyberCiphertext is not null) w.WriteBlob(p.KyberCiphertext);
        w.WriteBlob(p.BaseKey);
    }

    private static PendingPreKey ReadPending(BinaryReader r)
    {
        uint? preKeyId = r.ReadBoolean() ? r.ReadUInt32() : null;
        uint signedId = r.ReadUInt32();
        uint? kyberId = r.ReadBoolean() ? r.ReadUInt32() : null;
        byte[]? kyberCt = r.ReadBoolean() ? r.ReadBlob() : null;
        byte[] baseKey = r.ReadBlob();
        return new PendingPreKey(preKeyId, signedId, kyberId, kyberCt, baseKey);
    }
}
