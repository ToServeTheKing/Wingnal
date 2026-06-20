using System.IO;
using Wingnal.Protocol.Messages;

namespace Wingnal.Protocol.Groups;

/// <summary>
/// All sender-key states for one (sender, distribution-id). The most-recently-added state is current
/// (used for encrypting / the latest received chain); older states are kept (bounded) so in-flight
/// messages under a superseded chain still decrypt. Mirrors libsignal's SenderKeyRecord.
/// </summary>
public sealed class SenderKeyRecord
{
    /// <summary>libsignal <c>consts::MAX_SENDER_KEY_STATES</c>.</summary>
    public const int MaxStates = 5;

    private readonly List<SenderKeyState> _states = new();  // index 0 = current

    public bool IsEmpty => _states.Count == 0;

    /// <summary>The current (most recent) state.</summary>
    public SenderKeyState State =>
        _states.Count > 0 ? _states[0] : throw new InvalidMessageException("no sender key state");

    /// <summary>The state for a specific chain id (a received message names its chain), or null.</summary>
    public SenderKeyState? StateForChainId(uint chainId) =>
        _states.Find(s => s.ChainId == chainId);

    /// <summary>
    /// Installs a sender-key state (from our own keygen, or from a processed SKDM). Idempotent for a
    /// repeated SKDM: if a state with the same chain id and signing key already exists it's left
    /// untouched (so re-processing the same distribution message doesn't rewind the chain).
    /// </summary>
    public void AddState(uint chainId, int messageVersion, uint iteration, byte[] chainKeySeed,
        byte[] signingKeyPublic, byte[]? signingKeyPrivate)
    {
        SenderKeyState? existing = _states.Find(s => s.ChainId == chainId);
        if (existing is not null && existing.SigningKeyPublic.AsSpan().SequenceEqual(signingKeyPublic))
            return;

        _states.RemoveAll(s => s.ChainId == chainId);
        _states.Insert(0, new SenderKeyState(chainId, messageVersion, iteration, chainKeySeed,
            signingKeyPublic, signingKeyPrivate));
        while (_states.Count > MaxStates)
            _states.RemoveAt(_states.Count - 1);
    }

    // ── durable persistence (local-only binary; never sent to a peer) ──

    /// <summary>Serializes every state (index 0 = current) for durable storage.</summary>
    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(_states.Count);
        foreach (SenderKeyState s in _states) s.Write(w);
        w.Flush();
        return ms.ToArray();
    }

    public static SenderKeyRecord Deserialize(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        using var r = new BinaryReader(ms);
        var record = new SenderKeyRecord();
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++) record._states.Add(SenderKeyState.Read(r));
        return record;
    }
}
