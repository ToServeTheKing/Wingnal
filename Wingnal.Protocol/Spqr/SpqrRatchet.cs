using System.IO;

namespace Wingnal.Protocol.Spqr;

public enum SpqrVersion { V0 = 0, V1 = 1 }

/// <summary>Parameters for <see cref="SpqrRatchet.InitialState"/> (mirrors lib.rs Params).</summary>
public sealed class SpqrParams
{
    public required Direction Direction { get; init; }
    public required SpqrVersion Version { get; init; }
    public required SpqrVersion MinVersion { get; init; }
    public required byte[] AuthKey { get; init; }
    public ChainParams ChainParams { get; init; } = new();
}

/// <summary>
/// Top-level SPQR ratchet API (ported from SparsePostQuantumRatchet v1.5.1 src/lib.rs). Glues the
/// chunked SCKA state machine to the symmetric <see cref="Chain"/>: <see cref="Send"/> emits the wire
/// <c>pq_ratchet</c> bytes plus an optional 32-byte message key (the HKDF salt libsignal mixes into the
/// per-message WhisperMessageKeys), and <see cref="Recv"/> consumes peer bytes and returns the matching
/// salt. State is kept in-memory (object form); proto serialization for durable storage is layered on
/// separately. Only V1 is implemented (libsignal mandates V1/min-V1 on both ends).
/// </summary>
public sealed class SpqrRatchet
{
    private SckaStates? _inner;           // null ⇒ V0 (disabled)
    private Chain? _chain;

    // Version-negotiation block (present until the first recv); needed to lazily build the Chain.
    private bool _hasVn;
    private byte[]? _vnAuthKey;
    private Direction _vnDirection;
    private SpqrVersion _vnMinVersion;
    private ChainParams _vnChainParams = new();

    private SpqrRatchet() { }

    public SpqrVersion CurrentVersion => _inner is null ? SpqrVersion.V0 : SpqrVersion.V1;

    public static SpqrRatchet InitialState(SpqrParams p)
    {
        var r = new SpqrRatchet();
        if (p.Version == SpqrVersion.V0) return r;   // empty/disabled

        r._inner = p.Direction == Direction.A2B
            ? SckaStates.InitA(p.AuthKey)
            : SckaStates.InitB(p.AuthKey);
        r._hasVn = true;
        r._vnAuthKey = p.AuthKey;
        r._vnDirection = p.Direction;
        r._vnMinVersion = p.MinVersion;
        r._vnChainParams = p.ChainParams;
        return r;
    }

    public sealed class SendOutput
    {
        public required byte[] Message { get; init; }   // wire pq_ratchet bytes (empty for V0)
        public byte[]? Key { get; init; }               // 32-byte HKDF salt, or null
    }

    public SendOutput Send()
    {
        if (_inner is null) return new SendOutput { Message = Array.Empty<byte>(), Key = null };

        SckaStates.SendResult sr = _inner.Send();

        Chain? chain;
        if (_chain is not null) chain = _chain;
        else if (_hasVn) chain = _vnMinVersion > SpqrVersion.V0 ? new Chain(_vnAuthKey!, _vnDirection, _vnChainParams) : null;
        else throw new SpqrException("chain not available");

        uint index; byte[] msgKey;
        if (chain is null) { index = 0; msgKey = Array.Empty<byte>(); }
        else
        {
            if (sr.Key is not null) chain.AddEpoch(sr.Key);
            (index, msgKey) = chain.SendKey(sr.Msg.Epoch - 1);
        }

        byte[] wire = SerializeMessage(sr.Msg, index);
        _inner = sr.State;
        if (chain is not null) _chain = chain;   // version_negotiation unchanged on send
        return new SendOutput { Message = wire, Key = msgKey.Length == 0 ? null : msgKey };
    }

    /// <summary>Process a peer's pq_ratchet bytes; returns the 32-byte message-key salt (or null).</summary>
    public byte[]? Recv(byte[] message)
    {
        if (_inner is null) return null;  // V0

        // Version negotiation: libsignal uses V1/min-V1 both ways, so msg version (1) == our version (1).
        SpqrVersion? msgVer = MsgVersion(message);
        if (msgVer is null) return null;                 // unsupported higher version: ignore
        if (msgVer.Value < SpqrVersion.V1)
            throw new SpqrException("SPQR version downgrade not supported");

        (SpqrMessage scka, uint index) = DeserializeMessage(message);
        SckaStates.RecvResult rr = _inner.Recv(scka);

        ulong msgKeyEpoch = scka.Epoch - 1;
        Chain chain = _chain ?? (_hasVn
            ? new Chain(_vnAuthKey!, _vnDirection, _vnChainParams)
            : throw new SpqrException("chain not available"));
        if (rr.Key is not null) chain.AddEpoch(rr.Key);
        byte[] msgKey = msgKeyEpoch == 0 && index == 0
            ? Array.Empty<byte>()
            : chain.RecvKey(msgKeyEpoch, index);

        _inner = rr.State;
        _chain = chain;
        _hasVn = false;   // receiving clears version negotiation
        return msgKey.Length == 0 ? null : msgKey;
    }

    // ── state serialization (local-only persistence) ──

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        if (_inner is null)
        {
            w.Write((byte)0);   // V0 / disabled
        }
        else
        {
            w.Write((byte)1);
            _inner.Write(w);
            w.Write(_chain is not null);
            _chain?.Write(w);
            w.Write(_hasVn);
            if (_hasVn)
            {
                w.WriteBlob(_vnAuthKey!);
                w.Write((int)_vnDirection);
                w.Write((int)_vnMinVersion);
                w.Write(_vnChainParams.MaxJump);
                w.Write(_vnChainParams.MaxOooKeys);
            }
        }
        w.Flush();
        return ms.ToArray();
    }

    public static SpqrRatchet Deserialize(byte[] bytes)
    {
        var r = new SpqrRatchet();
        using var ms = new MemoryStream(bytes);
        using var rd = new BinaryReader(ms);
        if (rd.ReadByte() == 0) return r;   // V0
        r._inner = SckaStates.Read(rd);
        if (rd.ReadBoolean()) r._chain = Chain.Read(rd);
        r._hasVn = rd.ReadBoolean();
        if (r._hasVn)
        {
            r._vnAuthKey = rd.ReadBlob();
            r._vnDirection = (Direction)rd.ReadInt32();
            r._vnMinVersion = (SpqrVersion)rd.ReadInt32();
            r._vnChainParams = new ChainParams { MaxJump = rd.ReadUInt32(), MaxOooKeys = rd.ReadUInt32() };
        }
        return r;
    }

    private static SpqrVersion? MsgVersion(byte[] msg)
    {
        if (msg.Length == 0) return SpqrVersion.V0;
        return msg[0] switch { 0 => SpqrVersion.V0, 1 => SpqrVersion.V1, _ => null };
    }

    // ── wire message format (see v1/chunked/states/serialize.rs) ──
    //   [version=1] [varint epoch] [varint index] [type:1] [optional: varint chunkIndex || 32B data]
    private enum MsgType : byte { None = 0, Hdr = 1, Ek = 2, EkCt1Ack = 3, Ct1Ack = 4, Ct1 = 5, Ct2 = 6 }

    private static byte[] SerializeMessage(SpqrMessage msg, uint index)
    {
        var o = new List<byte>(40) { (byte)SpqrVersion.V1 };
        EncodeVarint(msg.Epoch, o);
        EncodeVarint(index, o);
        MsgType type = msg.Payload.Kind switch
        {
            SpqrMsgKind.None => MsgType.None,
            SpqrMsgKind.Hdr => MsgType.Hdr,
            SpqrMsgKind.Ek => MsgType.Ek,
            SpqrMsgKind.EkCt1Ack => MsgType.EkCt1Ack,
            SpqrMsgKind.Ct1Ack => MsgType.Ct1Ack,
            SpqrMsgKind.Ct1 => MsgType.Ct1,
            SpqrMsgKind.Ct2 => MsgType.Ct2,
            _ => throw new SpqrException("bad payload"),
        };
        o.Add((byte)type);
        if (msg.Payload.Chunk is { } chunk)
        {
            EncodeVarint(chunk.Index, o);
            o.AddRange(chunk.Data);
        }
        return o.ToArray();
    }

    private static (SpqrMessage Msg, uint Index) DeserializeMessage(byte[] from)
    {
        if (from.Length == 0 || from[0] != (byte)SpqrVersion.V1) throw new SpqrException("message decode failed");
        int at = 1;
        ulong epoch = DecodeVarint(from, ref at);
        if (epoch == 0) throw new SpqrException("message decode failed");
        ulong indexU = DecodeVarint(from, ref at);
        if (indexU > uint.MaxValue) throw new SpqrException("message decode failed");
        if (at >= from.Length) throw new SpqrException("message decode failed");
        var type = (MsgType)from[at];
        at++;
        SpqrPayload payload = type switch
        {
            MsgType.None => SpqrPayload.None,
            MsgType.Ct1Ack => SpqrPayload.Ct1Ack(true),
            MsgType.Hdr => SpqrPayload.Hdr(DecodeChunk(from, ref at)),
            MsgType.Ek => SpqrPayload.Ek(DecodeChunk(from, ref at)),
            MsgType.EkCt1Ack => SpqrPayload.EkCt1Ack(DecodeChunk(from, ref at)),
            MsgType.Ct1 => SpqrPayload.Ct1(DecodeChunk(from, ref at)),
            MsgType.Ct2 => SpqrPayload.Ct2(DecodeChunk(from, ref at)),
            _ => throw new SpqrException("message decode failed"),
        };
        return (new SpqrMessage(epoch, payload), (uint)indexU);
    }

    private static SpqrChunk DecodeChunk(byte[] from, ref int at)
    {
        ulong index = DecodeVarint(from, ref at);
        int start = at;
        at += 32;
        if (at > from.Length || index > 65535) throw new SpqrException("message decode failed");
        return new SpqrChunk((ushort)index, from[start..at]);
    }

    private static void EncodeVarint(ulong a, List<byte> into)
    {
        for (int i = 0; i < 10; i++)
        {
            byte b = (byte)(a & 0x7F);
            if (a < 0x80) { into.Add(b); break; }
            into.Add((byte)(0x80 | b));
            a >>= 7;
        }
    }

    private static ulong DecodeVarint(byte[] from, ref int at)
    {
        ulong outv = 0;
        int start = at;
        if (start >= from.Length) throw new SpqrException("message decode failed");
        int max = Math.Min(10, from.Length - start);
        int i = 0;
        bool done = false;
        while (i < max && !done)
        {
            byte b = from[start + i];
            outv |= ((ulong)b & 0x7F) << (7 * i);
            i++;
            done = (b & 0x80) == 0;
        }
        if (!done) throw new SpqrException("message decode failed");
        at += i;
        return outv;
    }
}
