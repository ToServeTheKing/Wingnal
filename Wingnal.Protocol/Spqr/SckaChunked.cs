using System.IO;
using Enc = Wingnal.Protocol.Spqr.Polynomial.Encoder;
using Dec = Wingnal.Protocol.Spqr.Polynomial.Decoder;

namespace Wingnal.Protocol.Spqr;

/// <summary>A 32-byte fountain-code chunk with its index.</summary>
public sealed class SpqrChunk
{
    public ushort Index { get; }
    public byte[] Data { get; }   // 32
    public SpqrChunk(ushort index, byte[] data) { Index = index; Data = data; }
}

public enum SpqrMsgKind { None, Hdr, Ek, EkCt1Ack, Ct1Ack, Ct1, Ct2 }

/// <summary>The SPQR per-message payload (one of the V1Msg inner_msg variants).</summary>
public sealed class SpqrPayload
{
    public SpqrMsgKind Kind { get; }
    public SpqrChunk? Chunk { get; }
    public bool Ack { get; }

    private SpqrPayload(SpqrMsgKind kind, SpqrChunk? chunk, bool ack) { Kind = kind; Chunk = chunk; Ack = ack; }

    public static readonly SpqrPayload None = new(SpqrMsgKind.None, null, false);
    public static SpqrPayload Hdr(SpqrChunk c) => new(SpqrMsgKind.Hdr, c, false);
    public static SpqrPayload Ek(SpqrChunk c) => new(SpqrMsgKind.Ek, c, false);
    public static SpqrPayload EkCt1Ack(SpqrChunk c) => new(SpqrMsgKind.EkCt1Ack, c, false);
    public static SpqrPayload Ct1Ack(bool ack) => new(SpqrMsgKind.Ct1Ack, null, ack);
    public static SpqrPayload Ct1(SpqrChunk c) => new(SpqrMsgKind.Ct1, c, false);
    public static SpqrPayload Ct2(SpqrChunk c) => new(SpqrMsgKind.Ct2, c, false);
}

/// <summary>An SCKA message: an epoch plus a payload.</summary>
public sealed class SpqrMessage
{
    public ulong Epoch { get; }
    public SpqrPayload Payload { get; }
    public SpqrMessage(ulong epoch, SpqrPayload payload) { Epoch = epoch; Payload = payload; }
}

/// <summary>
/// The SPQR v1 chunked SCKA state machine (ported from SparsePostQuantumRatchet v1.5.1
/// src/v1/chunked/{states,send_ek,send_ct}.rs). It wraps the unchunked crypto states with polynomial
/// encoders/decoders so the large ML-KEM-768 header/ek/ct blobs are spread across many messages.
/// <see cref="Send"/> emits the next chunk (and possibly a new EpochSecret); <see cref="Recv"/> ingests
/// a peer chunk and advances state. Header/ct chunks carry an authenticator MAC appended to the blob.
/// </summary>
public sealed class SckaStates
{
    private const int HeaderSize = MlKem768.HeaderBytes;          // 64
    private const int MacSize = Authenticator.MacSize;            // 32
    private const int Ct1Size = MlKem768.Ct1Bytes;               // 960
    private const int Ct2Size = MlKem768.Ct2Bytes;               // 128
    private const int EkSize = MlKem768.Pk2Bytes;               // 1152

    public sealed class SendResult
    {
        public required SpqrMessage Msg { get; init; }
        public EpochSecret? Key { get; init; }
        public required SckaStates State { get; init; }
    }

    public sealed class RecvResult
    {
        public EpochSecret? Key { get; init; }
        public required SckaStates State { get; init; }
    }

    // Exactly one of these is non-null (mirrors the Rust States enum).
    private readonly object _inner;

    private SckaStates(object inner) => _inner = inner;

    public static SckaStates InitA(byte[] authKey) =>
        new(new CKeysUnsampled(UcKeysUnsampled.New(authKey)));

    public static SckaStates InitB(byte[] authKey) =>
        new(new CNoHeaderReceived(UcNoHeaderReceived.New(authKey),
            new Dec(HeaderSize + MacSize)));

    private static ulong EpochOf(object s) => s switch
    {
        CKeysUnsampled x => x.Uc.Epoch,
        CKeysSampled x => x.Uc.Epoch,
        CHeaderSent x => x.Uc.Epoch,
        CCt1Received x => x.Uc.Epoch,
        CEkSentCt1Received x => x.Uc.Epoch,
        CNoHeaderReceived x => x.Uc.Epoch,
        CHeaderReceived x => x.Uc.Epoch,
        CCt1Sampled x => x.Uc.Epoch,
        CEkReceivedCt1Sampled x => x.Uc.Epoch,
        CCt1Acknowledged x => x.Uc.Epoch,
        CCt2Sampled x => x.Uc.Epoch,
        _ => throw new SpqrException("unknown state"),
    };

    // ───────────────────────── send ─────────────────────────

    public SendResult Send()
    {
        switch (_inner)
        {
            // send_ek
            case CKeysUnsampled s:
            {
                ulong epoch = s.Uc.Epoch;
                (UcHeaderSent uc, byte[] hdr, byte[] mac) = s.Uc.SendHeader();
                var enc = new Enc(Cat(hdr, mac));
                SpqrChunk chunk = Next(enc);
                return new SendResult
                {
                    Msg = new SpqrMessage(epoch, SpqrPayload.Hdr(chunk)),
                    State = new SckaStates(new CKeysSampled(uc, enc)),
                };
            }
            case CKeysSampled s:
            {
                SpqrChunk chunk = Next(s.SendingHdr);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Hdr(chunk)),
                    State = this,
                };
            }
            case CHeaderSent s:
            {
                SpqrChunk chunk = Next(s.SendingEk);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Ek(chunk)),
                    State = this,
                };
            }
            case CCt1Received s:
            {
                SpqrChunk chunk = Next(s.SendingEk);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.EkCt1Ack(chunk)),
                    State = this,
                };
            }
            case CEkSentCt1Received s:
            {
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Ct1Ack(true)),
                    State = this,
                };
            }
            // send_ct
            case CNoHeaderReceived s:
            {
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.None),
                    State = this,
                };
            }
            case CHeaderReceived s:
            {
                ulong epoch = s.Uc.Epoch;
                (UcCt1Sent uc, byte[] ct1, EpochSecret secret) = s.Uc.SendCt1();
                var enc = new Enc(ct1);
                SpqrChunk chunk = Next(enc);
                return new SendResult
                {
                    Msg = new SpqrMessage(epoch, SpqrPayload.Ct1(chunk)),
                    Key = secret,
                    State = new SckaStates(new CCt1Sampled(uc, enc, s.ReceivingEk)),
                };
            }
            case CCt1Sampled s:
            {
                SpqrChunk chunk = Next(s.SendingCt1);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Ct1(chunk)),
                    State = this,
                };
            }
            case CEkReceivedCt1Sampled s:
            {
                SpqrChunk chunk = Next(s.SendingCt1);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Ct1(chunk)),
                    State = this,
                };
            }
            case CCt1Acknowledged s:
            {
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.None),
                    State = this,
                };
            }
            case CCt2Sampled s:
            {
                SpqrChunk chunk = Next(s.SendingCt2);
                return new SendResult
                {
                    Msg = new SpqrMessage(s.Uc.Epoch, SpqrPayload.Ct2(chunk)),
                    State = this,
                };
            }
            default: throw new SpqrException("unknown state");
        }
    }

    // ───────────────────────── recv ─────────────────────────

    public RecvResult Recv(SpqrMessage msg)
    {
        EpochSecret? key = null;
        object newState;
        ulong epoch = EpochOf(_inner);

        switch (_inner)
        {
            // send_ek
            case CKeysUnsampled s:
                RequireNotGreater(msg.Epoch, epoch);
                newState = s; // Less or Equal: stay
                break;

            case CKeysSampled s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch && msg.Payload.Kind == SpqrMsgKind.Ct1)
                {
                    UcEkSent uc; byte[] ek;
                    (uc, ek) = s.Uc.SendEk();
                    var ct1Dec = new Dec(Ct1Size);
                    ct1Dec.AddChunk(msg.Payload.Chunk!.Index, msg.Payload.Chunk.Data);
                    newState = new CHeaderSent(uc, new Enc(ek), ct1Dec);
                }
                else newState = s;
                break;

            case CHeaderSent s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch && msg.Payload.Kind == SpqrMsgKind.Ct1)
                {
                    s.ReceivingCt1.AddChunk(msg.Payload.Chunk!.Index, msg.Payload.Chunk.Data);
                    byte[]? decoded = s.ReceivingCt1.DecodedMessage();
                    if (decoded is not null)
                    {
                        UcEkSentCt1Received uc = s.Uc.RecvCt1(msg.Epoch, decoded);
                        newState = new CCt1Received(uc, s.SendingEk);
                    }
                    else newState = s;
                }
                else newState = s;
                break;

            case CCt1Received s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch && msg.Payload.Kind == SpqrMsgKind.Ct2)
                {
                    var ct2Dec = new Dec(Ct2Size + MacSize);
                    ct2Dec.AddChunk(msg.Payload.Chunk!.Index, msg.Payload.Chunk.Data);
                    newState = new CEkSentCt1Received(s.Uc, ct2Dec);
                }
                else newState = s;
                break;

            case CEkSentCt1Received s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch && msg.Payload.Kind == SpqrMsgKind.Ct2)
                {
                    s.ReceivingCt2.AddChunk(msg.Payload.Chunk!.Index, msg.Payload.Chunk.Data);
                    byte[]? decoded = s.ReceivingCt2.DecodedMessage();
                    if (decoded is not null)
                    {
                        byte[] ct2 = decoded[..Ct2Size];
                        byte[] mac = decoded[Ct2Size..];
                        (UcNoHeaderReceived uc, EpochSecret sec) = s.Uc.RecvCt2(ct2, mac);
                        key = sec;
                        newState = new CNoHeaderReceived(uc, new Dec(HeaderSize + MacSize));
                    }
                    else newState = s;
                }
                else newState = s;
                break;

            // send_ct
            case CNoHeaderReceived s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch && msg.Payload.Kind == SpqrMsgKind.Hdr)
                {
                    s.ReceivingHdr.AddChunk(msg.Payload.Chunk!.Index, msg.Payload.Chunk.Data);
                    byte[]? decoded = s.ReceivingHdr.DecodedMessage();
                    if (decoded is not null)
                    {
                        byte[] hdr = decoded[..HeaderSize];
                        byte[] mac = decoded[HeaderSize..];
                        UcHeaderReceived uc = s.Uc.RecvHeader(msg.Epoch, hdr, mac);
                        newState = new CHeaderReceived(uc, new Dec(EkSize));
                    }
                    else newState = s;
                }
                else newState = s;
                break;

            case CHeaderReceived s:
                RequireNotGreater(msg.Epoch, epoch);
                newState = s; // no recv transition; we only send_ct1 from here
                break;

            case CCt1Sampled s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch)
                {
                    SpqrChunk? chunk = null; bool ack = false;
                    if (msg.Payload.Kind == SpqrMsgKind.Ek) { chunk = msg.Payload.Chunk; ack = false; }
                    else if (msg.Payload.Kind == SpqrMsgKind.EkCt1Ack) { chunk = msg.Payload.Chunk; ack = true; }
                    if (chunk is not null)
                    {
                        s.ReceivingEk.AddChunk(chunk.Index, chunk.Data);
                        byte[]? decoded = s.ReceivingEk.DecodedMessage();
                        if (decoded is not null)
                        {
                            UcCt1SentEkReceived uc = s.Uc.RecvEk(msg.Epoch, decoded);
                            if (ack)
                            {
                                (UcCt2Sent uc2, byte[] ct2, byte[] mac) = uc.SendCt2();
                                newState = new CCt2Sampled(uc2, new Enc(Cat(ct2, mac)));
                            }
                            else newState = new CEkReceivedCt1Sampled(uc, s.SendingCt1);
                        }
                        else if (ack)
                            newState = new CCt1Acknowledged(s.Uc, s.ReceivingEk);
                        else newState = s;
                    }
                    else newState = s;
                }
                else newState = s;
                break;

            case CEkReceivedCt1Sampled s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch &&
                    ((msg.Payload.Kind == SpqrMsgKind.Ct1Ack && msg.Payload.Ack) ||
                      msg.Payload.Kind == SpqrMsgKind.EkCt1Ack))
                {
                    (UcCt2Sent uc2, byte[] ct2, byte[] mac) = s.Uc.SendCt2();
                    newState = new CCt2Sampled(uc2, new Enc(Cat(ct2, mac)));
                }
                else newState = s;
                break;

            case CCt1Acknowledged s:
                RequireNotGreater(msg.Epoch, epoch);
                if (msg.Epoch == epoch)
                {
                    SpqrChunk? chunk = msg.Payload.Kind is SpqrMsgKind.Ek or SpqrMsgKind.EkCt1Ack
                        ? msg.Payload.Chunk : null;
                    if (chunk is not null)
                    {
                        s.ReceivingEk.AddChunk(chunk.Index, chunk.Data);
                        byte[]? decoded = s.ReceivingEk.DecodedMessage();
                        if (decoded is not null)
                        {
                            UcCt1SentEkReceived uc = s.Uc.RecvEk(msg.Epoch, decoded);
                            (UcCt2Sent uc2, byte[] ct2, byte[] mac) = uc.SendCt2();
                            newState = new CCt2Sampled(uc2, new Enc(Cat(ct2, mac)));
                        }
                        else newState = s;
                    }
                    else newState = s;
                }
                else newState = s;
                break;

            case CCt2Sampled s:
                if (msg.Epoch > epoch)
                {
                    if (msg.Epoch == epoch + 1)
                    {
                        UcKeysUnsampled uc = s.Uc.RecvNextEpoch(msg.Epoch);
                        newState = new CKeysUnsampled(uc);
                    }
                    else throw new SpqrException($"epoch out of range: {msg.Epoch}");
                }
                else newState = s; // Less or Equal: stay
                break;

            default: throw new SpqrException("unknown state");
        }

        return new RecvResult { Key = key, State = newState == _inner ? this : new SckaStates(newState) };
    }

    private static void RequireNotGreater(ulong msgEpoch, ulong stateEpoch)
    {
        if (msgEpoch > stateEpoch) throw new SpqrException($"epoch out of range: {msgEpoch}");
    }

    private static SpqrChunk Next(Enc enc)
    {
        (ushort idx, byte[] data) = enc.NextChunk();
        return new SpqrChunk(idx, data);
    }

    private static byte[] Cat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    // ── serialization (local-only state persistence) ──

    internal void Write(BinaryWriter w)
    {
        switch (_inner)
        {
            case CKeysUnsampled s: w.Write((byte)1); WKeysUnsampled(w, s.Uc); break;
            case CKeysSampled s: w.Write((byte)2); WHeaderSent(w, s.Uc); s.SendingHdr.Write(w); break;
            case CHeaderSent s: w.Write((byte)3); WEkSent(w, s.Uc); s.SendingEk.Write(w); s.ReceivingCt1.Write(w); break;
            case CCt1Received s: w.Write((byte)4); WEkSentCt1Received(w, s.Uc); s.SendingEk.Write(w); break;
            case CEkSentCt1Received s: w.Write((byte)5); WEkSentCt1Received(w, s.Uc); s.ReceivingCt2.Write(w); break;
            case CNoHeaderReceived s: w.Write((byte)6); WNoHeaderReceived(w, s.Uc); s.ReceivingHdr.Write(w); break;
            case CHeaderReceived s: w.Write((byte)7); WHeaderReceived(w, s.Uc); s.ReceivingEk.Write(w); break;
            case CCt1Sampled s: w.Write((byte)8); WCt1Sent(w, s.Uc); s.SendingCt1.Write(w); s.ReceivingEk.Write(w); break;
            case CEkReceivedCt1Sampled s: w.Write((byte)9); WCt1SentEkReceived(w, s.Uc); s.SendingCt1.Write(w); break;
            case CCt1Acknowledged s: w.Write((byte)10); WCt1Sent(w, s.Uc); s.ReceivingEk.Write(w); break;
            case CCt2Sampled s: w.Write((byte)11); WCt2Sent(w, s.Uc); s.SendingCt2.Write(w); break;
            default: throw new SpqrException("unknown state");
        }
    }

    internal static SckaStates Read(BinaryReader r)
    {
        byte tag = r.ReadByte();
        object inner = tag switch
        {
            1 => new CKeysUnsampled(RKeysUnsampled(r)),
            2 => new CKeysSampled(RHeaderSent(r), Enc.Read(r)),
            3 => new CHeaderSent(REkSent(r), Enc.Read(r), Dec.Read(r)),
            4 => new CCt1Received(REkSentCt1Received(r), Enc.Read(r)),
            5 => new CEkSentCt1Received(REkSentCt1Received(r), Dec.Read(r)),
            6 => new CNoHeaderReceived(RNoHeaderReceived(r), Dec.Read(r)),
            7 => new CHeaderReceived(RHeaderReceived(r), Dec.Read(r)),
            8 => new CCt1Sampled(RCt1Sent(r), Enc.Read(r), Dec.Read(r)),
            9 => new CEkReceivedCt1Sampled(RCt1SentEkReceived(r), Enc.Read(r)),
            10 => new CCt1Acknowledged(RCt1Sent(r), Dec.Read(r)),
            11 => new CCt2Sampled(RCt2Sent(r), Enc.Read(r)),
            _ => throw new SpqrException("unknown state tag"),
        };
        return new SckaStates(inner);
    }

    // Unchunked-state field writers/readers (fields are public; Authenticator round-trips itself).
    private static void WKeysUnsampled(BinaryWriter w, UcKeysUnsampled u) { w.Write(u.Epoch); u.Auth.Write(w); }
    private static UcKeysUnsampled RKeysUnsampled(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r));

    private static void WHeaderSent(BinaryWriter w, UcHeaderSent u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Ek); w.WriteBlob(u.Dk); }
    private static UcHeaderSent RHeaderSent(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob(), r.ReadBlob());

    private static void WEkSent(BinaryWriter w, UcEkSent u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Dk); }
    private static UcEkSent REkSent(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob());

    private static void WEkSentCt1Received(BinaryWriter w, UcEkSentCt1Received u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Dk); w.WriteBlob(u.Ct1); }
    private static UcEkSentCt1Received REkSentCt1Received(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob(), r.ReadBlob());

    private static void WNoHeaderReceived(BinaryWriter w, UcNoHeaderReceived u) { w.Write(u.Epoch); u.Auth.Write(w); }
    private static UcNoHeaderReceived RNoHeaderReceived(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r));

    private static void WHeaderReceived(BinaryWriter w, UcHeaderReceived u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Hdr); }
    private static UcHeaderReceived RHeaderReceived(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob());

    private static void WCt1Sent(BinaryWriter w, UcCt1Sent u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Hdr); w.WriteBlob(u.Es); w.WriteBlob(u.Ct1); }
    private static UcCt1Sent RCt1Sent(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob(), r.ReadBlob(), r.ReadBlob());

    private static void WCt1SentEkReceived(BinaryWriter w, UcCt1SentEkReceived u) { w.Write(u.Epoch); u.Auth.Write(w); w.WriteBlob(u.Es); w.WriteBlob(u.Ek); w.WriteBlob(u.Ct1); }
    private static UcCt1SentEkReceived RCt1SentEkReceived(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r), r.ReadBlob(), r.ReadBlob(), r.ReadBlob());

    private static void WCt2Sent(BinaryWriter w, UcCt2Sent u) { w.Write(u.Epoch); u.Auth.Write(w); }
    private static UcCt2Sent RCt2Sent(BinaryReader r) => new(r.ReadUInt64(), Authenticator.Read(r));

    // ── chunked state holders (mirror proto V1State.Chunked.*) ──
    private sealed class CKeysUnsampled { public UcKeysUnsampled Uc; public CKeysUnsampled(UcKeysUnsampled uc) => Uc = uc; }
    private sealed class CKeysSampled { public UcHeaderSent Uc; public Enc SendingHdr; public CKeysSampled(UcHeaderSent uc, Enc h) { Uc = uc; SendingHdr = h; } }
    private sealed class CHeaderSent { public UcEkSent Uc; public Enc SendingEk; public Dec ReceivingCt1; public CHeaderSent(UcEkSent uc, Enc e, Dec d) { Uc = uc; SendingEk = e; ReceivingCt1 = d; } }
    private sealed class CCt1Received { public UcEkSentCt1Received Uc; public Enc SendingEk; public CCt1Received(UcEkSentCt1Received uc, Enc e) { Uc = uc; SendingEk = e; } }
    private sealed class CEkSentCt1Received { public UcEkSentCt1Received Uc; public Dec ReceivingCt2; public CEkSentCt1Received(UcEkSentCt1Received uc, Dec d) { Uc = uc; ReceivingCt2 = d; } }

    private sealed class CNoHeaderReceived { public UcNoHeaderReceived Uc; public Dec ReceivingHdr; public CNoHeaderReceived(UcNoHeaderReceived uc, Dec d) { Uc = uc; ReceivingHdr = d; } }
    private sealed class CHeaderReceived { public UcHeaderReceived Uc; public Dec ReceivingEk; public CHeaderReceived(UcHeaderReceived uc, Dec d) { Uc = uc; ReceivingEk = d; } }
    private sealed class CCt1Sampled { public UcCt1Sent Uc; public Enc SendingCt1; public Dec ReceivingEk; public CCt1Sampled(UcCt1Sent uc, Enc e, Dec d) { Uc = uc; SendingCt1 = e; ReceivingEk = d; } }
    private sealed class CEkReceivedCt1Sampled { public UcCt1SentEkReceived Uc; public Enc SendingCt1; public CEkReceivedCt1Sampled(UcCt1SentEkReceived uc, Enc e) { Uc = uc; SendingCt1 = e; } }
    private sealed class CCt1Acknowledged { public UcCt1Sent Uc; public Dec ReceivingEk; public CCt1Acknowledged(UcCt1Sent uc, Dec d) { Uc = uc; ReceivingEk = d; } }
    private sealed class CCt2Sampled { public UcCt2Sent Uc; public Enc SendingCt2; public CCt2Sampled(UcCt2Sent uc, Enc e) { Uc = uc; SendingCt2 = e; } }
}
