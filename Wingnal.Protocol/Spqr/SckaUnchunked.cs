using System.Security.Cryptography;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Protocol.Spqr;

/// <summary>
/// The "unchunked" SPQR v1 SCKA crypto states (ported from SparsePostQuantumRatchet v1.5.1
/// src/v1/unchunked/{send_ek,send_ct}.rs). These hold the raw ML-KEM-768 material + Authenticator and
/// perform the actual KEM operations; the chunked layer (<see cref="SckaChunked"/>) spreads the large
/// header/ek/ct byte blobs across many ratchet messages via the polynomial fountain code.
///
/// Two role tracks alternate per epoch:
///   send_ek: KeysUnsampled → HeaderSent → EkSent → EkSentCt1Received → (switch to send_ct, epoch+1)
///   send_ct: NoHeaderReceived → HeaderReceived → Ct1Sent → Ct1SentEkReceived → Ct2Sent → (switch, epoch+1)
/// </summary>
internal static class SckaKdf
{
    private static readonly byte[] ZeroSalt = new byte[32];
    private static readonly byte[] SckaKeyLabel = "Signal_PQCKA_V1_MLKEM768:SCKA Key"u8.ToArray();

    /// <summary>HKDF(salt=0^32, ikm=ss, info="…SCKA Key"‖BE64(epoch), 32) — turns a raw ML-KEM shared
    /// secret into the per-epoch secret mixed into the symmetric Chain.</summary>
    public static byte[] DeriveEpochSecret(byte[] ss, ulong epoch)
    {
        var info = new byte[SckaKeyLabel.Length + 8];
        Buffer.BlockCopy(SckaKeyLabel, 0, info, 0, SckaKeyLabel.Length);
        for (int i = 7; i >= 0; i--) { info[SckaKeyLabel.Length + i] = (byte)(epoch & 0xFF); epoch >>= 8; }
        return CryptoPrimitives.Hkdf(ss, ZeroSalt, info, 32);
    }

    public static byte[] Random32()
    {
        var b = new byte[32];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}

// ───────────────────────── send_ek track ─────────────────────────

internal sealed class UcKeysUnsampled
{
    public ulong Epoch;
    public Authenticator Auth;

    public UcKeysUnsampled(ulong epoch, Authenticator auth) { Epoch = epoch; Auth = auth; }
    public static UcKeysUnsampled New(byte[] authKey) => new(1, new Authenticator(authKey, 1));

    /// <summary>Generates a fresh ML-KEM keypair, MACs its header, advances to HeaderSent.</summary>
    public (UcHeaderSent State, byte[] Hdr, byte[] Mac) SendHeader()
    {
        MlKem768.Keys keys = MlKem768.Generate(SckaKdf.Random32(), SckaKdf.Random32());
        byte[] mac = Auth.MacHeader(Epoch, keys.Header);
        return (new UcHeaderSent(Epoch, Auth, keys.Ek, keys.Dk), keys.Header, mac);
    }
}

internal sealed class UcHeaderSent
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Ek;   // 1152
    public byte[] Dk;   // 2400

    public UcHeaderSent(ulong epoch, Authenticator auth, byte[] ek, byte[] dk)
    { Epoch = epoch; Auth = auth; Ek = ek; Dk = dk; }

    public (UcEkSent State, byte[] Ek) SendEk() => (new UcEkSent(Epoch, Auth, Dk), Ek);
}

internal sealed class UcEkSent
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Dk;

    public UcEkSent(ulong epoch, Authenticator auth, byte[] dk) { Epoch = epoch; Auth = auth; Dk = dk; }

    public UcEkSentCt1Received RecvCt1(ulong epoch, byte[] ct1)
    {
        if (epoch != Epoch) throw new SpqrException("epoch mismatch");
        return new UcEkSentCt1Received(Epoch, Auth, Dk, ct1);
    }
}

internal sealed class UcEkSentCt1Received
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Dk;
    public byte[] Ct1;  // 960

    public UcEkSentCt1Received(ulong epoch, Authenticator auth, byte[] dk, byte[] ct1)
    { Epoch = epoch; Auth = auth; Dk = dk; Ct1 = ct1; }

    /// <summary>Decapsulates ct1‖ct2, derives + mixes the epoch secret, verifies the ciphertext MAC,
    /// and switches into the send_ct track for the next epoch.</summary>
    public (UcNoHeaderReceived State, EpochSecret Secret) RecvCt2(byte[] ct2, byte[] mac)
    {
        byte[] ss = MlKem768.DecapsIncremental(Dk, Ct1, ct2);
        byte[] secret = SckaKdf.DeriveEpochSecret(ss, Epoch);
        Auth.Update(Epoch, secret);
        var full = new byte[Ct1.Length + ct2.Length];
        Buffer.BlockCopy(Ct1, 0, full, 0, Ct1.Length);
        Buffer.BlockCopy(ct2, 0, full, Ct1.Length, ct2.Length);
        if (!Auth.VerifyCiphertext(Epoch, full, mac))
            throw new SpqrException("ciphertext MAC verification failed");
        return (new UcNoHeaderReceived(Epoch + 1, Auth), new EpochSecret(Epoch, secret));
    }
}

// ───────────────────────── send_ct track ─────────────────────────

internal sealed class UcNoHeaderReceived
{
    public ulong Epoch;
    public Authenticator Auth;

    public UcNoHeaderReceived(ulong epoch, Authenticator auth) { Epoch = epoch; Auth = auth; }
    public static UcNoHeaderReceived New(byte[] authKey) => new(1, new Authenticator(authKey, 1));

    public UcHeaderReceived RecvHeader(ulong epoch, byte[] hdr, byte[] mac)
    {
        if (epoch != Epoch) throw new SpqrException("epoch mismatch");
        if (!Auth.VerifyHeader(Epoch, hdr, mac)) throw new SpqrException("header MAC verification failed");
        return new UcHeaderReceived(Epoch, Auth, hdr);
    }
}

internal sealed class UcHeaderReceived
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Hdr;  // 64

    public UcHeaderReceived(ulong epoch, Authenticator auth, byte[] hdr) { Epoch = epoch; Auth = auth; Hdr = hdr; }

    /// <summary>encaps1 against the received header, derives + mixes the epoch secret.</summary>
    public (UcCt1Sent State, byte[] Ct1, EpochSecret Secret) SendCt1()
    {
        MlKem768.Encaps1(Hdr, SckaKdf.Random32(), out byte[] ct1, out byte[] es, out byte[] ss);
        byte[] secret = SckaKdf.DeriveEpochSecret(ss, Epoch);
        Auth.Update(Epoch, secret);
        return (new UcCt1Sent(Epoch, Auth, Hdr, es, ct1), ct1, new EpochSecret(Epoch, secret));
    }
}

internal sealed class UcCt1Sent
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Hdr;  // 64
    public byte[] Es;   // encaps state (local)
    public byte[] Ct1;  // 960

    public UcCt1Sent(ulong epoch, Authenticator auth, byte[] hdr, byte[] es, byte[] ct1)
    { Epoch = epoch; Auth = auth; Hdr = hdr; Es = es; Ct1 = ct1; }

    public UcCt1SentEkReceived RecvEk(ulong epoch, byte[] ek)
    {
        if (epoch != Epoch) throw new SpqrException("epoch mismatch");
        if (!MlKem768.EkMatchesHeader(ek, Hdr)) throw new SpqrException("erroneous data received");
        return new UcCt1SentEkReceived(Epoch, Auth, Es, ek, Ct1);
    }
}

internal sealed class UcCt1SentEkReceived
{
    public ulong Epoch;
    public Authenticator Auth;
    public byte[] Es;
    public byte[] Ek;   // 1152
    public byte[] Ct1;  // 960

    public UcCt1SentEkReceived(ulong epoch, Authenticator auth, byte[] es, byte[] ek, byte[] ct1)
    { Epoch = epoch; Auth = auth; Es = es; Ek = ek; Ct1 = ct1; }

    /// <summary>encaps2 to produce ct2, then MAC ct1‖ct2.</summary>
    public (UcCt2Sent State, byte[] Ct2, byte[] Mac) SendCt2()
    {
        byte[] ct2 = MlKem768.Encaps2(Ek, Es);
        var full = new byte[Ct1.Length + ct2.Length];
        Buffer.BlockCopy(Ct1, 0, full, 0, Ct1.Length);
        Buffer.BlockCopy(ct2, 0, full, Ct1.Length, ct2.Length);
        byte[] mac = Auth.MacCiphertext(Epoch, full);
        return (new UcCt2Sent(Epoch, Auth), ct2, mac);
    }
}

internal sealed class UcCt2Sent
{
    public ulong Epoch;
    public Authenticator Auth;

    public UcCt2Sent(ulong epoch, Authenticator auth) { Epoch = epoch; Auth = auth; }

    public UcKeysUnsampled RecvNextEpoch(ulong nextEpoch)
    {
        if (nextEpoch != Epoch + 1) throw new SpqrException("epoch must advance by one");
        return new UcKeysUnsampled(Epoch + 1, Auth);
    }
}
