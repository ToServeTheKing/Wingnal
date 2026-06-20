using System.Security.Cryptography;
using System.Text;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Protocol.Spqr;

/// <summary>
/// The SPQR authenticator (ported from SparsePostQuantumRatchet v1.5.1 src/authenticator.rs). Keeps a
/// rolling root key + MAC key, advanced each epoch via HKDF, and MACs the chunked header/ciphertext
/// material so a man-in-the-middle can't tamper with the spread-out ML-KEM bytes. HKDF-SHA256 +
/// HMAC-SHA256; the domain-separation strings must match Signal byte-for-byte.
/// </summary>
public sealed class Authenticator
{
    public const int MacSize = 32;

    private static readonly byte[] ZeroSalt = new byte[32];
    private static readonly byte[] UpdateInfo = "Signal_PQCKA_V1_MLKEM768:Authenticator Update"u8.ToArray();
    private static readonly byte[] CiphertextLabel = "Signal_PQCKA_V1_MLKEM768:ciphertext"u8.ToArray();
    private static readonly byte[] HeaderLabel = "Signal_PQCKA_V1_MLKEM768:ekheader"u8.ToArray();

    private byte[] _rootKey = new byte[32];
    private byte[] _macKey = new byte[32];

    public Authenticator(byte[] rootKey, ulong epoch) => Update(epoch, rootKey);

    private Authenticator(byte[] rootKey, byte[] macKey, bool _)
    {
        _rootKey = (byte[])rootKey.Clone();
        _macKey = (byte[])macKey.Clone();
    }

    public byte[] RootKey => _rootKey;
    public byte[] MacKey => _macKey;

    /// <summary>Deep copy (used so a failed recv doesn't corrupt committed state).</summary>
    public Authenticator Clone() => new(_rootKey, _macKey, true);

    internal void Write(System.IO.BinaryWriter w) { w.WriteBlob(_rootKey); w.WriteBlob(_macKey); }
    internal static Authenticator Read(System.IO.BinaryReader r) => new(r.ReadBlob(), r.ReadBlob(), true);

    public void Update(ulong epoch, byte[] k)
    {
        byte[] ikm = Concat(_rootKey, k);
        byte[] info = Concat(UpdateInfo, Be64(epoch));
        byte[] okm = CryptoPrimitives.Hkdf(ikm, ZeroSalt, info, 64);
        _rootKey = okm[..32];
        _macKey = okm[32..];
    }

    public byte[] MacCiphertext(ulong epoch, byte[] ciphertext) =>
        Mac(CiphertextLabel, epoch, ciphertext);

    public byte[] MacHeader(ulong epoch, byte[] header) =>
        Mac(HeaderLabel, epoch, header);

    public bool VerifyCiphertext(ulong epoch, byte[] ciphertext, byte[] expectedMac) =>
        CryptographicOperations.FixedTimeEquals(expectedMac, MacCiphertext(epoch, ciphertext));

    public bool VerifyHeader(ulong epoch, byte[] header, byte[] expectedMac) =>
        CryptographicOperations.FixedTimeEquals(expectedMac, MacHeader(epoch, header));

    private byte[] Mac(byte[] label, ulong epoch, byte[] data)
    {
        byte[] macData = Concat(label, Be64(epoch), data);
        return CryptoPrimitives.HmacSha256(_macKey, macData); // already 32 bytes
    }

    private static byte[] Be64(ulong v)
    {
        var b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return b;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int len = 0;
        foreach (byte[] p in parts) len += p.Length;
        var result = new byte[len];
        int off = 0;
        foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, result, off, p.Length); off += p.Length; }
        return result;
    }
}
