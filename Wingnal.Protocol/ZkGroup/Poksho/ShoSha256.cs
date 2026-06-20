using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Wingnal.Protocol.ZkGroup.Poksho;

/// <summary>
/// Byte-exact port of poksho's <c>ShoSha256</c> — the "innerpad" stateful hash object over SHA-256 (the
/// non-HMAC sibling of <see cref="ShoHmacSha256"/>). zkcredential's generic credential <c>SystemParams</c>
/// are derived through this. Absorbing prefixes a zero block + the chaining value; ratchet double-hashes;
/// squeeze is an SHA-256 PRF over (63 zeros‖0x01‖cv‖BE64(i)) re-ratcheting via (…‖0x02‖cv‖BE64(len)).
/// Validated against poksho's own test vectors.
/// </summary>
public sealed class ShoSha256
{
    private const int BlockLen = 64;
    private const int HashLen = 32;

    private byte[] _cv = new byte[HashLen];
    private IncrementalHash _hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private bool _absorbing;   // false = RATCHETED

    public ShoSha256(ReadOnlySpan<byte> label) => AbsorbAndRatchet(label);

    public void Absorb(ReadOnlySpan<byte> input)
    {
        if (!_absorbing)
        {
            _hasher.AppendData(new byte[BlockLen]);   // 64 zero bytes
            _hasher.AppendData(_cv);
            _absorbing = true;
        }
        _hasher.AppendData(input);
    }

    public void Ratchet()
    {
        if (!_absorbing) return;
        byte[] once = _hasher.GetHashAndReset();
        _cv = SHA256.HashData(once);                   // double hash
        _absorbing = false;
    }

    public void AbsorbAndRatchet(ReadOnlySpan<byte> input) { Absorb(input); Ratchet(); }

    public byte[] SqueezeAndRatchet(int outlen)
    {
        if (_absorbing) throw new InvalidOperationException("ShoSha256: must ratchet before squeezing");
        var output = new byte[outlen];
        for (int i = 0; i * HashLen < outlen; i++)
        {
            using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            h.AppendData(new byte[BlockLen - 1]);      // 63 zero bytes
            h.AppendData(new byte[] { 0x01 });
            h.AppendData(_cv);
            Span<byte> ctr = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(ctr, (ulong)i);
            h.AppendData(ctr);
            byte[] digest = h.GetHashAndReset();
            int num = Math.Min(HashLen, outlen - i * HashLen);
            Array.Copy(digest, 0, output, i * HashLen, num);
        }

        using var next = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        next.AppendData(new byte[BlockLen - 1]);
        next.AppendData(new byte[] { 0x02 });
        next.AppendData(_cv);
        Span<byte> lenBe = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(lenBe, (ulong)outlen);
        next.AppendData(lenBe);
        _cv = next.GetHashAndReset();
        return output;
    }

    /// <summary>squeeze 64 bytes → a pseudorandom Ristretto point (poksho ShoExt.get_point).</summary>
    public Curve.Ristretto255 GetPoint() => Curve.Ristretto255.FromUniformBytes(SqueezeAndRatchet(64));
}
