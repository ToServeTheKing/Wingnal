using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Wingnal.Protocol.ZkGroup.Poksho;

/// <summary>
/// Byte-exact port of libsignal poksho's <c>ShoHmacSha256</c> — a "stateful hash object" (sponge over
/// HMAC-SHA256) used throughout zkgroup for Fiat-Shamir transcripts and for deriving scalars/points.
/// Absorbing appends to an HMAC keyed by the chaining value; ratchet finalizes (message‖0x00) into a new
/// chaining value; squeeze is an HMAC-PRF expansion keyed by the chaining value over (BE64(i)‖0x01), and
/// re-ratchets via (BE64(outlen)‖0x02). Validated against poksho's own test vectors.
/// </summary>
public sealed class ShoHmacSha256
{
    private const int HashLen = 32;

    private byte[] _cv = new byte[HashLen];   // chaining value (starts all-zero, mode = RATCHETED)
    private byte[] _key = new byte[HashLen];   // HMAC key in use while ABSORBING (the cv at absorb time)
    private readonly List<byte> _buffer = new();
    private bool _absorbing;                   // false = RATCHETED

    public ShoHmacSha256(ReadOnlySpan<byte> label) => AbsorbAndRatchet(label);

    private ShoHmacSha256() { }

    /// <summary>Deep copy of the current state (poksho proves fork the transcript with a clone).</summary>
    public ShoHmacSha256 Clone()
    {
        var c = new ShoHmacSha256
        {
            _cv = (byte[])_cv.Clone(),
            _key = (byte[])_key.Clone(),
            _absorbing = _absorbing,
        };
        c._buffer.AddRange(_buffer);
        return c;
    }

    public void Absorb(ReadOnlySpan<byte> input)
    {
        if (!_absorbing)
        {
            _key = (byte[])_cv.Clone();
            _buffer.Clear();
            _absorbing = true;
        }
        _buffer.AddRange(input.ToArray());
    }

    public void Ratchet()
    {
        if (!_absorbing) return;
        _buffer.Add(0x00);
        _cv = Hmac(_key, _buffer.ToArray());
        _buffer.Clear();
        _absorbing = false;
    }

    public void AbsorbAndRatchet(ReadOnlySpan<byte> input) { Absorb(input); Ratchet(); }

    public byte[] SqueezeAndRatchet(int outlen)
    {
        if (_absorbing) throw new InvalidOperationException("ShoHmacSha256: must ratchet before squeezing");

        var output = new byte[outlen];
        int pos = 0;
        for (int i = 0; i * HashLen < outlen; i++)
        {
            var msg = new byte[9];
            BinaryPrimitives.WriteUInt64BigEndian(msg, (ulong)i);
            msg[8] = 0x01;
            byte[] digest = Hmac(_cv, msg);
            int num = Math.Min(HashLen, outlen - i * HashLen);
            Array.Copy(digest, 0, output, pos, num);
            pos += num;
        }

        var next = new byte[9];
        BinaryPrimitives.WriteUInt64BigEndian(next, (ulong)outlen);
        next[8] = 0x02;
        _cv = Hmac(_cv, next);
        return output;
    }

    /// <summary>squeeze 64 bytes → scalar mod ℓ (poksho ShoExt.get_scalar).</summary>
    public Curve.Scalar25519 GetScalar() => Curve.Scalar25519.FromBytesModOrderWide(SqueezeAndRatchet(64));

    /// <summary>squeeze 64 bytes → a pseudorandom Ristretto point (poksho ShoExt.get_point).</summary>
    public Curve.Ristretto255 GetPoint() => Curve.Ristretto255.FromUniformBytes(SqueezeAndRatchet(64));

    private static byte[] Hmac(byte[] key, byte[] message)
    {
        using var h = new HMACSHA256(key);
        return h.ComputeHash(message);
    }
}
