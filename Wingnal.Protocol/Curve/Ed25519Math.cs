using System.Numerics;

namespace Wingnal.Protocol.Curve;

/// <summary>
/// Compact reference implementation of the Ed25519 group over GF(2^255-19), using
/// <see cref="BigInteger"/> affine coordinates. Chosen for auditability over speed: signing a
/// handful of prekeys and verifying signatures does not need constant-time field arithmetic.
///
/// This mirrors the original ed25519 reference (djb / RFC 8032 "slow" reference). It is shared by
/// both <see cref="XEd25519"/> and the RFC 8032 known-answer tests, so passing those KATs validates
/// the field/group/scalar/encode/decode routines used in production.
/// </summary>
internal static class Ed25519Math
{
    /// <summary>Field prime 2^255 - 19.</summary>
    internal static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    /// <summary>Group order L = 2^252 + 27742317777372353535851937790883648493.</summary>
    internal static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    /// <summary>Curve constant d = -121665/121666 mod p.</summary>
    private static readonly BigInteger D = Mod(-121665 * Inverse(121666), P);

    /// <summary>sqrt(-1) mod p = 2^((p-1)/4).</summary>
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) / 4, P);

    /// <summary>Base point B = (Bx, 4/5).</summary>
    private static readonly Point B = MakeBasePoint();

    internal readonly struct Point
    {
        internal readonly BigInteger X;
        internal readonly BigInteger Y;
        internal Point(BigInteger x, BigInteger y) { X = x; Y = y; }
        internal Point Negate() => new Point(Mod(-X, P), Y);
    }

    private static readonly Point Identity = new Point(BigInteger.Zero, BigInteger.One);

    private static Point MakeBasePoint()
    {
        BigInteger by = Mod(4 * Inverse(5), P);
        BigInteger bx = RecoverX(by, 0);
        return new Point(bx, by);
    }

    internal static BigInteger Mod(BigInteger a, BigInteger m)
    {
        BigInteger r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    internal static BigInteger Inverse(BigInteger z) => BigInteger.ModPow(Mod(z, P), P - 2, P);

    /// <summary>Edwards addition (unified; also doubles) on -x^2 + y^2 = 1 + d x^2 y^2.</summary>
    internal static Point Add(Point p1, Point p2)
    {
        BigInteger x1 = p1.X, y1 = p1.Y, x2 = p2.X, y2 = p2.Y;
        BigInteger dxy = Mod(D * x1 * x2 % P * y1 % P * y2, P);
        BigInteger x3 = Mod((x1 * y2 + x2 * y1) * Inverse(Mod(1 + dxy, P)), P);
        BigInteger y3 = Mod((y1 * y2 + x1 * x2) * Inverse(Mod(1 - dxy, P)), P);
        return new Point(x3, y3);
    }

    internal static Point ScalarMult(Point p, BigInteger e)
    {
        Point result = Identity;
        Point addend = p;
        while (e.Sign > 0)
        {
            if (!e.IsEven) result = Add(result, addend);
            addend = Add(addend, addend);
            e >>= 1;
        }
        return result;
    }

    internal static Point ScalarMultBase(BigInteger e) => ScalarMult(B, e);

    /// <summary>Encode a point to 32 bytes (little-endian y with the low bit of x in bit 255).</summary>
    internal static byte[] Encode(Point p)
    {
        byte[] bytes = ToLe32(Mod(p.Y, P));
        if (!Mod(p.X, P).IsEven) bytes[31] |= 0x80;
        return bytes;
    }

    private static BigInteger RecoverX(BigInteger y, int sign)
    {
        BigInteger y2 = Mod(y * y, P);
        BigInteger num = Mod(y2 - 1, P);
        BigInteger den = Mod(D * y2 + 1, P);
        BigInteger xx = Mod(num * Inverse(den), P);
        BigInteger x = BigInteger.ModPow(xx, (P + 3) / 8, P);
        if (!Mod(x * x - xx, P).IsZero) x = Mod(x * SqrtM1, P);
        if (!Mod(x * x - xx, P).IsZero) return BigInteger.MinusOne; // not on curve
        if (((int)(x & 1)) != sign) x = Mod(-x, P);
        return x;
    }

    /// <summary>Decode a point from its y-coordinate and sign bit. Returns false if not on curve.</summary>
    internal static bool TryDecode(BigInteger y, int sign, out Point point)
    {
        BigInteger x = RecoverX(Mod(y, P), sign);
        if (x.Sign < 0) { point = default; return false; }
        point = new Point(x, y);
        return true;
    }

    /// <summary>Reduce a 64-byte little-endian hash to a scalar mod L.</summary>
    internal static BigInteger ScReduce(ReadOnlySpan<byte> hash64) => Mod(FromLe(hash64), L);

    internal static BigInteger FromLe(ReadOnlySpan<byte> bytes) =>
        new BigInteger(bytes, isUnsigned: true, isBigEndian: false);

    internal static byte[] ToLe32(BigInteger value)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        Array.Copy(raw, result, Math.Min(raw.Length, 32));
        return result;
    }
}
