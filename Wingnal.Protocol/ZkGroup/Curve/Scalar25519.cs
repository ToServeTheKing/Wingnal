using System.Numerics;

namespace Wingnal.Protocol.ZkGroup.Curve;

/// <summary>
/// An integer modulo ℓ = 2²⁵² + 27742317777372353535851937790883648493 (the order of the Ristretto255 /
/// edwards25519 prime-order group). Backs zkgroup's scalar arithmetic. Implemented on
/// <see cref="BigInteger"/> for a clear first-correct version — NOT constant-time; harden with the ref10
/// <c>sc_*</c> routines later (see docs/GROUPS.md / SHORTCUTS.md). Canonical wire form is 32 little-endian
/// bytes.
/// </summary>
public readonly struct Scalar25519 : IEquatable<Scalar25519>
{
    /// <summary>The group order ℓ.</summary>
    public static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    private readonly BigInteger _v;   // always reduced into [0, L)

    private Scalar25519(BigInteger v)
    {
        BigInteger m = v % L;
        _v = m.Sign < 0 ? m + L : m;
    }

    public static Scalar25519 Zero => new(BigInteger.Zero);
    public static Scalar25519 One => new(BigInteger.One);

    /// <summary>Reduces a 32-byte little-endian value mod ℓ.</summary>
    public static Scalar25519 FromBytesModOrder(ReadOnlySpan<byte> le32) =>
        new(new BigInteger(le32, isUnsigned: true, isBigEndian: false));

    /// <summary>Reduces a 64-byte little-endian value mod ℓ (uniform hash → scalar).</summary>
    public static Scalar25519 FromBytesModOrderWide(ReadOnlySpan<byte> le64) =>
        new(new BigInteger(le64, isUnsigned: true, isBigEndian: false));

    public static Scalar25519 FromBigInteger(BigInteger v) => new(v);

    /// <summary>Parses a 32-byte little-endian scalar, returning null if it is not canonical (≥ ℓ).</summary>
    public static Scalar25519? FromCanonicalBytes(ReadOnlySpan<byte> le32)
    {
        if (le32.Length != 32) return null;
        var v = new BigInteger(le32, isUnsigned: true, isBigEndian: false);
        return v >= L ? null : new Scalar25519(v);
    }

    /// <summary>32-byte little-endian canonical encoding.</summary>
    public byte[] ToBytes()
    {
        byte[] raw = _v.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        Array.Copy(raw, result, Math.Min(raw.Length, 32));
        return result;
    }

    public BigInteger ToBigInteger() => _v;

    public static Scalar25519 Add(Scalar25519 a, Scalar25519 b) => new(a._v + b._v);
    public static Scalar25519 Sub(Scalar25519 a, Scalar25519 b) => new(a._v - b._v);
    public static Scalar25519 Mul(Scalar25519 a, Scalar25519 b) => new(a._v * b._v);
    public static Scalar25519 Negate(Scalar25519 a) => new(-a._v);

    /// <summary>Multiplicative inverse mod ℓ (ℓ is prime, so via Fermat: a^(ℓ-2)).</summary>
    public Scalar25519 Invert() => new(BigInteger.ModPow(_v, L - 2, L));

    public bool Equals(Scalar25519 other) => _v == other._v;
    public override bool Equals(object? obj) => obj is Scalar25519 s && Equals(s);
    public override int GetHashCode() => _v.GetHashCode();
}
