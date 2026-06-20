using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Wingnal.Protocol.ZkGroup.Curve;

/// <summary>
/// A field element of GF(2²⁵⁵−19), wrapping BouncyCastle's vetted constant-time <see cref="X25519Field"/>
/// representation (10 limbs) with value-semantics helpers (each op returns a fresh element, so BC's
/// not-alias-safe Mul/Sqr are always called with distinct outputs). Every returned element is carried, so
/// it is safe to feed straight into another Mul/Sqr. This is the base field for the Ristretto255 group
/// hand-port (zkgroup) — see <see cref="Ristretto255"/>.
/// </summary>
internal sealed class Fe
{
    internal readonly int[] L;   // 10-limb X25519Field representation

    private Fe(int[] l) => L = l;

    public static Fe Zero() { var f = new Fe(X25519Field.Create()); X25519Field.Zero(f.L); return f; }
    public static Fe One() { var f = new Fe(X25519Field.Create()); X25519Field.One(f.L); return f; }

    /// <summary>Decodes 32 little-endian bytes, masking bit 255 (dalek <c>FieldElement::from_bytes</c>
    /// semantics). The value is reduced mod p on the next Normalize/Encode.</summary>
    public static Fe Decode(ReadOnlySpan<byte> bytes32)
    {
        Span<byte> b = stackalloc byte[32];
        bytes32[..32].CopyTo(b);
        b[31] &= 0x7f;
        var f = new Fe(X25519Field.Create());
        X25519Field.Decode(b.ToArray(), 0, f.L);
        return f;
    }

    /// <summary>Canonical 32-byte little-endian encoding (reduced mod p; bit 255 = 0).</summary>
    public byte[] Encode()
    {
        int[] t = (int[])L.Clone();
        X25519Field.Normalize(t);
        var b = new byte[32];
        X25519Field.Encode(t, b, 0);
        return b;
    }

    public Fe Clone() => new((int[])L.Clone());

    public static Fe Add(Fe a, Fe b) { var r = new Fe(X25519Field.Create()); X25519Field.Add(a.L, b.L, r.L); X25519Field.Carry(r.L); return r; }
    public static Fe Sub(Fe a, Fe b) { var r = new Fe(X25519Field.Create()); X25519Field.Sub(a.L, b.L, r.L); X25519Field.Carry(r.L); return r; }
    public static Fe Mul(Fe a, Fe b) { var r = new Fe(X25519Field.Create()); X25519Field.Mul(a.L, b.L, r.L); return r; }
    public static Fe Sqr(Fe a) { var r = new Fe(X25519Field.Create()); X25519Field.Sqr(a.L, r.L); return r; }
    public static Fe Inv(Fe a) { var r = new Fe(X25519Field.Create()); X25519Field.Inv(a.L, r.L); return r; }

    public static Fe Neg(Fe a) { var r = a.Clone(); X25519Field.CNegate(1, r.L); X25519Field.Carry(r.L); return r; }

    private static Fe SqrN(Fe x, int n) { Fe r = x; for (int i = 0; i < n; i++) r = Sqr(r); return r; }

    /// <summary>x^((p−5)/8) = x^(2²⁵²−3), the inverse-fourth-root exponent used by sqrt_ratio. ref10's
    /// pow22523 addition chain (BC's equivalent <c>X25519Field.PowPm5d8</c> is internal).</summary>
    public static Fe PowP58(Fe z)
    {
        Fe t0 = Sqr(z);                       // z^2
        Fe t1 = Sqr(Sqr(t0));                 // z^8
        t1 = Mul(z, t1);                      // z^9
        t0 = Mul(t0, t1);                     // z^11
        t0 = Sqr(t0);                         // z^22
        t0 = Mul(t1, t0);                     // z^(2^5-1)
        t1 = SqrN(t0, 5); t0 = Mul(t1, t0);   // 2^10-1
        t1 = SqrN(t0, 10); t1 = Mul(t1, t0);  // 2^20-1
        Fe t2 = SqrN(t1, 20); t1 = Mul(t2, t1); // 2^40-1
        t1 = SqrN(t1, 10); t0 = Mul(t1, t0);  // 2^50-1
        t1 = SqrN(t0, 50); t1 = Mul(t1, t0);  // 2^100-1
        t2 = SqrN(t1, 100); t1 = Mul(t2, t1); // 2^200-1
        t1 = SqrN(t1, 50); t0 = Mul(t1, t0);  // 2^250-1
        t0 = Sqr(Sqr(t0));                    // 2^252-4
        return Mul(t0, z);                    // 2^252-3
    }

    /// <summary>cond ? b : a (constant-time select).</summary>
    public static Fe Select(Fe a, Fe b, bool cond)
    {
        var r = a.Clone();
        X25519Field.CMov(cond ? -1 : 0, b.L, 0, r.L, 0);
        return r;
    }

    public bool IsNegative() => (Encode()[0] & 1) == 1;
    public bool IsZero() => Equals(Zero());
    public bool ConstantTimeEquals(Fe other) => Encode().AsSpan().SequenceEqual(other.Encode());
    public bool Equals(Fe other) => ConstantTimeEquals(other);

    /// <summary>|x| = (x is negative) ? −x : x.</summary>
    public Fe Abs() => IsNegative() ? Neg(this) : Clone();
}
