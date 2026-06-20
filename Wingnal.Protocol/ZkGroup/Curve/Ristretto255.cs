namespace Wingnal.Protocol.ZkGroup.Curve;

/// <summary>
/// Hand-port of the Ristretto255 prime-order group (RFC 9496) on top of <see cref="Fe"/> / BouncyCastle's
/// edwards25519 base field — BouncyCastle 2.5.1 has no Ristretto, and zkgroup is built entirely on this
/// group. Provides point add / scalar-mul, the canonical 32-byte encode/decode, and the one-way map
/// <see cref="FromUniformBytes"/> (Elligator) used for hash-to-group. Correctness is gated by the RFC 9496
/// Appendix-A test vectors (multiples of the generator, invalid-encoding rejection, hash-to-group).
///
/// NOTE: scalar multiplication here is NOT constant-time (double-and-add with a data-dependent add). For
/// the client-side zkgroup proofs this is acceptable for a first correct version; harden later. See
/// docs/GROUPS.md / SHORTCUTS.md.
/// </summary>
public sealed class Ristretto255
{
    // ── field constants (computed from definitions; SQRT_M1 hardcoded + self-checked in tests) ──

    /// <summary>sqrt(-1) mod p, COMPUTED (not transcribed): p ≡ 5 (mod 8) ⇒ 2 is a non-residue, so
    /// 2^((p-1)/4) is a square root of -1, and (p-1)/4 = 2·(p-5)/8 + 1 ⇒ SQRT_M1 = 2·(2^((p-5)/8))².
    /// Self-checked SQRT_M1² == -1 by the Phase B vector test.</summary>
    internal static readonly Fe SqrtM1 = BuildSqrtM1();

    private static Fe BuildSqrtM1()
    {
        Fe two = Fe.Add(Fe.One(), Fe.One());
        return Fe.Mul(Fe.Sqr(Fe.PowP58(two)), two);
    }

    internal static readonly Fe D = BuildD();          // edwards25519 d = -121665/121666
    private static readonly Fe D2 = Fe.Add(D, D);       // 2d, for the addition formula
    private static readonly Fe OneMinusDSq = Fe.Sub(Fe.One(), Fe.Sqr(D));        // 1 - d²
    private static readonly Fe DMinusOneSq = Fe.Sqr(Fe.Sub(D, Fe.One()));        // (d - 1)²
    // a = -1, so a - d = a*d - 1 = -1 - d.
    private static readonly Fe AMinusD = Fe.Sub(Fe.Neg(Fe.One()), D);            // -1 - d
    // 1/sqrt(-1-d): the abs (even) root — matches dalek INVSQRT_A_MINUS_D (even).
    internal static readonly Fe InvSqrtAMinusD = SqrtRatioM1(Fe.One(), AMinusD).root;
    // sqrt(-1-d): dalek SQRT_AD_MINUS_ONE is the odd root, so negate the abs (even) root.
    private static readonly Fe SqrtADMinusOne = Fe.Neg(SqrtRatioM1(AMinusD, Fe.One()).root);

    // ── Lizard constants (computed from the definitions in the dalek-signal lizard_constants test) ──
    // SQRT_ID = sqrt(i·d) (abs root); DP1_OVER_DM1 = (d+1)/(d-1);
    // MDOUBLE_INVSQRT_A_MINUS_D = -2/sqrt(a-d); MIDOUBLE = that·i; MINVSQRT_ONE_PLUS_D = -1/sqrt(1+d).
    private static readonly Fe SqrtId = SqrtRatioM1(Fe.Mul(SqrtM1, D), Fe.One()).root;
    private static readonly Fe Dp1OverDm1 = Fe.Mul(Fe.Add(D, Fe.One()), Fe.Inv(Fe.Sub(D, Fe.One())));
    private static readonly Fe MDoubleInvSqrtAMinusD = Fe.Neg(Fe.Add(InvSqrtAMinusD, InvSqrtAMinusD));
    private static readonly Fe MiDoubleInvSqrtAMinusD = Fe.Mul(MDoubleInvSqrtAMinusD, SqrtM1);
    private static readonly Fe MInvSqrtOnePlusD = Fe.Neg(SqrtRatioM1(Fe.One(), Fe.Add(D, Fe.One())).root);

    private static Fe BuildD()
    {
        // d = -121665/121666 (computed, not transcribed).
        var num = new byte[32]; num[0] = 0x41; num[1] = 0xDB; num[2] = 0x01;   // 121665 = 0x1DB41
        var den = new byte[32]; den[0] = 0x42; den[1] = 0xDB; den[2] = 0x01;   // 121666 = 0x1DB42
        return Fe.Neg(Fe.Mul(Fe.Decode(num), Fe.Inv(Fe.Decode(den))));
    }

    // ── point (extended twisted-Edwards coordinates X:Y:Z:T) ──

    private readonly Fe _x, _y, _z, _t;

    private Ristretto255(Fe x, Fe y, Fe z, Fe t) { _x = x; _y = y; _z = z; _t = t; }

    /// <summary>The identity element.</summary>
    public static Ristretto255 Identity => new(Fe.Zero(), Fe.One(), Fe.One(), Fe.Zero());

    /// <summary>The Ristretto255 generator (canonical encoding e2f2ae0a…).</summary>
    public static Ristretto255 BasePoint => Decode(
        Convert.FromHexString("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"))!;

    /// <summary>Group addition (the complete a=-1 twisted-Edwards formula; also valid for doubling).</summary>
    public static Ristretto255 Add(Ristretto255 p, Ristretto255 q)
    {
        Fe a = Fe.Mul(Fe.Sub(p._y, p._x), Fe.Sub(q._y, q._x));   // (Y1-X1)(Y2-X2)
        Fe b = Fe.Mul(Fe.Add(p._y, p._x), Fe.Add(q._y, q._x));   // (Y1+X1)(Y2+X2)
        Fe c = Fe.Mul(Fe.Mul(p._t, q._t), D2);                   // 2d·T1·T2
        Fe d = Fe.Add(Fe.Mul(p._z, q._z), Fe.Mul(p._z, q._z));   // 2·Z1·Z2
        Fe e = Fe.Sub(b, a), f = Fe.Sub(d, c), g = Fe.Add(d, c), h = Fe.Add(b, a);
        return new Ristretto255(Fe.Mul(e, f), Fe.Mul(g, h), Fe.Mul(f, g), Fe.Mul(e, h));
    }

    /// <summary>Group negation: −(X:Y:Z:T) = (−X:Y:Z:−T).</summary>
    public static Ristretto255 Negate(Ristretto255 p) => new(Fe.Neg(p._x), p._y, p._z, Fe.Neg(p._t));

    /// <summary>scalar·this.</summary>
    public Ristretto255 Multiply(Scalar25519 s) => Multiply(s.ToBytes());

    /// <summary>scalar·this (double-and-add, MSB first; scalar is 32-byte little-endian).</summary>
    public Ristretto255 Multiply(ReadOnlySpan<byte> scalarLe)
    {
        Ristretto255 r = Identity;
        for (int i = 255; i >= 0; i--)
        {
            r = Add(r, r);
            if (((scalarLe[i >> 3] >> (i & 7)) & 1) == 1) r = Add(r, this);
        }
        return r;
    }

    /// <summary>Ristretto equality: two representatives are equal iff X1·Y2 == Y1·X2 and Y1·Y2 == X1·X2
    /// (RFC 9496 §4.3.6). Cheaper + sign-robust vs comparing encodings.</summary>
    public bool ConstantTimeEquals(Ristretto255 q)
    {
        bool a = Fe.Mul(_x, q._y).ConstantTimeEquals(Fe.Mul(_y, q._x));
        bool b = Fe.Mul(_y, q._y).ConstantTimeEquals(Fe.Mul(_x, q._x));
        return a || b;
    }

    // ── encode / decode (RFC 9496 §4.3.1–4.3.2) ──

    public byte[] Encode()
    {
        Fe u1 = Fe.Mul(Fe.Add(_z, _y), Fe.Sub(_z, _y));   // (Z+Y)(Z-Y)
        Fe u2 = Fe.Mul(_x, _y);
        (_, Fe invsqrt) = SqrtRatioM1(Fe.One(), Fe.Mul(u1, Fe.Sqr(u2)));
        Fe den1 = Fe.Mul(invsqrt, u1);
        Fe den2 = Fe.Mul(invsqrt, u2);
        Fe zInv = Fe.Mul(Fe.Mul(den1, den2), _t);
        Fe ix = Fe.Mul(_x, SqrtM1);
        Fe iy = Fe.Mul(_y, SqrtM1);
        Fe enchantedDenominator = Fe.Mul(den1, InvSqrtAMinusD);
        bool rotate = Fe.Mul(_t, zInv).IsNegative();
        Fe x = Fe.Select(_x, iy, rotate);
        Fe y = Fe.Select(_y, ix, rotate);
        Fe denInv = Fe.Select(den2, enchantedDenominator, rotate);
        y = Fe.Select(y, Fe.Neg(y), Fe.Mul(x, zInv).IsNegative());
        Fe s = Fe.Mul(denInv, Fe.Sub(_z, y)).Abs();
        return s.Encode();
    }

    public static Ristretto255? Decode(ReadOnlySpan<byte> bytes32)
    {
        if (bytes32.Length != 32) return null;
        Fe s = Fe.Decode(bytes32);
        // s must be the canonical encoding of a non-negative field element.
        if (!s.Encode().AsSpan().SequenceEqual(bytes32) || s.IsNegative()) return null;

        Fe ss = Fe.Sqr(s);
        Fe u1 = Fe.Sub(Fe.One(), ss);                  // 1 - s²
        Fe u2 = Fe.Add(Fe.One(), ss);                  // 1 + s²
        Fe u2Sqr = Fe.Sqr(u2);
        Fe v = Fe.Sub(Fe.Neg(Fe.Mul(D, Fe.Sqr(u1))), u2Sqr);   // -(d·u1²) - u2²
        (bool wasSquare, Fe invsqrt) = SqrtRatioM1(Fe.One(), Fe.Mul(v, u2Sqr));
        Fe denX = Fe.Mul(invsqrt, u2);
        Fe denY = Fe.Mul(Fe.Mul(invsqrt, denX), v);
        Fe x = Fe.Mul(Fe.Add(s, s), denX).Abs();       // |2·s·den_x|
        Fe y = Fe.Mul(u1, denY);
        Fe t = Fe.Mul(x, y);
        if (!wasSquare || t.IsNegative() || y.IsZero()) return null;
        return new Ristretto255(x, y, Fe.One(), t);
    }

    // ── hash-to-group (RFC 9496 §4.3.4) ──

    /// <summary>Maps 64 uniformly-random bytes to a group element (two Elligator maps + add).</summary>
    public static Ristretto255 FromUniformBytes(ReadOnlySpan<byte> bytes64)
    {
        Ristretto255 p1 = ElligatorRistrettoFlavor(Fe.Decode(bytes64[..32]));
        Ristretto255 p2 = ElligatorRistrettoFlavor(Fe.Decode(bytes64[32..64]));
        return Add(p1, p2);
    }

    /// <summary>Maps a single 32-byte field element to a group element (one Elligator map). This is
    /// dalek-signal's <c>from_uniform_bytes_single_elligator</c> / zkgroup's <c>get_point_single_elligator</c>,
    /// and the encode half of Lizard.</summary>
    public static Ristretto255 FromSingleElligatorBytes(ReadOnlySpan<byte> bytes32) =>
        ElligatorRistrettoFlavor(Fe.Decode(bytes32));

    /// <summary>The Ristretto-flavored Elligator2 map (RFC 9496 §4.3.4 MAP). Public so Lizard can reuse it.</summary>
    internal static Ristretto255 ElligatorRistrettoFlavor(Fe t)
    {
        Fe r = Fe.Mul(SqrtM1, Fe.Sqr(t));
        Fe u = Fe.Mul(Fe.Add(r, Fe.One()), OneMinusDSq);
        Fe c = Fe.Neg(Fe.One());
        Fe v = Fe.Mul(Fe.Sub(c, Fe.Mul(r, D)), Fe.Add(r, D));
        (bool wasSquare, Fe s) = SqrtRatioM1(u, v);
        Fe sPrime = Fe.Neg(Fe.Mul(s, t).Abs());
        s = Fe.Select(sPrime, s, wasSquare);
        c = Fe.Select(r, c, wasSquare);
        Fe n = Fe.Sub(Fe.Mul(Fe.Mul(c, Fe.Sub(r, Fe.One())), DMinusOneSq), v);
        Fe w0 = Fe.Add(Fe.Mul(s, v), Fe.Mul(s, v));   // 2·s·v
        Fe w1 = Fe.Mul(n, SqrtADMinusOne);
        Fe w2 = Fe.Sub(Fe.One(), Fe.Sqr(s));
        Fe w3 = Fe.Add(Fe.One(), Fe.Sqr(s));
        return new Ristretto255(Fe.Mul(w0, w3), Fe.Mul(w2, w1), Fe.Mul(w1, w3), Fe.Mul(w0, w2));
    }

    // ── sqrt_ratio_i (RFC 9496 §4.3) : returns (wasSquare, |sqrt(u/v)|) ──

    internal static (bool wasSquare, Fe root) SqrtRatioM1(Fe u, Fe v)
    {
        Fe v3 = Fe.Mul(Fe.Sqr(v), v);
        Fe v7 = Fe.Mul(Fe.Sqr(v3), v);
        Fe r = Fe.Mul(Fe.Mul(u, v3), Fe.PowP58(Fe.Mul(u, v7)));
        Fe check = Fe.Mul(v, Fe.Sqr(r));
        Fe uNeg = Fe.Neg(u);
        bool correct = check.ConstantTimeEquals(u);
        bool flipped = check.ConstantTimeEquals(uNeg);
        bool flippedI = check.ConstantTimeEquals(Fe.Mul(uNeg, SqrtM1));
        Fe rPrime = Fe.Mul(SqrtM1, r);
        r = Fe.Select(r, rPrime, flipped || flippedI);
        return (correct || flipped, r.Abs());
    }

    // ── Elligator inverse (for Lizard decode) — port of the dalek-signal lizard fork ──

    private readonly struct JacobiPoint
    {
        public readonly Fe S, T;
        public JacobiPoint(Fe s, Fe t) { S = s; T = t; }
        public JacobiPoint Dual() => new(Fe.Neg(S), Fe.Neg(T));

        /// <summary>Computes the field element that Elligator2 maps to this Jacobi-quartic point, if any.</summary>
        public (bool ok, Fe fe) ElligatorInv()
        {
            Fe outFe = Fe.Zero();
            bool sIsZero = S.IsZero();
            bool tEqualsOne = T.ConstantTimeEquals(Fe.One());
            outFe = Fe.Select(outFe, SqrtId, tEqualsOne);
            bool ret = sIsZero;
            bool done = sIsZero;

            Fe a = Fe.Mul(Fe.Add(T, Fe.One()), Dp1OverDm1);
            Fe a2 = Fe.Sqr(a);
            Fe s2 = Fe.Sqr(S);
            Fe s4 = Fe.Sqr(s2);
            Fe invSqY = Fe.Mul(Fe.Sub(s4, a2), SqrtM1);
            (bool sq, Fe y) = SqrtRatioM1(Fe.One(), invSqY);   // invsqrt
            ret = ret || sq;
            done = done || !sq;

            Fe pms2 = Fe.Select(s2, Fe.Neg(s2), S.IsNegative());   // sign(s)·s²
            Fe x = Fe.Mul(Fe.Add(a, pms2), y);
            x = Fe.Select(x, Fe.Neg(x), x.IsNegative());           // |x|
            outFe = Fe.Select(outFe, x, !done);
            return (ret, outFe);
        }
    }

    /// <summary>Computes the (at most 8) positive field elements f with this == ElligatorRistrettoFlavor(f),
    /// plus a bitmask of which slots are set. Assumes this is even. Port of dalek-signal's
    /// <c>elligator_ristretto_flavor_inverse</c>.</summary>
    internal (byte mask, Fe[] fes) ElligatorInverse()
    {
        JacobiPoint[] jcs = ToJacobiQuarticRistretto();
        var fes = new Fe[8];
        for (int i = 0; i < 8; i++) fes[i] = Fe.One();
        byte mask = 0;
        for (int i = 0; i < 4; i++)
        {
            (bool ok0, Fe fe0) = jcs[i].ElligatorInv();
            fes[2 * i] = fe0;
            if (ok0) mask |= (byte)(1 << (2 * i));
            (bool ok1, Fe fe1) = jcs[i].Dual().ElligatorInv();
            fes[2 * i + 1] = fe1;
            if (ok1) mask |= (byte)(1 << (2 * i + 1));
        }
        return (mask, fes);
    }

    private JacobiPoint[] ToJacobiQuarticRistretto()
    {
        Fe x2 = Fe.Sqr(_x), y2 = Fe.Sqr(_y), y4 = Fe.Sqr(y2), z2 = Fe.Sqr(_z);
        Fe zMinY = Fe.Sub(_z, _y), zPlY = Fe.Add(_z, _y);
        Fe z2MinY2 = Fe.Sub(z2, y2);

        // gamma = 1/sqrt(Y⁴·X²·(Z²−Y²))
        (_, Fe gamma) = SqrtRatioM1(Fe.One(), Fe.Mul(Fe.Mul(y4, x2), z2MinY2));
        Fe den = Fe.Mul(gamma, y2);
        Fe sOverX = Fe.Mul(den, zMinY);
        Fe spOverXp = Fe.Mul(den, zPlY);
        Fe s0 = Fe.Mul(sOverX, _x);
        Fe s1 = Fe.Mul(Fe.Neg(spOverXp), _x);
        Fe tmp = Fe.Mul(MDoubleInvSqrtAMinusD, _z);
        Fe t0 = Fe.Mul(tmp, sOverX);
        Fe t1 = Fe.Mul(tmp, spOverXp);

        // den = -1/sqrt(1+d)·(Y²−Z²)·gamma  (substitution (X,Y,Z) -> (Y,X,iZ))
        Fe den2 = Fe.Mul(Fe.Mul(Fe.Neg(z2MinY2), MInvSqrtOnePlusD), gamma);
        Fe iz = Fe.Mul(SqrtM1, _z);
        Fe izMinX = Fe.Sub(iz, _x), izPlX = Fe.Add(iz, _x);
        Fe sOverY = Fe.Mul(den2, izMinX);
        Fe spOverYp = Fe.Mul(den2, izPlX);
        Fe s2 = Fe.Mul(sOverY, _y);
        Fe s3 = Fe.Mul(Fe.Neg(spOverYp), _y);
        Fe tmp2 = Fe.Mul(MDoubleInvSqrtAMinusD, iz);
        Fe t2 = Fe.Mul(tmp2, sOverY);
        Fe t3 = Fe.Mul(tmp2, spOverYp);

        // Special case X=0 or Y=0 (then sᵢ=tᵢ=0): return fixed coset points.
        bool xy0 = _x.IsZero() || _y.IsZero();
        t0 = Fe.Select(t0, Fe.One(), xy0);
        t1 = Fe.Select(t1, Fe.One(), xy0);
        t2 = Fe.Select(t2, MiDoubleInvSqrtAMinusD, xy0);
        t3 = Fe.Select(t3, MiDoubleInvSqrtAMinusD, xy0);
        s2 = Fe.Select(s2, Fe.One(), xy0);
        s3 = Fe.Select(s3, Fe.Neg(Fe.One()), xy0);

        return new[]
        {
            new JacobiPoint(s0, t0), new JacobiPoint(s1, t1),
            new JacobiPoint(s2, t2), new JacobiPoint(s3, t3),
        };
    }
}
