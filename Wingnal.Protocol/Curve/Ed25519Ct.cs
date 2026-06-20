using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Wingnal.Protocol.Curve;

/// <summary>
/// Constant-time Ed25519 primitives for the SIGNING path (the only place a long-term secret is used),
/// built on BouncyCastle's vetted constant-time field <see cref="X25519Field"/>. Provides:
/// a constant-time fixed-base scalar multiply (no data-dependent branches/table indexing) and the
/// ref10 constant-time scalar arithmetic mod L (<see cref="ScReduce"/>, <see cref="ScMulAdd"/>).
///
/// Correctness is gated by a cross-check test: signatures produced via these must be byte-identical to
/// the existing KAT-validated reference (<c>Ed25519Math</c>) for the same inputs, so a bug here can't
/// silently change/break signatures.
/// </summary>
internal static class Ed25519Ct
{
    // Base point B (x,y), little-endian 32-byte encodings (standard Ed25519 generator).
    private static readonly byte[] BxBytes = Convert.FromHexString("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921");
    private static readonly byte[] ByBytes = Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666");

    private static readonly int[] D2 = BuildD2();
    private static readonly Pt Base = BuildBase();

    private sealed class Pt
    {
        public readonly int[] X = X25519Field.Create();
        public readonly int[] Y = X25519Field.Create();
        public readonly int[] Z = X25519Field.Create();
        public readonly int[] T = X25519Field.Create();
    }

    // d = -121665/121666 (mod p); compute it from the definition to avoid transcription error.
    private static int[] BuildD2()
    {
        byte[] numBytes = new byte[32]; numBytes[0] = 0x41; numBytes[1] = 0xDB; numBytes[2] = 0x01; // 121665 = 0x1DB41
        byte[] denBytes = new byte[32]; denBytes[0] = 0x42; denBytes[1] = 0xDB; denBytes[2] = 0x01; // 121666 = 0x1DB42

        int[] num = X25519Field.Create(); X25519Field.Decode(numBytes, 0, num);
        int[] den = X25519Field.Create(); X25519Field.Decode(denBytes, 0, den);
        int[] dinv = X25519Field.Create(); X25519Field.Inv(den, dinv);
        int[] d = X25519Field.Create(); X25519Field.Mul(num, dinv, d);
        X25519Field.CNegate(1, d); X25519Field.Carry(d);              // d = -num/den
        int[] d2 = X25519Field.Create(); X25519Field.Add(d, d, d2); X25519Field.Carry(d2);
        return d2;
    }

    private static Pt BuildBase()
    {
        var b = new Pt();
        X25519Field.Decode(BxBytes, 0, b.X);
        X25519Field.Decode(ByBytes, 0, b.Y);
        X25519Field.One(b.Z);
        X25519Field.Mul(b.X, b.Y, b.T);
        return b;
    }

    // ── constant-time fixed-base scalar multiply ──

    /// <summary>Returns the 32-byte encoding of <c>scalar·B</c>, constant-time in the scalar bits.</summary>
    public static byte[] ScalarMultBaseEncode(byte[] scalar)
    {
        var r = new Pt();                 // identity (0, 1, 1, 0)
        X25519Field.Zero(r.X); X25519Field.One(r.Y); X25519Field.One(r.Z); X25519Field.Zero(r.T);
        var added = new Pt();

        for (int i = 255; i >= 0; i--)
        {
            Double(r, r);
            Add(r, Base, added);
            int bit = (scalar[i >> 3] >> (i & 7)) & 1;
            CMov(bit, added, r);
        }
        return Encode(r);
    }

    private static void Add(Pt p, Pt q, Pt outp)
    {
        // No Mul/Sqr writes into one of its own inputs (BC's field Mul is not alias-safe).
        int[] A = X25519Field.Create(), B = X25519Field.Create(), C = X25519Field.Create();
        int[] D = X25519Field.Create(), E = X25519Field.Create(), F = X25519Field.Create();
        int[] G = X25519Field.Create(), H = X25519Field.Create();
        int[] t1 = X25519Field.Create(), t2 = X25519Field.Create();

        X25519Field.Sub(p.Y, p.X, t1); X25519Field.Sub(q.Y, q.X, t2); X25519Field.Mul(t1, t2, A); // A=(Y1-X1)(Y2-X2)
        X25519Field.Add(p.Y, p.X, t1); X25519Field.Add(q.Y, q.X, t2); X25519Field.Mul(t1, t2, B); // B=(Y1+X1)(Y2+X2)
        X25519Field.Mul(p.T, q.T, t1); X25519Field.Mul(t1, D2, C);                                // C=2d*T1*T2
        X25519Field.Mul(p.Z, q.Z, t2); X25519Field.Add(t2, t2, D);                                // D=2*Z1*Z2
        X25519Field.Sub(B, A, E); X25519Field.Carry(E);
        X25519Field.Sub(D, C, F); X25519Field.Carry(F);
        X25519Field.Add(D, C, G); X25519Field.Carry(G);
        X25519Field.Add(B, A, H); X25519Field.Carry(H);
        X25519Field.Mul(E, F, outp.X);
        X25519Field.Mul(G, H, outp.Y);
        X25519Field.Mul(E, H, outp.T);
        X25519Field.Mul(F, G, outp.Z);
    }

    // Dedicated doubling for twisted Edwards with a = -1 (dbl-2008-hwcd, specialized):
    //   A=X², B=Y², C=2Z², E=(X+Y)²-A-B, G=B-A, F=G-C, H=-(A+B).
    private static void Double(Pt p, Pt outp)
    {
        int[] A = X25519Field.Create(), B = X25519Field.Create(), C = X25519Field.Create();
        int[] E = X25519Field.Create(), F = X25519Field.Create(), G = X25519Field.Create();
        int[] H = X25519Field.Create(), t1 = X25519Field.Create(), t2 = X25519Field.Create();

        X25519Field.Sqr(p.X, A);
        X25519Field.Sqr(p.Y, B);
        X25519Field.Sqr(p.Z, t1); X25519Field.Add(t1, t1, C);              // C = 2Z²
        X25519Field.Add(p.X, p.Y, t1); X25519Field.Sqr(t1, t2);           // t2 = (X+Y)²
        X25519Field.Sub(t2, A, t1); X25519Field.Sub(t1, B, E); X25519Field.Carry(E);   // E = (X+Y)² - A - B
        X25519Field.Sub(B, A, G); X25519Field.Carry(G);                                // G = B - A
        X25519Field.Sub(G, C, F); X25519Field.Carry(F);                                // F = G - C
        X25519Field.Add(A, B, H); X25519Field.CNegate(1, H); X25519Field.Carry(H);     // H = -(A + B)
        X25519Field.Mul(E, F, outp.X);
        X25519Field.Mul(G, H, outp.Y);
        X25519Field.Mul(E, H, outp.T);
        X25519Field.Mul(F, G, outp.Z);
    }

    private static void CMov(int cond, Pt src, Pt dst)
    {
        int mask = -(cond & 1);   // BC's CMov wants a full word mask (0 or 0xFFFFFFFF), not 0/1
        X25519Field.CMov(mask, src.X, 0, dst.X, 0);
        X25519Field.CMov(mask, src.Y, 0, dst.Y, 0);
        X25519Field.CMov(mask, src.Z, 0, dst.Z, 0);
        X25519Field.CMov(mask, src.T, 0, dst.T, 0);
    }

    private static byte[] Encode(Pt p)
    {
        int[] zInv = X25519Field.Create(), x = X25519Field.Create(), y = X25519Field.Create();
        X25519Field.Inv(p.Z, zInv);
        X25519Field.Mul(p.X, zInv, x); X25519Field.Normalize(x);
        X25519Field.Mul(p.Y, zInv, y); X25519Field.Normalize(y);

        var yBytes = new byte[32];
        X25519Field.Encode(y, yBytes, 0);
        var xBytes = new byte[32];
        X25519Field.Encode(x, xBytes, 0);
        yBytes[31] |= (byte)((xBytes[0] & 1) << 7);
        return yBytes;
    }

    // ── ref10 constant-time scalar arithmetic mod L (faithful portable port of sc.c) ──

    private static long Load3(byte[] x, int o) =>
        (x[o] & 0xFFL) | ((x[o + 1] & 0xFFL) << 8) | ((x[o + 2] & 0xFFL) << 16);

    private static long Load4(byte[] x, int o) =>
        (x[o] & 0xFFL) | ((x[o + 1] & 0xFFL) << 8) | ((x[o + 2] & 0xFFL) << 16) | ((x[o + 3] & 0xFFL) << 24);

    /// <summary>Reduces a 64-byte little-endian value mod L → 32 bytes.</summary>
    public static byte[] ScReduce(byte[] s)
    {
        long s0 = 0x1FFFFF & Load3(s, 0);
        long s1 = 0x1FFFFF & (Load4(s, 2) >> 5);
        long s2 = 0x1FFFFF & (Load3(s, 5) >> 2);
        long s3 = 0x1FFFFF & (Load4(s, 7) >> 7);
        long s4 = 0x1FFFFF & (Load4(s, 10) >> 4);
        long s5 = 0x1FFFFF & (Load3(s, 13) >> 1);
        long s6 = 0x1FFFFF & (Load4(s, 15) >> 6);
        long s7 = 0x1FFFFF & (Load3(s, 18) >> 3);
        long s8 = 0x1FFFFF & Load3(s, 21);
        long s9 = 0x1FFFFF & (Load4(s, 23) >> 5);
        long s10 = 0x1FFFFF & (Load3(s, 26) >> 2);
        long s11 = 0x1FFFFF & (Load4(s, 28) >> 7);
        long s12 = 0x1FFFFF & (Load4(s, 31) >> 4);
        long s13 = 0x1FFFFF & (Load3(s, 34) >> 1);
        long s14 = 0x1FFFFF & (Load4(s, 36) >> 6);
        long s15 = 0x1FFFFF & (Load3(s, 39) >> 3);
        long s16 = 0x1FFFFF & Load3(s, 42);
        long s17 = 0x1FFFFF & (Load4(s, 44) >> 5);
        long s18 = 0x1FFFFF & (Load3(s, 47) >> 2);
        long s19 = 0x1FFFFF & (Load4(s, 49) >> 7);
        long s20 = 0x1FFFFF & (Load4(s, 52) >> 4);
        long s21 = 0x1FFFFF & (Load3(s, 55) >> 1);
        long s22 = 0x1FFFFF & (Load4(s, 57) >> 6);
        long s23 = Load4(s, 60) >> 3;
        long carry;

        s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183; s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
        s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183; s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
        s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183; s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
        s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183; s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
        s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183; s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
        s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183; s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;

        carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
        carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
        carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
        carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
        carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
        carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;

        s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183; s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
        s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183; s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
        s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183; s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
        s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183; s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
        s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183; s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
        s12 = 0;

        carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
        carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
        carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
        carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
        carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
        carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
        carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;

        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
        s12 = 0;

        carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
        carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
        carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
        carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
        carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
        carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
        carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
        carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
        carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
        carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
        carry = s10 >> 21; s11 += carry; s10 -= carry << 21;
        carry = s11 >> 21; s12 += carry; s11 -= carry << 21;

        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;

        carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
        carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
        carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
        carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
        carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
        carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
        carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
        carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
        carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
        carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
        carry = s10 >> 21; s11 += carry; s10 -= carry << 21;

        return Pack(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11);
    }

    /// <summary>Returns (a*b + c) mod L, all 32-byte little-endian scalars.</summary>
    public static byte[] ScMulAdd(byte[] a, byte[] b, byte[] c)
    {
        long a0 = 0x1FFFFF & Load3(a, 0);
        long a1 = 0x1FFFFF & (Load4(a, 2) >> 5);
        long a2 = 0x1FFFFF & (Load3(a, 5) >> 2);
        long a3 = 0x1FFFFF & (Load4(a, 7) >> 7);
        long a4 = 0x1FFFFF & (Load4(a, 10) >> 4);
        long a5 = 0x1FFFFF & (Load3(a, 13) >> 1);
        long a6 = 0x1FFFFF & (Load4(a, 15) >> 6);
        long a7 = 0x1FFFFF & (Load3(a, 18) >> 3);
        long a8 = 0x1FFFFF & Load3(a, 21);
        long a9 = 0x1FFFFF & (Load4(a, 23) >> 5);
        long a10 = 0x1FFFFF & (Load3(a, 26) >> 2);
        long a11 = Load4(a, 28) >> 7;
        long b0 = 0x1FFFFF & Load3(b, 0);
        long b1 = 0x1FFFFF & (Load4(b, 2) >> 5);
        long b2 = 0x1FFFFF & (Load3(b, 5) >> 2);
        long b3 = 0x1FFFFF & (Load4(b, 7) >> 7);
        long b4 = 0x1FFFFF & (Load4(b, 10) >> 4);
        long b5 = 0x1FFFFF & (Load3(b, 13) >> 1);
        long b6 = 0x1FFFFF & (Load4(b, 15) >> 6);
        long b7 = 0x1FFFFF & (Load3(b, 18) >> 3);
        long b8 = 0x1FFFFF & Load3(b, 21);
        long b9 = 0x1FFFFF & (Load4(b, 23) >> 5);
        long b10 = 0x1FFFFF & (Load3(b, 26) >> 2);
        long b11 = Load4(b, 28) >> 7;
        long c0 = 0x1FFFFF & Load3(c, 0);
        long c1 = 0x1FFFFF & (Load4(c, 2) >> 5);
        long c2 = 0x1FFFFF & (Load3(c, 5) >> 2);
        long c3 = 0x1FFFFF & (Load4(c, 7) >> 7);
        long c4 = 0x1FFFFF & (Load4(c, 10) >> 4);
        long c5 = 0x1FFFFF & (Load3(c, 13) >> 1);
        long c6 = 0x1FFFFF & (Load4(c, 15) >> 6);
        long c7 = 0x1FFFFF & (Load3(c, 18) >> 3);
        long c8 = 0x1FFFFF & Load3(c, 21);
        long c9 = 0x1FFFFF & (Load4(c, 23) >> 5);
        long c10 = 0x1FFFFF & (Load3(c, 26) >> 2);
        long c11 = Load4(c, 28) >> 7;
        long carry;

        long s0 = c0 + a0 * b0;
        long s1 = c1 + a0 * b1 + a1 * b0;
        long s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
        long s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
        long s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        long s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
        long s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
        long s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
        long s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
        long s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
        long s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
        long s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
        long s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
        long s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
        long s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
        long s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
        long s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
        long s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
        long s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
        long s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
        long s20 = a9 * b11 + a10 * b10 + a11 * b9;
        long s21 = a10 * b11 + a11 * b10;
        long s22 = a11 * b11;
        long s23 = 0;

        carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
        carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
        carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
        carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
        carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
        carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
        carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;
        carry = (s18 + (1 << 20)) >> 21; s19 += carry; s18 -= carry << 21;
        carry = (s20 + (1 << 20)) >> 21; s21 += carry; s20 -= carry << 21;
        carry = (s22 + (1 << 20)) >> 21; s23 += carry; s22 -= carry << 21;
        carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
        carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
        carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
        carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
        carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;
        carry = (s17 + (1 << 20)) >> 21; s18 += carry; s17 -= carry << 21;
        carry = (s19 + (1 << 20)) >> 21; s20 += carry; s19 -= carry << 21;
        carry = (s21 + (1 << 20)) >> 21; s22 += carry; s21 -= carry << 21;

        s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183; s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
        s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183; s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
        s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183; s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
        s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183; s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
        s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183; s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
        s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183; s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;

        carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
        carry = (s12 + (1 << 20)) >> 21; s13 += carry; s12 -= carry << 21;
        carry = (s14 + (1 << 20)) >> 21; s15 += carry; s14 -= carry << 21;
        carry = (s16 + (1 << 20)) >> 21; s17 += carry; s16 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;
        carry = (s13 + (1 << 20)) >> 21; s14 += carry; s13 -= carry << 21;
        carry = (s15 + (1 << 20)) >> 21; s16 += carry; s15 -= carry << 21;

        s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183; s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
        s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183; s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
        s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183; s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
        s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183; s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
        s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183; s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
        s12 = 0;

        carry = (s0 + (1 << 20)) >> 21; s1 += carry; s0 -= carry << 21;
        carry = (s2 + (1 << 20)) >> 21; s3 += carry; s2 -= carry << 21;
        carry = (s4 + (1 << 20)) >> 21; s5 += carry; s4 -= carry << 21;
        carry = (s6 + (1 << 20)) >> 21; s7 += carry; s6 -= carry << 21;
        carry = (s8 + (1 << 20)) >> 21; s9 += carry; s8 -= carry << 21;
        carry = (s10 + (1 << 20)) >> 21; s11 += carry; s10 -= carry << 21;
        carry = (s1 + (1 << 20)) >> 21; s2 += carry; s1 -= carry << 21;
        carry = (s3 + (1 << 20)) >> 21; s4 += carry; s3 -= carry << 21;
        carry = (s5 + (1 << 20)) >> 21; s6 += carry; s5 -= carry << 21;
        carry = (s7 + (1 << 20)) >> 21; s8 += carry; s7 -= carry << 21;
        carry = (s9 + (1 << 20)) >> 21; s10 += carry; s9 -= carry << 21;
        carry = (s11 + (1 << 20)) >> 21; s12 += carry; s11 -= carry << 21;

        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
        s12 = 0;

        carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
        carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
        carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
        carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
        carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
        carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
        carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
        carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
        carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
        carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
        carry = s10 >> 21; s11 += carry; s10 -= carry << 21;
        carry = s11 >> 21; s12 += carry; s11 -= carry << 21;

        s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183; s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;

        carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
        carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
        carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
        carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
        carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
        carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
        carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
        carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
        carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
        carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
        carry = s10 >> 21; s11 += carry; s10 -= carry << 21;

        return Pack(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11);
    }

    private static byte[] Pack(long s0, long s1, long s2, long s3, long s4, long s5,
        long s6, long s7, long s8, long s9, long s10, long s11)
    {
        var r = new byte[32];
        r[0] = (byte)s0; r[1] = (byte)(s0 >> 8); r[2] = (byte)((s0 >> 16) | (s1 << 5));
        r[3] = (byte)(s1 >> 3); r[4] = (byte)(s1 >> 11); r[5] = (byte)((s1 >> 19) | (s2 << 2));
        r[6] = (byte)(s2 >> 6); r[7] = (byte)((s2 >> 14) | (s3 << 7)); r[8] = (byte)(s3 >> 1);
        r[9] = (byte)(s3 >> 9); r[10] = (byte)((s3 >> 17) | (s4 << 4)); r[11] = (byte)(s4 >> 4);
        r[12] = (byte)(s4 >> 12); r[13] = (byte)((s4 >> 20) | (s5 << 1)); r[14] = (byte)(s5 >> 7);
        r[15] = (byte)((s5 >> 15) | (s6 << 6)); r[16] = (byte)(s6 >> 2); r[17] = (byte)(s6 >> 10);
        r[18] = (byte)((s6 >> 18) | (s7 << 3)); r[19] = (byte)(s7 >> 5); r[20] = (byte)(s7 >> 13);
        r[21] = (byte)s8; r[22] = (byte)(s8 >> 8); r[23] = (byte)((s8 >> 16) | (s9 << 5));
        r[24] = (byte)(s9 >> 3); r[25] = (byte)(s9 >> 11); r[26] = (byte)((s9 >> 19) | (s10 << 2));
        r[27] = (byte)(s10 >> 6); r[28] = (byte)((s10 >> 14) | (s11 << 7)); r[29] = (byte)(s11 >> 1);
        r[30] = (byte)(s11 >> 9); r[31] = (byte)(s11 >> 17);
        return r;
    }

}
