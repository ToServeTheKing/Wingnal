using Org.BouncyCastle.Crypto.Digests;

namespace Wingnal.Protocol.Curve;

/// <summary>
/// Pure-C# implementation of round-3 Kyber-1024 (the CRYSTALS-Kyber NIST round-3 submission, as used
/// by libsignal's <c>KYBER_1024</c> KEM for PQXDH). Faithfully ported from the pq-crystals reference
/// (tag v3.0, ref/), using BouncyCastle only for SHA3/SHAKE. Validated against the reference's
/// published test-vector SHA-256 (see KyberKatTests).
///
/// All polynomial coefficients are 16-bit; arithmetic is unchecked to mirror C int16_t wraparound.
/// </summary>
internal static class Kyber1024
{
    public const int N = 256;
    public const int Q = 3329;
    public const int K = 4;
    public const int Eta1 = 2;
    public const int Eta2 = 2;
    public const int SymBytes = 32;

    public const int PolyBytes = 384;
    public const int PolyVecBytes = K * PolyBytes;                 // 1536
    public const int PolyCompressedBytes = 160;                    // dv = 5
    public const int PolyVecCompressedBytes = K * 352;             // 1408, du = 11
    public const int IndcpaPublicKeyBytes = PolyVecBytes + SymBytes;   // 1568
    public const int IndcpaSecretKeyBytes = PolyVecBytes;             // 1536
    public const int IndcpaBytes = PolyVecCompressedBytes + PolyCompressedBytes; // 1568

    public const int PublicKeyBytes = IndcpaPublicKeyBytes;        // 1568
    public const int SecretKeyBytes = IndcpaSecretKeyBytes + IndcpaPublicKeyBytes + 2 * SymBytes; // 3168
    public const int CiphertextBytes = IndcpaBytes;                // 1568
    public const int SsBytes = 32;

    private const short MONT = -1044;   // 2^16 mod q
    private const short QINV = -3327;   // q^-1 mod 2^16

    private static readonly short[] Zetas =
    {
        -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
         -171,   622,  1577,   182,   962, -1202, -1474,  1468,
          573, -1325,   264,   383,  -829,  1458, -1602,  -130,
         -681,  1017,   732,   608, -1542,   411,  -205, -1571,
         1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
          516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
         -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
         -398,   961, -1508,  -725,   448, -1065,   677, -1275,
        -1103,   430,   555,   843, -1251,   871,  1550,   105,
          422,   587,   177,  -235,  -291,  -460,  1574,  1653,
         -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
        -1590,   644,  -872,   349,   418,   329,  -156,   -75,
          817,  1097,   603,   610,  1322, -1285, -1465,   384,
        -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
        -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
         -108,  -308,   996,   991,   958, -1460,  1522,  1628,
    };

    // ---- reductions ----

    private static short MontgomeryReduce(int a)
    {
        unchecked
        {
            short t = (short)((short)a * QINV);
            return (short)((a - (int)t * Q) >> 16);
        }
    }

    private static short BarrettReduce(short a)
    {
        unchecked
        {
            const int v = ((1 << 26) + Q / 2) / Q;
            short t = (short)((v * a + (1 << 25)) >> 26);
            return (short)(a - (short)(t * Q));
        }
    }

    private static short FqMul(short a, short b) => MontgomeryReduce(a * b);

    // ---- NTT ----

    private static void Ntt(short[] r)
    {
        unchecked
        {
            int k = 1;
            for (int len = 128; len >= 2; len >>= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    short zeta = Zetas[k++];
                    for (int j = start; j < start + len; j++)
                    {
                        short t = FqMul(zeta, r[j + len]);
                        r[j + len] = (short)(r[j] - t);
                        r[j] = (short)(r[j] + t);
                    }
                }
            }
        }
    }

    private static void InvNtt(short[] r)
    {
        unchecked
        {
            const short f = 1441; // mont^2/128
            int k = 127;
            for (int len = 2; len <= 128; len <<= 1)
            {
                for (int start = 0; start < 256; start += 2 * len)
                {
                    short zeta = Zetas[k--];
                    for (int j = start; j < start + len; j++)
                    {
                        short t = r[j];
                        r[j] = BarrettReduce((short)(t + r[j + len]));
                        r[j + len] = (short)(r[j + len] - t);
                        r[j + len] = FqMul(zeta, r[j + len]);
                    }
                }
            }
            for (int j = 0; j < 256; j++)
                r[j] = FqMul(r[j], f);
        }
    }

    private static void BaseMul(short[] r, int rOff, short[] a, int aOff, short[] b, int bOff, short zeta)
    {
        unchecked
        {
            r[rOff] = FqMul(a[aOff + 1], b[bOff + 1]);
            r[rOff] = FqMul(r[rOff], zeta);
            r[rOff] = (short)(r[rOff] + FqMul(a[aOff], b[bOff]));
            r[rOff + 1] = FqMul(a[aOff], b[bOff + 1]);
            r[rOff + 1] = (short)(r[rOff + 1] + FqMul(a[aOff + 1], b[bOff]));
        }
    }

    // ---- hashing (BouncyCastle SHA3/SHAKE) ----

    private static byte[] Sha3_256(byte[] data, int off, int len)
    {
        var d = new Sha3Digest(256);
        d.BlockUpdate(data, off, len);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    private static byte[] Sha3_512(byte[] data, int off, int len)
    {
        var d = new Sha3Digest(512);
        d.BlockUpdate(data, off, len);
        var o = new byte[64];
        d.DoFinal(o, 0);
        return o;
    }

    private static byte[] Shake256(byte[] data, int len)
    {
        var d = new ShakeDigest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[len];
        d.Output(o, 0, len);
        return o;
    }

    // ---- centered binomial distribution (eta = 2) ----

    private static uint Load32Le(byte[] x, int off) =>
        (uint)(x[off] | (x[off + 1] << 8) | (x[off + 2] << 16) | (x[off + 3] << 24));

    private static void Cbd2(short[] r, byte[] buf)
    {
        unchecked
        {
            for (int i = 0; i < N / 8; i++)
            {
                uint t = Load32Le(buf, 4 * i);
                uint d = t & 0x55555555u;
                d += (t >> 1) & 0x55555555u;
                for (int j = 0; j < 8; j++)
                {
                    short a = (short)((d >> (4 * j + 0)) & 0x3);
                    short b = (short)((d >> (4 * j + 2)) & 0x3);
                    r[8 * i + j] = (short)(a - b);
                }
            }
        }
    }

    // ---- poly serialization ----

    private static void PolyToBytes(byte[] r, int rOff, short[] a)
    {
        unchecked
        {
            for (int i = 0; i < N / 2; i++)
            {
                ushort t0 = (ushort)(a[2 * i] + ((a[2 * i] >> 15) & Q));
                ushort t1 = (ushort)(a[2 * i + 1] + ((a[2 * i + 1] >> 15) & Q));
                r[rOff + 3 * i + 0] = (byte)t0;
                r[rOff + 3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));
                r[rOff + 3 * i + 2] = (byte)(t1 >> 4);
            }
        }
    }

    private static void PolyFromBytes(short[] r, byte[] a, int aOff)
    {
        unchecked
        {
            for (int i = 0; i < N / 2; i++)
            {
                r[2 * i] = (short)(((a[aOff + 3 * i + 0] >> 0) | (a[aOff + 3 * i + 1] << 8)) & 0xFFF);
                r[2 * i + 1] = (short)(((a[aOff + 3 * i + 1] >> 4) | (a[aOff + 3 * i + 2] << 4)) & 0xFFF);
            }
        }
    }

    private static void PolyCompress(byte[] r, int rOff, short[] a)
    {
        unchecked
        {
            var t = new byte[8];
            for (int i = 0; i < N / 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    int u = a[8 * i + j];
                    u += (u >> 15) & Q;
                    t[j] = (byte)(((((uint)u << 5) + Q / 2) / Q) & 31);
                }
                r[rOff + 0] = (byte)((t[0] >> 0) | (t[1] << 5));
                r[rOff + 1] = (byte)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                r[rOff + 2] = (byte)((t[3] >> 1) | (t[4] << 4));
                r[rOff + 3] = (byte)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                r[rOff + 4] = (byte)((t[6] >> 2) | (t[7] << 3));
                rOff += 5;
            }
        }
    }

    private static void PolyDecompress(short[] r, byte[] a, int aOff)
    {
        unchecked
        {
            var t = new byte[8];
            for (int i = 0; i < N / 8; i++)
            {
                t[0] = (byte)(a[aOff + 0] >> 0);
                t[1] = (byte)((a[aOff + 0] >> 5) | (a[aOff + 1] << 3));
                t[2] = (byte)(a[aOff + 1] >> 2);
                t[3] = (byte)((a[aOff + 1] >> 7) | (a[aOff + 2] << 1));
                t[4] = (byte)((a[aOff + 2] >> 4) | (a[aOff + 3] << 4));
                t[5] = (byte)(a[aOff + 3] >> 1);
                t[6] = (byte)((a[aOff + 3] >> 6) | (a[aOff + 4] << 2));
                t[7] = (byte)(a[aOff + 4] >> 3);
                aOff += 5;
                for (int j = 0; j < 8; j++)
                    r[8 * i + j] = (short)(((uint)(t[j] & 31) * Q + 16) >> 5);
            }
        }
    }

    private static void PolyFromMsg(short[] r, byte[] msg)
    {
        unchecked
        {
            for (int i = 0; i < N / 8; i++)
                for (int j = 0; j < 8; j++)
                {
                    short mask = (short)(-(short)((msg[i] >> j) & 1));
                    r[8 * i + j] = (short)(mask & ((Q + 1) / 2));
                }
        }
    }

    private static byte[] PolyToMsg(short[] a)
    {
        unchecked
        {
            var msg = new byte[SymBytes];
            for (int i = 0; i < N / 8; i++)
            {
                msg[i] = 0;
                for (int j = 0; j < 8; j++)
                {
                    int t = a[8 * i + j];
                    t += (t >> 15) & Q;
                    t = (((t << 1) + Q / 2) / Q) & 1;
                    msg[i] |= (byte)(t << j);
                }
            }
            return msg;
        }
    }

    private static short[] PolyGetNoiseEta1(byte[] seed, byte nonce) => GetNoise(seed, nonce, Eta1);
    private static short[] PolyGetNoiseEta2(byte[] seed, byte nonce) => GetNoise(seed, nonce, Eta2);

    private static short[] GetNoise(byte[] seed, byte nonce, int eta)
    {
        var extkey = new byte[SymBytes + 1];
        Array.Copy(seed, extkey, SymBytes);
        extkey[SymBytes] = nonce;
        byte[] buf = Shake256(extkey, eta * N / 4);
        var r = new short[N];
        Cbd2(r, buf); // eta1 == eta2 == 2 for Kyber-1024
        return r;
    }

    private static void PolyNtt(short[] r) { Ntt(r); PolyReduce(r); }
    private static void PolyInvNttToMont(short[] r) => InvNtt(r);

    private static void PolyBaseMulMont(short[] r, short[] a, short[] b)
    {
        unchecked
        {
            for (int i = 0; i < N / 4; i++)
            {
                BaseMul(r, 4 * i, a, 4 * i, b, 4 * i, Zetas[64 + i]);
                BaseMul(r, 4 * i + 2, a, 4 * i + 2, b, 4 * i + 2, (short)(-Zetas[64 + i]));
            }
        }
    }

    private static void PolyToMont(short[] r)
    {
        unchecked
        {
            const short f = (short)(((1L << 32) % Q));
            for (int i = 0; i < N; i++)
                r[i] = MontgomeryReduce(r[i] * f);
        }
    }

    private static void PolyReduce(short[] r)
    {
        for (int i = 0; i < N; i++)
            r[i] = BarrettReduce(r[i]);
    }

    private static void PolyAdd(short[] r, short[] a, short[] b)
    {
        unchecked
        {
            for (int i = 0; i < N; i++) r[i] = (short)(a[i] + b[i]);
        }
    }

    private static void PolySub(short[] r, short[] a, short[] b)
    {
        unchecked
        {
            for (int i = 0; i < N; i++) r[i] = (short)(a[i] - b[i]);
        }
    }

    // ---- polyvec (short[K][N]) ----

    private static short[][] NewPolyVec()
    {
        var v = new short[K][];
        for (int i = 0; i < K; i++) v[i] = new short[N];
        return v;
    }

    private static void PolyVecToBytes(byte[] r, int rOff, short[][] a)
    {
        for (int i = 0; i < K; i++) PolyToBytes(r, rOff + i * PolyBytes, a[i]);
    }

    private static short[][] PolyVecFromBytes(byte[] a, int aOff)
    {
        var r = NewPolyVec();
        for (int i = 0; i < K; i++) PolyFromBytes(r[i], a, aOff + i * PolyBytes);
        return r;
    }

    private static void PolyVecCompress(byte[] r, int rOff, short[][] a)
    {
        unchecked
        {
            var t = new ushort[8];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < N / 8; j++)
                {
                    for (int k = 0; k < 8; k++)
                    {
                        int c = a[i][8 * j + k];
                        c += (c >> 15) & Q;
                        t[k] = (ushort)(((((uint)c << 11) + Q / 2) / Q) & 0x7ff);
                    }
                    r[rOff + 0] = (byte)(t[0] >> 0);
                    r[rOff + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                    r[rOff + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                    r[rOff + 3] = (byte)(t[2] >> 2);
                    r[rOff + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                    r[rOff + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                    r[rOff + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                    r[rOff + 7] = (byte)(t[5] >> 1);
                    r[rOff + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                    r[rOff + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                    r[rOff + 10] = (byte)(t[7] >> 3);
                    rOff += 11;
                }
            }
        }
    }

    private static short[][] PolyVecDecompress(byte[] a, int aOff)
    {
        unchecked
        {
            var r = NewPolyVec();
            var t = new ushort[8];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < N / 8; j++)
                {
                    t[0] = (ushort)((a[aOff + 0] >> 0) | (a[aOff + 1] << 8));
                    t[1] = (ushort)((a[aOff + 1] >> 3) | (a[aOff + 2] << 5));
                    t[2] = (ushort)((a[aOff + 2] >> 6) | (a[aOff + 3] << 2) | (a[aOff + 4] << 10));
                    t[3] = (ushort)((a[aOff + 4] >> 1) | (a[aOff + 5] << 7));
                    t[4] = (ushort)((a[aOff + 5] >> 4) | (a[aOff + 6] << 4));
                    t[5] = (ushort)((a[aOff + 6] >> 7) | (a[aOff + 7] << 1) | (a[aOff + 8] << 9));
                    t[6] = (ushort)((a[aOff + 8] >> 2) | (a[aOff + 9] << 6));
                    t[7] = (ushort)((a[aOff + 9] >> 5) | (a[aOff + 10] << 3));
                    aOff += 11;
                    for (int k = 0; k < 8; k++)
                        r[i][8 * j + k] = (short)(((uint)(t[k] & 0x7FF) * Q + 1024) >> 11);
                }
            }
            return r;
        }
    }

    private static void PolyVecNtt(short[][] r) { for (int i = 0; i < K; i++) PolyNtt(r[i]); }
    private static void PolyVecInvNttToMont(short[][] r) { for (int i = 0; i < K; i++) PolyInvNttToMont(r[i]); }

    private static void PolyVecBaseMulAccMont(short[] r, short[][] a, short[][] b)
    {
        var t = new short[N];
        PolyBaseMulMont(r, a[0], b[0]);
        for (int i = 1; i < K; i++)
        {
            PolyBaseMulMont(t, a[i], b[i]);
            PolyAdd(r, r, t);
        }
        PolyReduce(r);
    }

    private static void PolyVecReduce(short[][] r) { for (int i = 0; i < K; i++) PolyReduce(r[i]); }
    private static void PolyVecAdd(short[][] r, short[][] a, short[][] b) { for (int i = 0; i < K; i++) PolyAdd(r[i], a[i], b[i]); }

    // ---- matrix generation (rejection sampling on SHAKE128) ----

    private const int XofBlockBytes = 168; // SHAKE128 rate
    private const int GenMatrixNBlocks = (12 * N / 8 * (1 << 12) / Q + XofBlockBytes) / XofBlockBytes; // 3

    private static int RejUniform(short[] r, int rOff, int len, byte[] buf, int buflen)
    {
        unchecked
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                ushort val0 = (ushort)(((buf[pos + 0] >> 0) | (buf[pos + 1] << 8)) & 0xFFF);
                ushort val1 = (ushort)(((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF);
                pos += 3;
                if (val0 < Q) r[rOff + ctr++] = (short)val0;
                if (ctr < len && val1 < Q) r[rOff + ctr++] = (short)val1;
            }
            return ctr;
        }
    }

    private static short[][][] GenMatrix(byte[] seed, bool transposed)
    {
        var a = new short[K][][];
        for (int i = 0; i < K; i++)
        {
            a[i] = NewPolyVec();
            for (int j = 0; j < K; j++)
            {
                var extseed = new byte[SymBytes + 2];
                Array.Copy(seed, extseed, SymBytes);
                extseed[SymBytes] = (byte)(transposed ? i : j);
                extseed[SymBytes + 1] = (byte)(transposed ? j : i);

                var xof = new ShakeDigest(128);
                xof.BlockUpdate(extseed, 0, extseed.Length);

                var buf = new byte[GenMatrixNBlocks * XofBlockBytes + 2];
                xof.Output(buf, 0, GenMatrixNBlocks * XofBlockBytes);
                int buflen = GenMatrixNBlocks * XofBlockBytes;
                int ctr = RejUniform(a[i][j], 0, N, buf, buflen);

                while (ctr < N)
                {
                    int off = buflen % 3;
                    for (int k = 0; k < off; k++) buf[k] = buf[buflen - off + k];
                    xof.Output(buf, off, XofBlockBytes);
                    buflen = off + XofBlockBytes;
                    ctr += RejUniform(a[i][j], ctr, N - ctr, buf, buflen);
                }
            }
        }
        return a;
    }

    // ---- IND-CPA ----

    private static void IndcpaKeypair(byte[] d, out byte[] pk, out byte[] sk)
    {
        byte[] buf = Sha3_512(d, 0, SymBytes);     // publicseed || noiseseed
        var publicseed = new byte[SymBytes];
        var noiseseed = new byte[SymBytes];
        Array.Copy(buf, 0, publicseed, 0, SymBytes);
        Array.Copy(buf, SymBytes, noiseseed, 0, SymBytes);

        short[][][] a = GenMatrix(publicseed, transposed: false);

        var skpv = NewPolyVec();
        var e = NewPolyVec();
        byte nonce = 0;
        for (int i = 0; i < K; i++) skpv[i] = PolyGetNoiseEta1(noiseseed, nonce++);
        for (int i = 0; i < K; i++) e[i] = PolyGetNoiseEta1(noiseseed, nonce++);

        PolyVecNtt(skpv);
        PolyVecNtt(e);

        var pkpv = NewPolyVec();
        for (int i = 0; i < K; i++)
        {
            PolyVecBaseMulAccMont(pkpv[i], a[i], skpv);
            PolyToMont(pkpv[i]);
        }
        PolyVecAdd(pkpv, pkpv, e);
        PolyVecReduce(pkpv);

        sk = new byte[IndcpaSecretKeyBytes];
        PolyVecToBytes(sk, 0, skpv);

        pk = new byte[IndcpaPublicKeyBytes];
        PolyVecToBytes(pk, 0, pkpv);
        Array.Copy(publicseed, 0, pk, PolyVecBytes, SymBytes);
    }

    private static byte[] IndcpaEnc(byte[] m, byte[] pk, byte[] coins)
    {
        short[][] pkpv = PolyVecFromBytes(pk, 0);
        var seed = new byte[SymBytes];
        Array.Copy(pk, PolyVecBytes, seed, 0, SymBytes);

        short[] k = new short[N];
        PolyFromMsg(k, m);
        short[][][] at = GenMatrix(seed, transposed: true);

        var sp = NewPolyVec();
        var ep = NewPolyVec();
        byte nonce = 0;
        for (int i = 0; i < K; i++) sp[i] = PolyGetNoiseEta1(coins, nonce++);
        for (int i = 0; i < K; i++) ep[i] = PolyGetNoiseEta2(coins, nonce++);
        short[] epp = PolyGetNoiseEta2(coins, nonce);

        PolyVecNtt(sp);

        var b = NewPolyVec();
        for (int i = 0; i < K; i++) PolyVecBaseMulAccMont(b[i], at[i], sp);
        var v = new short[N];
        PolyVecBaseMulAccMont(v, pkpv, sp);

        PolyVecInvNttToMont(b);
        PolyInvNttToMont(v);

        PolyVecAdd(b, b, ep);
        PolyAdd(v, v, epp);
        PolyAdd(v, v, k);
        PolyVecReduce(b);
        PolyReduce(v);

        var c = new byte[IndcpaBytes];
        PolyVecCompress(c, 0, b);
        PolyCompress(c, PolyVecCompressedBytes, v);
        return c;
    }

    private static byte[] IndcpaDec(byte[] c, byte[] sk)
    {
        short[][] b = PolyVecDecompress(c, 0);
        short[] v = new short[N];
        PolyDecompress(v, c, PolyVecCompressedBytes);

        short[][] skpv = PolyVecFromBytes(sk, 0);

        PolyVecNtt(b);
        var mp = new short[N];
        PolyVecBaseMulAccMont(mp, skpv, b);
        PolyInvNttToMont(mp);

        PolySub(mp, v, mp);
        PolyReduce(mp);
        return PolyToMsg(mp);
    }

    // ---- CCA-KEM ----

    /// <summary>Generates a key pair from the two 32-byte coins consumed by the reference
    /// (<paramref name="d"/> drives IND-CPA keygen, <paramref name="z"/> is the implicit-rejection value).</summary>
    public static void KeyPair(byte[] d, byte[] z, out byte[] pk, out byte[] sk)
    {
        IndcpaKeypair(d, out pk, out byte[] indcpaSk);
        sk = new byte[SecretKeyBytes];
        Array.Copy(indcpaSk, 0, sk, 0, IndcpaSecretKeyBytes);
        Array.Copy(pk, 0, sk, IndcpaSecretKeyBytes, IndcpaPublicKeyBytes);
        byte[] hpk = Sha3_256(pk, 0, PublicKeyBytes);
        Array.Copy(hpk, 0, sk, SecretKeyBytes - 2 * SymBytes, SymBytes);
        Array.Copy(z, 0, sk, SecretKeyBytes - SymBytes, SymBytes);
    }

    /// <summary>Encapsulates to <paramref name="pk"/> using the 32-byte message coin <paramref name="m"/>.</summary>
    public static void Encapsulate(byte[] pk, byte[] m, out byte[] ct, out byte[] ss)
    {
        var buf = new byte[2 * SymBytes];
        byte[] mh = Sha3_256(m, 0, SymBytes);          // don't release system RNG output
        Array.Copy(mh, 0, buf, 0, SymBytes);
        byte[] hpk = Sha3_256(pk, 0, PublicKeyBytes);
        Array.Copy(hpk, 0, buf, SymBytes, SymBytes);

        byte[] kr = Sha3_512(buf, 0, 2 * SymBytes);
        var coins = new byte[SymBytes];
        Array.Copy(kr, SymBytes, coins, 0, SymBytes);

        var msg = new byte[SymBytes];
        Array.Copy(buf, 0, msg, 0, SymBytes);
        ct = IndcpaEnc(msg, pk, coins);

        byte[] hc = Sha3_256(ct, 0, CiphertextBytes);
        var krFinal = new byte[2 * SymBytes];
        Array.Copy(kr, 0, krFinal, 0, SymBytes);
        Array.Copy(hc, 0, krFinal, SymBytes, SymBytes);
        ss = Shake256(krFinal, SsBytes);
    }

    /// <summary>Decapsulates <paramref name="ct"/> with <paramref name="sk"/>, returning the 32-byte shared secret
    /// (a pseudo-random value on implicit-rejection failure).</summary>
    public static byte[] Decapsulate(byte[] ct, byte[] sk)
    {
        var skCpa = new byte[IndcpaSecretKeyBytes];
        Array.Copy(sk, 0, skCpa, 0, IndcpaSecretKeyBytes);
        var pk = new byte[IndcpaPublicKeyBytes];
        Array.Copy(sk, IndcpaSecretKeyBytes, pk, 0, IndcpaPublicKeyBytes);

        byte[] m = IndcpaDec(ct, skCpa);

        var buf = new byte[2 * SymBytes];
        Array.Copy(m, 0, buf, 0, SymBytes);
        Array.Copy(sk, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes); // stored H(pk)

        byte[] kr = Sha3_512(buf, 0, 2 * SymBytes);
        var coins = new byte[SymBytes];
        Array.Copy(kr, SymBytes, coins, 0, SymBytes);

        byte[] cmp = IndcpaEnc(buf[..SymBytes], pk, coins);
        int fail = Verify(ct, cmp, CiphertextBytes);

        byte[] hc = Sha3_256(ct, 0, CiphertextBytes);
        var krFinal = new byte[2 * SymBytes];
        Array.Copy(kr, 0, krFinal, 0, SymBytes);
        Array.Copy(hc, 0, krFinal, SymBytes, SymBytes);

        // cmov: replace pre-k with z on failure (constant time)
        CMov(krFinal, 0, sk, SecretKeyBytes - SymBytes, SymBytes, (byte)fail);
        return Shake256(krFinal, SsBytes);
    }

    private static int Verify(byte[] a, byte[] b, int len)
    {
        unchecked
        {
            byte r = 0;
            for (int i = 0; i < len; i++) r |= (byte)(a[i] ^ b[i]);
            return (int)((ulong)(0 - (ulong)r) >> 63);
        }
    }

    private static void CMov(byte[] r, int rOff, byte[] x, int xOff, int len, byte b)
    {
        unchecked
        {
            b = (byte)(-(sbyte)b);
            for (int i = 0; i < len; i++)
                r[rOff + i] ^= (byte)(b & (r[rOff + i] ^ x[xOff + i]));
        }
    }
}
