using Org.BouncyCastle.Crypto.Digests;

namespace Wingnal.Protocol.Spqr;

/// <summary>
/// Pure-C# FIPS-203 ML-KEM-768 with the "incremental" ek/ciphertext split used by Signal's Sparse
/// Post-Quantum Ratchet (libcrux <c>mlkem768::incremental</c>). The ring arithmetic (q=3329, NTT,
/// zetas, Montgomery/Barrett, basemul, CBD-eta2, matrix gen) is identical to round-3 Kyber-1024
/// (<see cref="Curve.Kyber1024"/>); the differences are k=3, d_u=10 / d_v=4 compression, the FIPS-203
/// hashing (keygen G(d‖k), encaps (K,r)=G(m‖H(ek)), implicit reject J(z‖c)), and NO final KDF.
///
/// Incremental layout (byte-exact with libcrux, confirmed against cryspen/libcrux):
///   keygen  → hdr(64) = rho(32)‖H(ek)(32);  ek/pk2(1152) = ByteEncode12(t̂);  dk(2400) =
///             dkPke(1152)‖ek(1184)‖H(ek)(32)‖z(32), where ek(1184) = ByteEncode12(t̂)‖rho.
///   encaps1(hdr,m) → ct1(960) = Compress_{10}(u);  es (local);  ss(32) = K.
///   encaps2(ek,es) → ct2(128) = Compress_{4}(v).
///   decaps(dk,ct1,ct2) → ss(32): standard FIPS-203 decaps on ct = ct1‖ct2 (1088).
/// The encapsulation state <c>es</c> is never transmitted, so its format is our own.
/// </summary>
internal static class MlKem768
{
    public const int N = 256;
    public const int Q = 3329;
    public const int K = 3;
    public const int Eta = 2;                 // eta1 == eta2 == 2
    public const int SymBytes = 32;
    public const byte RankByte = 3;           // FIPS-203 domain-separation byte k for ML-KEM-768

    public const int PolyBytes = 384;
    public const int PolyVecBytes = K * PolyBytes;        // 1152 = ByteEncode12(vec)
    private const int Du = 10;
    private const int Dv = 4;
    public const int PolyVecCompressedBytes = K * (N * Du / 8);  // 960
    public const int PolyCompressedBytes = N * Dv / 8;          // 128

    public const int EkBytes = PolyVecBytes + SymBytes;   // 1184 (full FIPS-203 encapsulation key)
    public const int Pk2Bytes = PolyVecBytes;             // 1152 (incremental "encapsulation key")
    public const int HeaderBytes = 2 * SymBytes;          // 64
    public const int CiphertextBytes = PolyVecCompressedBytes + PolyCompressedBytes; // 1088
    public const int Ct1Bytes = PolyVecCompressedBytes;   // 960
    public const int Ct2Bytes = PolyCompressedBytes;      // 128
    public const int DkBytes = PolyVecBytes + EkBytes + SymBytes + SymBytes; // 2400
    public const int SsBytes = 32;

    private const short QINV = -3327; // q^-1 mod 2^16

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

    private static void InvNtt(short[] r)
    {
        unchecked
        {
            const short f = 1441; // mont^2/128
            int k = 127;
            for (int len = 2; len <= 128; len <<= 1)
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
            for (int j = 0; j < 256; j++) r[j] = FqMul(r[j], f);
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

    // ---- hashing ----

    private static byte[] Sha3_256(byte[] data, int off, int len)
    {
        var d = new Sha3Digest(256);
        d.BlockUpdate(data, off, len);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    private static byte[] Sha3_512(byte[] data)
    {
        var d = new Sha3Digest(512);
        d.BlockUpdate(data, 0, data.Length);
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

    // ---- CBD (eta = 2) ----

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

    private static short[] GetNoise(byte[] seed, byte nonce)
    {
        var extkey = new byte[SymBytes + 1];
        Array.Copy(seed, extkey, SymBytes);
        extkey[SymBytes] = nonce;
        byte[] buf = Shake256(extkey, Eta * N / 4);
        var r = new short[N];
        Cbd2(r, buf);
        return r;
    }

    // ---- poly (de)serialization: ByteEncode12 / ByteDecode12 ----

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

    // ---- generic d-bit compression (LSB-first bit packing, FIPS-203 ByteEncode/Compress) ----

    private static void CompressPoly(byte[] outBuf, int outOff, short[] a, int d)
    {
        unchecked
        {
            uint mask = (1u << d) - 1;
            ulong acc = 0;
            int bits = 0, pos = outOff;
            for (int i = 0; i < N; i++)
            {
                int u = a[i];
                u += (u >> 15) & Q;
                uint t = (uint)(((((ulong)u << d) + Q / 2) / Q) & mask);
                acc |= (ulong)t << bits;
                bits += d;
                while (bits >= 8) { outBuf[pos++] = (byte)acc; acc >>= 8; bits -= 8; }
            }
        }
    }

    private static short[] DecompressPoly(byte[] a, int aOff, int d)
    {
        unchecked
        {
            var r = new short[N];
            uint mask = (1u << d) - 1;
            ulong acc = 0;
            int bits = 0, pos = aOff;
            for (int i = 0; i < N; i++)
            {
                while (bits < d) { acc |= (ulong)a[pos++] << bits; bits += 8; }
                uint t = (uint)(acc & mask);
                acc >>= d;
                bits -= d;
                r[i] = (short)(((uint)t * Q + (1u << (d - 1))) >> d);
            }
            return r;
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

    private static void PolyNtt(short[] r) { Ntt(r); PolyReduce(r); }

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
            const short f = (short)((1L << 32) % Q);
            for (int i = 0; i < N; i++) r[i] = MontgomeryReduce(r[i] * f);
        }
    }

    private static void PolyReduce(short[] r) { for (int i = 0; i < N; i++) r[i] = BarrettReduce(r[i]); }
    private static void PolyAdd(short[] r, short[] a, short[] b) { unchecked { for (int i = 0; i < N; i++) r[i] = (short)(a[i] + b[i]); } }
    private static void PolySub(short[] r, short[] a, short[] b) { unchecked { for (int i = 0; i < N; i++) r[i] = (short)(a[i] - b[i]); } }

    // ---- polyvec ----

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
        for (int i = 0; i < K; i++) CompressPoly(r, rOff + i * (N * Du / 8), a[i], Du);
    }

    private static short[][] PolyVecDecompress(byte[] a, int aOff)
    {
        var r = NewPolyVec();
        for (int i = 0; i < K; i++) r[i] = DecompressPoly(a, aOff + i * (N * Du / 8), Du);
        return r;
    }

    private static void PolyVecNtt(short[][] r) { for (int i = 0; i < K; i++) PolyNtt(r[i]); }

    private static void PolyVecBaseMulAccMont(short[] r, short[][] a, short[][] b)
    {
        var t = new short[N];
        PolyBaseMulMont(r, a[0], b[0]);
        for (int i = 1; i < K; i++) { PolyBaseMulMont(t, a[i], b[i]); PolyAdd(r, r, t); }
        PolyReduce(r);
    }

    private static void PolyVecReduce(short[][] r) { for (int i = 0; i < K; i++) PolyReduce(r[i]); }
    private static void PolyVecAdd(short[][] r, short[][] a, short[][] b) { for (int i = 0; i < K; i++) PolyAdd(r[i], a[i], b[i]); }

    // ---- matrix generation (identical to round-3 Kyber: SHAKE128 rejection sampling) ----

    private const int XofBlockBytes = 168;
    private const int GenMatrixNBlocks = (12 * N / 8 * (1 << 12) / Q + XofBlockBytes) / XofBlockBytes;

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

    // ---- K-PKE keygen (FIPS-203) ----

    private static void KPkeKeygen(byte[] d, out short[][] skpv, out short[][] pkpv, out byte[] rho)
    {
        var dk = new byte[SymBytes + 1];
        Array.Copy(d, dk, SymBytes);
        dk[SymBytes] = RankByte;                 // FIPS-203: (rho,sigma) = G(d || k)
        byte[] buf = Sha3_512(dk);
        rho = buf[..SymBytes];
        var sigma = buf[SymBytes..];

        // Keygen samples A[i][j] from XOF(rho, j, i) (pq-crystals gen_a, transposed:false); encrypt
        // uses the transpose Aᵀ (transposed:true). Identical convention to round-3 Kyber.
        short[][][] a = GenMatrix(rho, transposed: false);

        skpv = NewPolyVec();
        var e = NewPolyVec();
        byte nonce = 0;
        for (int i = 0; i < K; i++) skpv[i] = GetNoise(sigma, nonce++);
        for (int i = 0; i < K; i++) e[i] = GetNoise(sigma, nonce++);

        PolyVecNtt(skpv);
        PolyVecNtt(e);

        pkpv = NewPolyVec();
        for (int i = 0; i < K; i++)
        {
            PolyVecBaseMulAccMont(pkpv[i], a[i], skpv);
            PolyToMont(pkpv[i]);
        }
        PolyVecAdd(pkpv, pkpv, e);
        PolyVecReduce(pkpv);
    }

    // ---- standard FIPS-203 API (for KAT) ----

    /// <summary>FIPS-203 ML-KEM.KeyGen_internal(d, z) → (ek 1184, dk 2400).</summary>
    public static void KeyGen(byte[] d, byte[] z, out byte[] ek, out byte[] dk)
    {
        KPkeKeygen(d, out short[][] skpv, out short[][] pkpv, out byte[] rho);

        ek = new byte[EkBytes];
        PolyVecToBytes(ek, 0, pkpv);
        Array.Copy(rho, 0, ek, PolyVecBytes, SymBytes);

        dk = new byte[DkBytes];
        PolyVecToBytes(dk, 0, skpv);                                  // dkPke = ByteEncode12(s)
        Array.Copy(ek, 0, dk, PolyVecBytes, EkBytes);                 // ek
        byte[] hek = Sha3_256(ek, 0, EkBytes);
        Array.Copy(hek, 0, dk, PolyVecBytes + EkBytes, SymBytes);     // H(ek)
        Array.Copy(z, 0, dk, PolyVecBytes + EkBytes + SymBytes, SymBytes); // z
    }

    /// <summary>K-PKE encryption split into the c1 (u, compressed du) and c2 (v, compressed dv) halves.
    /// Pass <paramref name="tHat"/> = null to skip c2 (incremental encaps1).</summary>
    private static void KPkeEncrypt(byte[] rho, short[][]? tHat, byte[] msg, byte[] coins,
        short[][] rOut, out short[] e2Out, byte[]? ct1, byte[]? ct2)
    {
        short[][][] at = GenMatrix(rho, transposed: true);  // Aᵀ for encrypt (see KPkeKeygen note)

        var sp = NewPolyVec();
        var ep = NewPolyVec();
        byte nonce = 0;
        for (int i = 0; i < K; i++) sp[i] = GetNoise(coins, nonce++);
        for (int i = 0; i < K; i++) ep[i] = GetNoise(coins, nonce++);
        short[] epp = GetNoise(coins, nonce);

        PolyVecNtt(sp);
        for (int i = 0; i < K; i++) rOut[i] = (short[])sp[i].Clone();  // r̂ saved for encaps2
        e2Out = epp;

        if (ct1 is not null)
        {
            var b = NewPolyVec();
            for (int i = 0; i < K; i++) PolyVecBaseMulAccMont(b[i], at[i], sp);
            for (int i = 0; i < K; i++) InvNtt(b[i]);
            PolyVecAdd(b, b, ep);
            PolyVecReduce(b);
            PolyVecCompress(ct1, 0, b);
        }

        if (ct2 is not null && tHat is not null)
        {
            var v = new short[N];
            PolyVecBaseMulAccMont(v, tHat, sp);
            InvNtt(v);
            var k = new short[N];
            PolyFromMsg(k, msg);
            PolyAdd(v, v, epp);
            PolyAdd(v, v, k);
            PolyReduce(v);
            CompressPoly(ct2, 0, v, Dv);
        }
    }

    /// <summary>FIPS-203 ML-KEM.Encaps_internal(ek, m) → (c 1088, ss 32). For KAT / standard use.</summary>
    public static void Encaps(byte[] ek, byte[] m, out byte[] ct, out byte[] ss)
    {
        byte[] hek = Sha3_256(ek, 0, EkBytes);
        byte[] g = Sha3_512(Concat(m, hek));
        ss = g[..SymBytes];
        byte[] coins = g[SymBytes..];

        byte[] rho = ek[PolyVecBytes..EkBytes];
        short[][] tHat = PolyVecFromBytes(ek, 0);

        var rHat = new short[K][];
        ct = new byte[CiphertextBytes];
        var ct1 = new byte[Ct1Bytes];
        var ct2 = new byte[Ct2Bytes];
        KPkeEncrypt(rho, tHat, m, coins, rHat, out _, ct1, ct2);
        Array.Copy(ct1, 0, ct, 0, Ct1Bytes);
        Array.Copy(ct2, 0, ct, Ct1Bytes, Ct2Bytes);
    }

    /// <summary>FIPS-203 ML-KEM.Decaps(dk, c) → ss 32 (c = ct1‖ct2).</summary>
    public static byte[] Decaps(byte[] dk, byte[] ct1, byte[] ct2)
    {
        var dkPke = dk[..PolyVecBytes];
        var ek = new byte[EkBytes];
        Array.Copy(dk, PolyVecBytes, ek, 0, EkBytes);
        var hek = new byte[SymBytes];
        Array.Copy(dk, PolyVecBytes + EkBytes, hek, 0, SymBytes);
        var z = new byte[SymBytes];
        Array.Copy(dk, PolyVecBytes + EkBytes + SymBytes, z, 0, SymBytes);

        // K-PKE.Decrypt
        short[][] u = PolyVecDecompress(ct1, 0);
        short[] v = DecompressPoly(ct2, 0, Dv);
        short[][] skpv = PolyVecFromBytes(dkPke, 0);
        PolyVecNtt(u);
        var mp = new short[N];
        PolyVecBaseMulAccMont(mp, skpv, u);
        InvNtt(mp);
        PolySub(mp, v, mp);
        PolyReduce(mp);
        byte[] mPrime = PolyToMsg(mp);

        // (K', r') = G(m' || H(ek))
        byte[] g = Sha3_512(Concat(mPrime, hek));
        byte[] kPrime = g[..SymBytes];
        byte[] coins = g[SymBytes..];

        // re-encrypt and compare
        byte[] rho = ek[PolyVecBytes..EkBytes];
        short[][] tHat = PolyVecFromBytes(ek, 0);
        var rHat = new short[K][];
        var ct1Cmp = new byte[Ct1Bytes];
        var ct2Cmp = new byte[Ct2Bytes];
        KPkeEncrypt(rho, tHat, mPrime, coins, rHat, out _, ct1Cmp, ct2Cmp);

        int fail = Verify(ct1, ct1Cmp) | Verify(ct2, ct2Cmp);

        // implicit reject: K_bar = J(z || c)
        byte[] kBar = Shake256(Concat(z, Concat(ct1, ct2)), SsBytes);

        var outSs = new byte[SsBytes];
        CMov(outSs, kPrime, kBar, (byte)fail);
        return outSs;
    }

    // ---- incremental API ----

    public sealed class Keys
    {
        public required byte[] Header { get; init; }  // 64
        public required byte[] Ek { get; init; }       // 1152 (pk2)
        public required byte[] Dk { get; init; }       // 2400
    }

    /// <summary>Incremental keygen → header (rho‖H(ek)), ek/pk2 (ByteEncode12(t̂)), dk.</summary>
    public static Keys Generate(byte[] d, byte[] z)
    {
        KeyGen(d, z, out byte[] ekFull, out byte[] dk);
        var header = new byte[HeaderBytes];
        Array.Copy(ekFull, PolyVecBytes, header, 0, SymBytes);             // rho
        byte[] hek = Sha3_256(ekFull, 0, EkBytes);
        Array.Copy(hek, 0, header, SymBytes, SymBytes);                    // H(ek)
        var pk2 = new byte[Pk2Bytes];
        Array.Copy(ekFull, 0, pk2, 0, Pk2Bytes);                           // ByteEncode12(t̂)
        return new Keys { Header = header, Ek = pk2, Dk = dk };
    }

    /// <summary>Validates that an encapsulation key (pk2) matches a header: H(pk2‖rho) == hdr hash.</summary>
    public static bool EkMatchesHeader(byte[] pk2, byte[] header)
    {
        if (pk2.Length != Pk2Bytes || header.Length != HeaderBytes) return false;
        var ekFull = new byte[EkBytes];
        Array.Copy(pk2, 0, ekFull, 0, Pk2Bytes);
        Array.Copy(header, 0, ekFull, PolyVecBytes, SymBytes);            // rho from header
        byte[] hek = Sha3_256(ekFull, 0, EkBytes);
        return CryptographicEquals(hek, header.AsSpan(SymBytes, SymBytes));
    }

    /// <summary>encaps1(hdr, m) → (ct1 960, es, ss 32). The shared secret is available immediately.</summary>
    public static void Encaps1(byte[] header, byte[] m, out byte[] ct1, out byte[] es, out byte[] ss)
    {
        byte[] rho = header[..SymBytes];
        byte[] hek = header[SymBytes..HeaderBytes];
        byte[] g = Sha3_512(Concat(m, hek));
        ss = g[..SymBytes];
        byte[] coins = g[SymBytes..];

        var rHat = new short[K][];
        ct1 = new byte[Ct1Bytes];
        KPkeEncrypt(rho, tHat: null, m, coins, rHat, out short[] e2, ct1, ct2: null);
        es = SerializeState(rHat, e2, m);
    }

    /// <summary>encaps2(ek/pk2, es) → ct2 128.</summary>
    public static byte[] Encaps2(byte[] pk2, byte[] es)
    {
        DeserializeState(es, out short[][] rHat, out short[] e2, out byte[] m);
        short[][] tHat = PolyVecFromBytes(pk2, 0);

        var v = new short[N];
        PolyVecBaseMulAccMont(v, tHat, rHat);
        InvNtt(v);
        var k = new short[N];
        PolyFromMsg(k, m);
        PolyAdd(v, v, e2);
        PolyAdd(v, v, k);
        PolyReduce(v);
        var ct2 = new byte[Ct2Bytes];
        CompressPoly(ct2, 0, v, Dv);
        return ct2;
    }

    /// <summary>decaps(dk, ct1, ct2) → ss 32.</summary>
    public static byte[] DecapsIncremental(byte[] dk, byte[] ct1, byte[] ct2) => Decaps(dk, ct1, ct2);

    // ---- local encapsulation-state serialization (never transmitted; our own format) ----
    // es = r̂ (K*N int16 LE) || e2 (N int16 LE) || m (32)

    private static byte[] SerializeState(short[][] rHat, short[] e2, byte[] m)
    {
        var es = new byte[(K * N + N) * 2 + SymBytes];
        int p = 0;
        for (int i = 0; i < K; i++)
            for (int j = 0; j < N; j++) { es[p++] = (byte)rHat[i][j]; es[p++] = (byte)(rHat[i][j] >> 8); }
        for (int j = 0; j < N; j++) { es[p++] = (byte)e2[j]; es[p++] = (byte)(e2[j] >> 8); }
        Array.Copy(m, 0, es, p, SymBytes);
        return es;
    }

    private static void DeserializeState(byte[] es, out short[][] rHat, out short[] e2, out byte[] m)
    {
        rHat = NewPolyVec();
        e2 = new short[N];
        int p = 0;
        for (int i = 0; i < K; i++)
            for (int j = 0; j < N; j++) { rHat[i][j] = (short)(es[p] | (es[p + 1] << 8)); p += 2; }
        for (int j = 0; j < N; j++) { e2[j] = (short)(es[p] | (es[p + 1] << 8)); p += 2; }
        m = new byte[SymBytes];
        Array.Copy(es, p, m, 0, SymBytes);
    }

    // ---- helpers ----

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    private static int Verify(byte[] a, byte[] b)
    {
        unchecked
        {
            byte r = 0;
            for (int i = 0; i < a.Length; i++) r |= (byte)(a[i] ^ b[i]);
            return (int)((ulong)(0 - (ulong)r) >> 63);
        }
    }

    private static void CMov(byte[] dst, byte[] good, byte[] bad, byte fail)
    {
        unchecked
        {
            byte mask = (byte)(-(sbyte)fail); // fail==1 -> 0xFF (use bad), fail==0 -> 0x00 (use good)
            for (int i = 0; i < dst.Length; i++)
                dst[i] = (byte)(good[i] ^ (mask & (good[i] ^ bad[i])));
        }
    }

    private static bool CryptographicEquals(byte[] a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) return false;
        int r = 0;
        for (int i = 0; i < a.Length; i++) r |= a[i] ^ b[i];
        return r == 0;
    }
}
