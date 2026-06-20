using System.Security.Cryptography;
using System.Text;
using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

/// <summary>
/// Validates the pure-C# round-3 Kyber-1024 against the pq-crystals reference. Reproduces the exact
/// stdout stream of <c>ref/test_vectors.c</c> (NTESTS iterations driven by DJB's deterministic "surf"
/// PRNG) and checks its SHA-256 against the value published in the reference's SHA256SUMS (tvecs1024).
/// A match proves byte-for-byte interoperability with libsignal's Kyber-1024.
/// </summary>
public class KyberKatTests
{
    private const int NTests = 10000;
    private const string ExpectedTvecs1024Sha256 =
        "ff1a854b9b6761a70c65ccae85246fe0596a949e72eae0866a8a2a2d4ea54b10";

    /// <summary>DJB's "surf" deterministic randombytes from SUPERCOP, as used by the reference test.</summary>
    private sealed class Surf
    {
        private static readonly uint[] Seed =
        {
            3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3,
            2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2, 7, 9, 5,
        };

        private readonly uint[] _in = new uint[12];
        private readonly uint[] _out = new uint[8];
        private int _outleft;

        private static uint Rotate(uint x, int b) => (x << b) | (x >> (32 - b));

        private void DoSurf()
        {
            unchecked
            {
                var t = new uint[12];
                uint sum = 0;
                for (int i = 0; i < 12; i++) t[i] = _in[i] ^ Seed[12 + i];
                for (int i = 0; i < 8; i++) _out[i] = Seed[24 + i];
                uint x = t[11];
                for (int loop = 0; loop < 2; loop++)
                {
                    for (int r = 0; r < 16; r++)
                    {
                        sum += 0x9e3779b9;
                        Mush(t, ref x, sum, 0, 5); Mush(t, ref x, sum, 1, 7);
                        Mush(t, ref x, sum, 2, 9); Mush(t, ref x, sum, 3, 13);
                        Mush(t, ref x, sum, 4, 5); Mush(t, ref x, sum, 5, 7);
                        Mush(t, ref x, sum, 6, 9); Mush(t, ref x, sum, 7, 13);
                        Mush(t, ref x, sum, 8, 5); Mush(t, ref x, sum, 9, 7);
                        Mush(t, ref x, sum, 10, 9); Mush(t, ref x, sum, 11, 13);
                    }
                    for (int i = 0; i < 8; i++) _out[i] ^= t[i + 4];
                }
            }
        }

        private static void Mush(uint[] t, ref uint x, uint sum, int i, int b)
        {
            unchecked
            {
                t[i] += ((x ^ Seed[i]) + sum) ^ Rotate(x, b);
                x = t[i];
            }
        }

        public byte[] NextBytes(int n)
        {
            var result = new byte[n];
            for (int k = 0; k < n; k++)
            {
                if (_outleft == 0)
                {
                    unchecked
                    {
                        if (++_in[0] == 0) if (++_in[1] == 0) if (++_in[2] == 0) ++_in[3];
                    }
                    DoSurf();
                    _outleft = 8;
                }
                result[k] = (byte)_out[--_outleft];
            }
            return result;
        }
    }

    [Trait("Category", "Kat")]
    [Fact]
    public void Kyber1024_ReproducesReferenceTestVectorStream()
    {
        var surf = new Surf();
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        void Emit(string s) => sha.AppendData(Encoding.ASCII.GetBytes(s));
        void EmitHexLine(byte[] b) => Emit(Hex(b) + "\n");

        for (int i = 0; i < NTests; i++)
        {
            byte[] d = surf.NextBytes(32); EmitHexLine(d);   // indcpa_keypair coin
            byte[] z = surf.NextBytes(32); EmitHexLine(z);   // implicit-rejection value
            Kyber1024.KeyPair(d, z, out byte[] pk, out byte[] sk);
            Emit("Public Key: " + Hex(pk) + "\n");
            Emit("Secret Key: " + Hex(sk) + "\n");

            byte[] m = surf.NextBytes(32); EmitHexLine(m);   // encaps coin
            Kyber1024.Encapsulate(pk, m, out byte[] ct, out byte[] keyB);
            Emit("Ciphertext: " + Hex(ct) + "\n");
            Emit("Shared Secret B: " + Hex(keyB) + "\n");

            byte[] keyA = Kyber1024.Decapsulate(ct, sk);
            Emit("Shared Secret A: " + Hex(keyA) + "\n");

            Assert.Equal(keyB, keyA);
        }

        string digest = Hex(sha.GetHashAndReset());
        Assert.Equal(ExpectedTvecs1024Sha256, digest);
    }

    private static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
