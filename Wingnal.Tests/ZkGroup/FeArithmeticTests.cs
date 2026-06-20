using System.Numerics;
using System.Security.Cryptography;
using Wingnal.Protocol.ZkGroup.Curve;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>Fuzz the <see cref="Fe"/> field wrapper against BigInteger mod p to localize any
/// carry/normalization bug independently of the Ristretto formulas.</summary>
public class FeArithmeticTests
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    private static BigInteger ToBig(Fe f) => new(f.Encode(), isUnsigned: true, isBigEndian: false);

    private static (Fe fe, BigInteger big) Rand()
    {
        byte[] b = RandomNumberGenerator.GetBytes(32);
        b[31] &= 0x7f;
        Fe fe = Fe.Decode(b);
        BigInteger big = new BigInteger(b, isUnsigned: true, isBigEndian: false) % P;
        return (fe, big);
    }

    [Fact]
    public void Mul_Add_Sub_Sqr_Inv_MatchBigInteger()
    {
        for (int i = 0; i < 2000; i++)
        {
            var (a, ab) = Rand();
            var (b, bb) = Rand();
            Assert.Equal((ab + bb) % P, ToBig(Fe.Add(a, b)));
            Assert.Equal(((ab - bb) % P + P) % P, ToBig(Fe.Sub(a, b)));
            Assert.Equal(ab * bb % P, ToBig(Fe.Mul(a, b)));
            Assert.Equal(ab * ab % P, ToBig(Fe.Sqr(a)));
            Assert.Equal(((P - ab) % P), ToBig(Fe.Neg(a)));
            if (ab != 0) Assert.Equal(BigInteger.ModPow(ab, P - 2, P), ToBig(Fe.Inv(a)));
        }
    }

    [Fact]
    public void SqrtRatioM1_ProducesCorrectRoot()
    {
        int squares = 0;
        for (int i = 0; i < 500; i++)
        {
            var (u, ub) = Rand();
            var (v, vb) = Rand();
            if (vb == 0) continue;
            (bool ws, Fe r) = Ristretto255.SqrtRatioM1(u, v);
            BigInteger rb = ToBig(r);
            // Legendre: u/v is a QR iff (u/v)^((p-1)/2) == 1.
            BigInteger uv = ub * BigInteger.ModPow(vb, P - 2, P) % P;
            bool isQr = ub == 0 || BigInteger.ModPow(uv, (P - 1) / 2, P) == 1;
            Assert.Equal(isQr, ws);
            if (ws)
            {
                squares++;
                Assert.Equal(uv, rb * rb % P);          // r² == u/v
                Assert.True((rb & 1) == 0 || rb == 0);  // root is non-negative (even)
            }
        }
        Assert.True(squares > 50);   // sanity: we actually exercised the square branch
    }

    [Fact]
    public void PowP58_MatchesBigInteger()
    {
        BigInteger exp = (P - 5) / 8;
        for (int i = 0; i < 200; i++)
        {
            var (a, ab) = Rand();
            Assert.Equal(BigInteger.ModPow(ab, exp, P), ToBig(Fe.PowP58(a)));
        }
    }
}
