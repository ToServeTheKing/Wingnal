using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

/// <summary>
/// Cross-checks the constant-time signing primitives (<see cref="Ed25519Ct"/>, built on BouncyCastle's
/// constant-time field) against the existing KAT-validated BigInteger reference (<see cref="Ed25519Math"/>)
/// across many random inputs. Byte-identical output ⇒ the constant-time path computes the same function,
/// so swapping it into signing can't change/break signatures.
/// </summary>
public class Ed25519CtTests
{
    [Fact]
    public void ScalarMultBase_MatchesReference()
    {
        for (int i = 0; i < 64; i++)
        {
            byte[] k = RandomNumberGenerator.GetBytes(32);
            byte[] ct = Ed25519Ct.ScalarMultBaseEncode(k);
            byte[] reference = Ed25519Math.Encode(Ed25519Math.ScalarMultBase(Ed25519Math.FromLe(k)));
            Assert.Equal(reference, ct);
        }
    }

    [Fact]
    public void ScReduce_MatchesReference()
    {
        for (int i = 0; i < 64; i++)
        {
            byte[] h = RandomNumberGenerator.GetBytes(64);
            byte[] ct = Ed25519Ct.ScReduce(h);
            byte[] reference = Ed25519Math.ToLe32(Ed25519Math.ScReduce(h));
            Assert.Equal(reference, ct);
        }
    }

    [Fact]
    public void ScMulAdd_MatchesReference()
    {
        for (int i = 0; i < 64; i++)
        {
            byte[] a = Ed25519Ct.ScReduce(RandomNumberGenerator.GetBytes(64));
            byte[] b = Ed25519Ct.ScReduce(RandomNumberGenerator.GetBytes(64));
            byte[] c = Ed25519Ct.ScReduce(RandomNumberGenerator.GetBytes(64));
            byte[] ct = Ed25519Ct.ScMulAdd(a, b, c);
            var expected = Ed25519Math.Mod(
                Ed25519Math.FromLe(a) * Ed25519Math.FromLe(b) + Ed25519Math.FromLe(c), Ed25519Math.L);
            Assert.Equal(Ed25519Math.ToLe32(expected), ct);
        }
    }
}
