using System.Text;
using Wingnal.Protocol.ZkGroup.Poksho;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>GV2 Phase C gate (part 1): the SHO must reproduce libsignal poksho's own
/// <c>ShoHmacSha256::test_vectors</c> byte-for-byte, or every downstream zkgroup proof verifies nowhere.</summary>
public class ShoHmacSha256Tests
{
    private static byte[] B(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void Squeeze64_MatchesPokshoVector()
    {
        var sho = new ShoHmacSha256(B("asd"));
        sho.AbsorbAndRatchet(B("asdasd"));
        Assert.Equal(
            "392cb944937303 7fa0c11aebed69cca3b7d3bc9790878f341729c65d5506442f04986cb5c9098f277c3ea640a4dc6e90372b433a90af9aea7072eaba3398c4fe".Replace(" ", ""),
            Convert.ToHexString(sho.SqueezeAndRatchet(64)).ToLowerInvariant());
    }

    [Fact]
    public void Squeeze65_MatchesPokshoVector()
    {
        var sho = new ShoHmacSha256(B("asd"));
        sho.AbsorbAndRatchet(B("asdasd"));
        Assert.Equal(
            "392cb944937303 7fa0c11aebed69cca3b7d3bc9790878f341729c65d5506442f04986cb5c9098f277c3ea640a4dc6e90372b433a90af9aea7072eaba3398c4fe7a".Replace(" ", ""),
            Convert.ToHexString(sho.SqueezeAndRatchet(65)).ToLowerInvariant());
    }

    [Fact]
    public void MultiAbsorbMultiSqueeze_MatchesPokshoVector()
    {
        var sho = new ShoHmacSha256(B(""));
        sho.AbsorbAndRatchet(B("abc"));
        sho.AbsorbAndRatchet(new byte[63]);
        sho.AbsorbAndRatchet(new byte[64]);
        sho.AbsorbAndRatchet(new byte[65]);
        sho.AbsorbAndRatchet(new byte[127]);
        sho.AbsorbAndRatchet(new byte[128]);
        sho.AbsorbAndRatchet(new byte[129]);
        sho.SqueezeAndRatchet(63);
        sho.SqueezeAndRatchet(64);
        sho.SqueezeAndRatchet(65);
        sho.SqueezeAndRatchet(127);
        sho.SqueezeAndRatchet(128);
        sho.SqueezeAndRatchet(129);
        sho.AbsorbAndRatchet(B("def"));
        Assert.Equal(
            "c5c13bcc6596c25fc4514eac9269dd6e3e57ef70f4bfb8d67fd3082ed9732d7790d8d2686f19eb2533a65c94bb8ceda0a068e1b615c81bb26e411889da9fb7",
            Convert.ToHexString(sho.SqueezeAndRatchet(63)).ToLowerInvariant());
    }
}
