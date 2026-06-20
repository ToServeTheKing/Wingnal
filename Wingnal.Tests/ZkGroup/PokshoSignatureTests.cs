using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>
/// GV2 Phase F gate (server-signature verification): poksho's Schnorr signature must reproduce poksho's own
/// signature vector byte-for-byte (sign), verify it, and reject a tampered message. zkgroup signs each
/// GroupChange with this; the client uses Verify to trust server changes.
/// </summary>
public class PokshoSignatureTests
{
    [Fact]
    public void Sign_MatchesPokshoVector_AndVerifies()
    {
        var block64 = new byte[64];
        for (int i = 0; i < 64; i++) block64[i] = (byte)i;
        var block32 = new byte[32];
        for (int i = 0; i < 32; i++) block32[i] = (byte)i;
        var message = new byte[100];
        for (int i = 0; i < 100; i++) message[i] = (byte)i;

        Scalar25519 a = Scalar25519.FromBytesModOrderWide(block64);
        Ristretto255 pub = Ristretto255.BasePoint.Multiply(a);

        byte[] signature = PokshoSignature.Sign(a, pub, message, block32);

        const string expected =
            "a08f6b34a282dd4c7cfc40b918f224a6b631ca5f6480a10b42bd1408602a7e00" +
            "8a23a1e32479befb5e26b9f0f4fe0e9e9e9ec9afad269143acb03a22c6364f03";
        Assert.Equal(expected, Convert.ToHexString(signature).ToLowerInvariant());

        Assert.True(PokshoSignature.Verify(signature, pub, message));

        message[0] ^= 1;
        Assert.False(PokshoSignature.Verify(signature, pub, message));
    }
}
