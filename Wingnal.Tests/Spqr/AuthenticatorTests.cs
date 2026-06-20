using System.Security.Cryptography;
using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

public class AuthenticatorTests
{
    [Fact]
    public void MacAndVerify_RoundTrips_AndIsDeterministic()
    {
        byte[] rootKey = RandomNumberGenerator.GetBytes(32);
        byte[] ct = RandomNumberGenerator.GetBytes(100);
        byte[] hdr = RandomNumberGenerator.GetBytes(64);

        var a = new Authenticator(rootKey, epoch: 7);
        var b = new Authenticator(rootKey, epoch: 7); // same inputs => same derived keys

        byte[] ctMac = a.MacCiphertext(7, ct);
        byte[] hdrMac = a.MacHeader(7, hdr);

        Assert.True(b.VerifyCiphertext(7, ct, ctMac));
        Assert.True(b.VerifyHeader(7, hdr, hdrMac));
        Assert.Equal(ctMac, b.MacCiphertext(7, ct));
        Assert.Equal(32, ctMac.Length);
    }

    [Fact]
    public void Verify_RejectsTamperedMacOrData()
    {
        var a = new Authenticator(RandomNumberGenerator.GetBytes(32), epoch: 1);
        byte[] ct = RandomNumberGenerator.GetBytes(50);
        byte[] mac = a.MacCiphertext(1, ct);

        byte[] badMac = (byte[])mac.Clone();
        badMac[0] ^= 0xFF;
        Assert.False(a.VerifyCiphertext(1, ct, badMac));

        ct[0] ^= 0xFF;
        Assert.False(a.VerifyCiphertext(1, ct, mac));
    }

    [Fact]
    public void Update_AdvancesKeys()
    {
        var a = new Authenticator(new byte[32], epoch: 0);
        byte[] before = (byte[])a.MacKey.Clone();
        a.Update(1, RandomNumberGenerator.GetBytes(32));
        Assert.NotEqual(before, a.MacKey);
    }
}
