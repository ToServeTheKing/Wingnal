using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

public class XEd25519Tests
{
    [Fact]
    public void SignThenVerify_RoundTrips()
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();
        byte[] message = RandomNumberGenerator.GetBytes(140);
        byte[] random = RandomNumberGenerator.GetBytes(64);

        byte[] signature = XEd25519.CalculateSignature(keyPair.PrivateKey, message, random);

        Assert.Equal(64, signature.Length);
        Assert.True(XEd25519.VerifySignature(keyPair.PublicKey, message, signature));
    }

    [Fact]
    public void Verify_RejectsTamperedMessage()
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();
        byte[] message = RandomNumberGenerator.GetBytes(32);
        byte[] signature = XEd25519.CalculateSignature(keyPair.PrivateKey, message, RandomNumberGenerator.GetBytes(64));

        message[0] ^= 0x01;
        Assert.False(XEd25519.VerifySignature(keyPair.PublicKey, message, signature));
    }

    [Fact]
    public void Verify_RejectsTamperedSignature()
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();
        byte[] message = RandomNumberGenerator.GetBytes(32);
        byte[] signature = XEd25519.CalculateSignature(keyPair.PrivateKey, message, RandomNumberGenerator.GetBytes(64));

        signature[10] ^= 0x01;
        Assert.False(XEd25519.VerifySignature(keyPair.PublicKey, message, signature));
    }

    [Fact]
    public void Verify_RejectsWrongKey()
    {
        ECKeyPair signer = Curve25519.GenerateKeyPair();
        ECKeyPair other = Curve25519.GenerateKeyPair();
        byte[] message = RandomNumberGenerator.GetBytes(32);
        byte[] signature = XEd25519.CalculateSignature(signer.PrivateKey, message, RandomNumberGenerator.GetBytes(64));

        Assert.False(XEd25519.VerifySignature(other.PublicKey, message, signature));
    }

    [Fact]
    public void Signature_IsRandomized_ButBothVerify()
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();
        byte[] message = RandomNumberGenerator.GetBytes(32);

        byte[] sig1 = XEd25519.CalculateSignature(keyPair.PrivateKey, message, RandomNumberGenerator.GetBytes(64));
        byte[] sig2 = XEd25519.CalculateSignature(keyPair.PrivateKey, message, RandomNumberGenerator.GetBytes(64));

        Assert.NotEqual(TestHex.Encode(sig1), TestHex.Encode(sig2));
        Assert.True(XEd25519.VerifySignature(keyPair.PublicKey, message, sig1));
        Assert.True(XEd25519.VerifySignature(keyPair.PublicKey, message, sig2));
    }
}
