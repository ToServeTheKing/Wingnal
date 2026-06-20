using System.Numerics;
using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

/// <summary>
/// Validates the shared Ed25519 group/field/scalar core (<see cref="Ed25519Math"/>) against the
/// RFC 8032 known-answer vectors. XEd25519 is built on the exact same routines, so passing these
/// gives high confidence in the underlying arithmetic, encoding, and SHA-512 reduction.
/// </summary>
public class Ed25519KatTests
{
    // RFC 8032, section 7.1.
    [Theory]
    [InlineData(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")]
    [InlineData(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")]
    [InlineData(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]
    public void MatchesRfc8032(string seedHex, string publicHex, string messageHex, string signatureHex)
    {
        byte[] seed = TestHex.Decode(seedHex);
        byte[] message = messageHex.Length == 0 ? Array.Empty<byte>() : TestHex.Decode(messageHex);

        (byte[] publicKey, byte[] signature) = Ed25519Reference.Sign(seed, message);

        Assert.Equal(publicHex, TestHex.Encode(publicKey));
        Assert.Equal(signatureHex, TestHex.Encode(signature));
    }

    /// <summary>
    /// Minimal RFC 8032 Ed25519 implemented on top of the production <see cref="Ed25519Math"/>
    /// primitives. Test-only oracle; not used in production (Wingnal signs with XEd25519).
    /// </summary>
    private static class Ed25519Reference
    {
        public static (byte[] publicKey, byte[] signature) Sign(byte[] seed, byte[] message)
        {
            byte[] h = SHA512.HashData(seed);
            byte[] aBytes = h[..32];
            aBytes[0] &= 248;
            aBytes[31] &= 127;
            aBytes[31] |= 64;
            BigInteger a = Ed25519Math.FromLe(aBytes);
            byte[] prefix = h[32..];

            byte[] aEnc = Ed25519Math.Encode(Ed25519Math.ScalarMultBase(a));

            BigInteger r = Ed25519Math.ScReduce(SHA512.HashData(Concat(prefix, message)));
            byte[] rEnc = Ed25519Math.Encode(Ed25519Math.ScalarMultBase(r));

            BigInteger k = Ed25519Math.ScReduce(SHA512.HashData(Concat(rEnc, aEnc, message)));
            BigInteger s = Ed25519Math.Mod(r + k * a, Ed25519Math.L);

            byte[] sig = new byte[64];
            Array.Copy(rEnc, 0, sig, 0, 32);
            Array.Copy(Ed25519Math.ToLe32(s), 0, sig, 32, 32);
            return (aEnc, sig);
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var result = new byte[parts.Sum(p => p.Length)];
            int offset = 0;
            foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
            return result;
        }
    }
}
