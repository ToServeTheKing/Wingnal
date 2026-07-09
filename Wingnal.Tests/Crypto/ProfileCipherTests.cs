using System;
using System.Security.Cryptography;
using System.Text;
using Wingnal.Protocol.Crypto;
using Wingnal.Service.Crypto;
using Xunit;

namespace Wingnal.Tests.Crypto;

public class ProfileCipherTests
{
    // Builds a Signal profile-name blob: nonce(12) || AES-256-GCM(profileKey, nonce, padded) || tag(16),
    // base64-encoded — the same layout the profile endpoint returns in its "name" field.
    private static string EncryptName(byte[] profileKey, string given, string family, int bucket = 53)
    {
        byte[] givenBytes = Encoding.UTF8.GetBytes(given);
        byte[] familyBytes = Encoding.UTF8.GetBytes(family);
        var padded = new byte[bucket];                              // zero-filled → trailing padding
        Array.Copy(givenBytes, 0, padded, 0, givenBytes.Length);
        int familyStart = givenBytes.Length + 1;                    // one NUL separates given/family
        Array.Copy(familyBytes, 0, padded, familyStart, familyBytes.Length);

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertextAndTag = CryptoPrimitives.AesGcmEncrypt(profileKey, nonce, padded);
        var blob = new byte[nonce.Length + ciphertextAndTag.Length];
        Array.Copy(nonce, 0, blob, 0, nonce.Length);
        Array.Copy(ciphertextAndTag, 0, blob, nonce.Length, ciphertextAndTag.Length);
        return Convert.ToBase64String(blob);
    }

    [Fact]
    public void DecryptName_RoundTripsGivenAndFamily()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        string blob = EncryptName(key, "Alice", "Smith");

        Assert.Equal("Alice Smith", ProfileCipher.DecryptName(key, blob));
    }

    [Fact]
    public void DecryptName_GivenNameOnly_HasNoTrailingSpace()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        string blob = EncryptName(key, "Bob", "");

        Assert.Equal("Bob", ProfileCipher.DecryptName(key, blob));
    }

    [Fact]
    public void DecryptName_WrongKey_ReturnsNull()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] otherKey = RandomNumberGenerator.GetBytes(32);
        string blob = EncryptName(key, "Alice", "Smith");

        Assert.Null(ProfileCipher.DecryptName(otherKey, blob));   // GCM tag mismatch
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-valid-base64!!")]
    [InlineData("QUJD")]   // valid base64 but far too short to hold a nonce + tag
    public void DecryptName_InvalidInput_ReturnsNull(string? input)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);

        Assert.Null(ProfileCipher.DecryptName(key, input));
    }

    [Fact]
    public void DecryptName_WrongKeyLength_ReturnsNull()
    {
        byte[] shortKey = RandomNumberGenerator.GetBytes(16);
        byte[] realKey = RandomNumberGenerator.GetBytes(32);
        string blob = EncryptName(realKey, "Alice", "Smith");

        Assert.Null(ProfileCipher.DecryptName(shortKey, blob));
    }
}
