using System.Security.Cryptography;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

public class PrimitivesTests
{
    [Fact]
    public void Hkdf_MatchesRfc5869TestCase1()
    {
        // RFC 5869, Appendix A.1 (SHA-256).
        byte[] ikm = TestHex.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = TestHex.Decode("000102030405060708090a0b0c");
        byte[] info = TestHex.Decode("f0f1f2f3f4f5f6f7f8f9");
        const string expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        byte[] okm = CryptoPrimitives.Hkdf(ikm, salt, info, 42);

        Assert.Equal(expected, TestHex.Encode(okm));
    }

    [Fact]
    public void AesCbc_RoundTrips()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = RandomNumberGenerator.GetBytes(100);

        byte[] ciphertext = CryptoPrimitives.AesCbcEncrypt(key, iv, plaintext);
        byte[] decrypted = CryptoPrimitives.AesCbcDecrypt(key, iv, ciphertext);

        Assert.Equal(TestHex.Encode(plaintext), TestHex.Encode(decrypted));
    }

    [Fact]
    public void AesGcm_RoundTrips_AndDetectsTampering()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = RandomNumberGenerator.GetBytes(64);
        byte[] aad = RandomNumberGenerator.GetBytes(16);

        byte[] sealed_ = CryptoPrimitives.AesGcmEncrypt(key, nonce, plaintext, aad);
        byte[] opened = CryptoPrimitives.AesGcmDecrypt(key, nonce, sealed_, aad);
        Assert.Equal(TestHex.Encode(plaintext), TestHex.Encode(opened));

        sealed_[0] ^= 0x01;
        Assert.Throws<AuthenticationTagMismatchException>(
            () => CryptoPrimitives.AesGcmDecrypt(key, nonce, sealed_, aad));
    }

    [Fact]
    public void Curve25519_AgreementIsSymmetric()
    {
        ECKeyPair alice = Curve25519.GenerateKeyPair();
        ECKeyPair bob = Curve25519.GenerateKeyPair();

        byte[] aliceShared = Curve25519.CalculateAgreement(bob.PublicKey, alice.PrivateKey);
        byte[] bobShared = Curve25519.CalculateAgreement(alice.PublicKey, bob.PrivateKey);

        Assert.Equal(TestHex.Encode(aliceShared), TestHex.Encode(bobShared));
        Assert.Equal(32, aliceShared.Length);
    }

    [Fact]
    public void Curve25519_EncodeDecodePoint_RoundTrips()
    {
        ECKeyPair keyPair = Curve25519.GenerateKeyPair();

        byte[] encoded = Curve25519.EncodePoint(keyPair.PublicKey);
        Assert.Equal(33, encoded.Length);
        Assert.Equal(Curve25519.DjbType, encoded[0]);

        byte[] decoded = Curve25519.DecodePoint(encoded);
        Assert.Equal(TestHex.Encode(keyPair.PublicKey), TestHex.Encode(decoded));
    }

    [Fact]
    public void Kyber_EncapsulateDecapsulate_SharesSecret()
    {
        KyberKeyPair keyPair = Kyber.GenerateKeyPair();

        KyberEncapsulation encapsulation = Kyber.Encapsulate(keyPair.PublicKey);
        byte[] recovered = Kyber.Decapsulate(keyPair.PrivateKey, encapsulation.CipherText);

        Assert.Equal(TestHex.Encode(encapsulation.SharedSecret), TestHex.Encode(recovered));
        Assert.Equal(32, encapsulation.SharedSecret.Length);
    }
}
