using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;
using Wingnal.Service.Protos;
using Wingnal.Service.Provisioning;
using Xunit;

namespace Wingnal.Tests.Provisioning;

public class ProvisioningCipherTests
{
    private static readonly byte[] Info = "TextSecure Provisioning Message"u8.ToArray();

    /// <summary>Mirrors the primary device's encryption side: ECDH against the linker's advertised
    /// ephemeral key, HKDF, then AES-256-CBC + HMAC-SHA256 over version||iv||ciphertext.</summary>
    private static ProvisionEnvelope SealEnvelope(byte[] linkerPublicKey, ProvisionMessage message)
    {
        ECKeyPair theirEphemeral = Curve25519.GenerateKeyPair();
        byte[] sharedSecret = Curve25519.CalculateAgreement(
            Curve25519.DecodePoint(linkerPublicKey), theirEphemeral.PrivateKey);
        byte[] keys = CryptoPrimitives.Hkdf(sharedSecret, salt: null, info: Info, outputLength: 64);
        byte[] cipherKey = keys[..32];
        byte[] macKey = keys[32..];

        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] ciphertext = CryptoPrimitives.AesCbcEncrypt(cipherKey, iv, message.ToByteArray());

        var signedBody = new byte[1 + iv.Length + ciphertext.Length];
        signedBody[0] = 0x01;
        Array.Copy(iv, 0, signedBody, 1, iv.Length);
        Array.Copy(ciphertext, 0, signedBody, 1 + iv.Length, ciphertext.Length);

        byte[] mac = CryptoPrimitives.HmacSha256(macKey, signedBody);
        var body = new byte[signedBody.Length + mac.Length];
        Array.Copy(signedBody, 0, body, 0, signedBody.Length);
        Array.Copy(mac, 0, body, signedBody.Length, mac.Length);

        return new ProvisionEnvelope
        {
            PublicKey = ByteString.CopyFrom(Curve25519.EncodePoint(theirEphemeral.PublicKey)),
            Body = ByteString.CopyFrom(body),
        };
    }

    [Fact]
    public void Decrypt_SyntheticEnvelope_RoundTripsProvisionMessage()
    {
        var cipher = new ProvisioningCipher();
        IdentityKeyPair identity = IdentityKeyPair.Generate();

        var original = new ProvisionMessage
        {
            AciIdentityKeyPublic = ByteString.CopyFrom(identity.PublicKey.Serialize()),
            AciIdentityKeyPrivate = ByteString.CopyFrom(identity.PrivateKey),
            Number = "+15555550123",
            Aci = "8f6c4d1e-2b3a-4c5d-9e8f-0a1b2c3d4e5f",
            Pni = "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
            ProvisioningCode = "123456",
            ProvisioningVersion = 1,
            ReadReceipts = true,
            ProfileKey = ByteString.CopyFrom(RandomNumberGenerator.GetBytes(32)),
        };

        ProvisionEnvelope envelope = SealEnvelope(cipher.PublicKey, original);
        ProvisionMessage decrypted = cipher.Decrypt(envelope);

        Assert.Equal(original.Number, decrypted.Number);
        Assert.Equal(original.Aci, decrypted.Aci);
        Assert.Equal(original.Pni, decrypted.Pni);
        Assert.Equal(original.ProvisioningCode, decrypted.ProvisioningCode);
        Assert.True(original.AciIdentityKeyPrivate.Span.SequenceEqual(decrypted.AciIdentityKeyPrivate.Span));
        Assert.True(original.ProfileKey.Span.SequenceEqual(decrypted.ProfileKey.Span));
    }



    [Fact]
    public void Decrypt_TamperedMac_Throws()
    {
        var cipher = new ProvisioningCipher();
        ProvisionEnvelope envelope = SealEnvelope(cipher.PublicKey, new ProvisionMessage { Number = "+15555550000" });

        byte[] body = envelope.Body.ToByteArray();
        body[^1] ^= 0x01; // corrupt the trailing MAC
        envelope.Body = ByteString.CopyFrom(body);

        Assert.Throws<InvalidOperationException>(() => cipher.Decrypt(envelope));
    }
}
