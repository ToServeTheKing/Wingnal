using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Provisioning;

/// <summary>
/// Decrypts the <see cref="ProvisionEnvelope"/> a primary device sends during secondary-device
/// linking. This client advertises an ephemeral Curve25519 public key in the linking QR code; the
/// phone performs ECDH against it, derives keys via HKDF, and AES-256-CBC+HMAC encrypts a
/// <see cref="ProvisionMessage"/> carrying our new identity key and account identifiers.
/// </summary>
public sealed class ProvisioningCipher
{
    private static readonly byte[] Info = "TextSecure Provisioning Message"u8.ToArray();

    private readonly ECKeyPair _ephemeralKeyPair;

    public ProvisioningCipher() : this(Curve25519.GenerateKeyPair()) { }

    public ProvisioningCipher(ECKeyPair ephemeralKeyPair) => _ephemeralKeyPair = ephemeralKeyPair;

    /// <summary>The 33-byte DjbECPublicKey advertised to the primary device in the QR code.</summary>
    public byte[] PublicKey => Curve25519.EncodePoint(_ephemeralKeyPair.PublicKey);

    public ProvisionMessage Decrypt(ProvisionEnvelope envelope)
    {
        byte[] theirPublicKey = Curve25519.DecodePoint(envelope.PublicKey.Span);
        byte[] body = envelope.Body.ToByteArray();

        if (body.Length < 1 + 16 + 32 || body[0] != 0x01)
            throw new InvalidOperationException("malformed provision envelope body");

        byte[] sharedSecret = Curve25519.CalculateAgreement(theirPublicKey, _ephemeralKeyPair.PrivateKey);
        byte[] keys = CryptoPrimitives.Hkdf(sharedSecret, salt: null, info: Info, outputLength: 64);
        byte[] cipherKey = keys[..32];
        byte[] macKey = keys[32..];

        int macOffset = body.Length - 32;
        byte[] mac = body[macOffset..];
        byte[] computed = CryptoPrimitives.HmacSha256(macKey, body.AsSpan(0, macOffset));
        if (!CryptographicOperations.FixedTimeEquals(mac, computed))
            throw new InvalidOperationException("provision envelope MAC verification failed");

        byte[] iv = body[1..17];
        byte[] ciphertext = body[17..macOffset];
        byte[] plaintext = CryptoPrimitives.AesCbcDecrypt(cipherKey, iv, ciphertext);

        return ProvisionMessage.Parser.ParseFrom(plaintext);
    }
}
