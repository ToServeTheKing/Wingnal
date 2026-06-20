using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;
using Wingnal.Service.Protos.SealedSender;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Decrypts a Sealed Sender v1 envelope (UNIDENTIFIED_SENDER) to recover the sender and the inner
/// ciphertext, which the normal session pipeline then decrypts. This is how messages other people send
/// us (and their replies) arrive — modern Signal clients default to sealed sender. Byte-exact with
/// libsignal v0.96.1 sealed_sender.rs (v1). Sealed Sender v2 (multi-recipient) is not handled here.
///
/// NOTE: the sender certificate's server signature is NOT validated against Signal's trust root yet
/// (see SHORTCUTS.md). The message is still cryptographically authenticated by the inner Double Ratchet
/// session (its MAC binds to the sender's identity key), so a forged certificate can't forge content;
/// trust-root validation only adds server-attested sender identity.
/// </summary>
public static class SealedSenderDecryptor
{
    private const byte SealedSenderV1MajorVersion = 1;
    private const byte SealedSenderV2MajorVersion = 2;
    private static readonly byte[] SaltPrefix = "UnidentifiedDelivery"u8.ToArray();

    /// <summary>The unwrapped sealed-sender payload: who sent it + the inner ciphertext to feed the
    /// session cipher.</summary>
    public sealed record Unsealed(string SenderUuid, uint SenderDevice, int CiphertextType, byte[] Content);

    public static Unsealed Decrypt(byte[] serialized, IdentityKeyPair ourIdentity, long nowMs,
        IReadOnlyList<byte[]>? trustRoots = null)
    {
        if (serialized.Length < 1) throw new InvalidMessageException("sealed sender message empty");
        int version = (serialized[0] >> 4) & 0xF;
        if (version == SealedSenderV2MajorVersion)
            throw new InvalidMessageException("sealed sender v2 not supported");
        if (version is not (0 or SealedSenderV1MajorVersion))
            throw new InvalidMessageException($"unknown sealed sender version {version}");

        UnidentifiedSenderMessage outer = UnidentifiedSenderMessage.Parser.ParseFrom(serialized.AsSpan(1).ToArray());
        byte[] ephemeralPublic = Curve25519.DecodePoint(outer.EphemeralPublic.Span);
        byte[] encryptedStatic = outer.EncryptedStatic.ToByteArray();
        byte[] encryptedMessage = outer.EncryptedMessage.ToByteArray();

        byte[] ourIdPriv = ourIdentity.PrivateKey;
        byte[] ourIdPub = ourIdentity.PublicKey.Serialize();   // 33-byte DjbECPublicKey

        // Ephemeral keys: HKDF(salt = "UnidentifiedDelivery" || ourPub || ephPub, ikm = ECDH(eph, ourId)).
        byte[] ephSalt = Concat(SaltPrefix, ourIdPub, Curve25519.EncodePoint(ephemeralPublic));
        byte[] ephSecret = Curve25519.CalculateAgreement(ephemeralPublic, ourIdPriv);
        byte[] ephKeys = CryptoPrimitives.Hkdf(ephSecret, ephSalt, info: null, 96);
        byte[] chainKey = ephKeys.AsSpan(0, 32).ToArray();
        byte[] ephCipherKey = ephKeys.AsSpan(32, 32).ToArray();
        byte[] ephMacKey = ephKeys.AsSpan(64, 32).ToArray();

        byte[] senderStaticBytes = DecryptCtrHmac(encryptedStatic, ephCipherKey, ephMacKey);
        byte[] senderStaticPublic = Curve25519.DecodePoint(senderStaticBytes);

        // Static keys: HKDF(salt = chainKey || encryptedStatic, ikm = ECDH(senderStatic, ourId)); first 32 discarded.
        byte[] staticSalt = Concat(chainKey, encryptedStatic);
        byte[] staticSecret = Curve25519.CalculateAgreement(senderStaticPublic, ourIdPriv);
        byte[] staticKeys = CryptoPrimitives.Hkdf(staticSecret, staticSalt, info: null, 96);
        byte[] staticCipherKey = staticKeys.AsSpan(32, 32).ToArray();
        byte[] staticMacKey = staticKeys.AsSpan(64, 32).ToArray();

        byte[] innerBytes = DecryptCtrHmac(encryptedMessage, staticCipherKey, staticMacKey);
        UnidentifiedSenderMessage.Types.Message inner = UnidentifiedSenderMessage.Types.Message.Parser.ParseFrom(innerBytes);

        // Validate the server-attested sender certificate (trust root → server → sender, not expired)
        // before believing the claimed sender.
        var senderCert = SenderCertificate.Parser.ParseFrom(inner.SenderCertificate);
        SenderCertificateValidator.Validate(senderCert, nowMs, trustRoots ?? SenderCertificateValidator.ProductionTrustRoots);

        (string uuid, uint device) = ExtractSender(senderCert);
        return new Unsealed(uuid, device, (int)inner.Type, inner.Content.ToByteArray());
    }

    /// <summary>Builds a Sealed Sender v1 envelope using a real (server-issued) sender certificate.
    /// Mirrors libsignal sealed_sender_encrypt.</summary>
    public static byte[] EncryptWithCertificate(IdentityKeyPair senderIdentity, IdentityKey recipientIdentity,
        byte[] senderCertificate, int ciphertextType, byte[] content)
    {
        byte[] recipientPubRaw = recipientIdentity.PublicKey;
        byte[] recipientPubEnc = recipientIdentity.Serialize();
        byte[] senderIdPubEnc = senderIdentity.PublicKey.Serialize();

        ECKeyPair ephemeral = Curve25519.GenerateKeyPair();
        byte[] ephPubEnc = Curve25519.EncodePoint(ephemeral.PublicKey);

        byte[] ephSalt = Concat(SaltPrefix, recipientPubEnc, ephPubEnc);
        byte[] ephSecret = Curve25519.CalculateAgreement(recipientPubRaw, ephemeral.PrivateKey);
        byte[] ephKeys = CryptoPrimitives.Hkdf(ephSecret, ephSalt, info: null, 96);
        byte[] chainKey = ephKeys.AsSpan(0, 32).ToArray();
        byte[] ephCipherKey = ephKeys.AsSpan(32, 32).ToArray();
        byte[] ephMacKey = ephKeys.AsSpan(64, 32).ToArray();

        byte[] encryptedStatic = EncryptCtrHmac(senderIdPubEnc, ephCipherKey, ephMacKey);

        byte[] staticSalt = Concat(chainKey, encryptedStatic);
        byte[] staticSecret = Curve25519.CalculateAgreement(recipientPubRaw, senderIdentity.PrivateKey);
        byte[] staticKeys = CryptoPrimitives.Hkdf(staticSecret, staticSalt, info: null, 96);
        byte[] staticCipherKey = staticKeys.AsSpan(32, 32).ToArray();
        byte[] staticMacKey = staticKeys.AsSpan(64, 32).ToArray();

        var inner = new UnidentifiedSenderMessage.Types.Message
        {
            Type = (UnidentifiedSenderMessage.Types.Message.Types.Type)ciphertextType,
            SenderCertificate = Google.Protobuf.ByteString.CopyFrom(senderCertificate),
            Content = Google.Protobuf.ByteString.CopyFrom(content),
        };
        byte[] encryptedMessage = EncryptCtrHmac(inner.ToByteArray(), staticCipherKey, staticMacKey);

        var outer = new UnidentifiedSenderMessage
        {
            EphemeralPublic = Google.Protobuf.ByteString.CopyFrom(ephPubEnc),
            EncryptedStatic = Google.Protobuf.ByteString.CopyFrom(encryptedStatic),
            EncryptedMessage = Google.Protobuf.ByteString.CopyFrom(encryptedMessage),
        };
        byte[] body = outer.ToByteArray();
        var result = new byte[1 + body.Length];
        result[0] = 0x11;   // SEALED_SENDER_V1_FULL_VERSION
        Buffer.BlockCopy(body, 0, result, 1, body.Length);
        return result;
    }

    /// <summary>Test helper: builds a signed cert chain (trustRoot → server → sender) and seals with it.</summary>
    public static byte[] Encrypt(IdentityKeyPair senderIdentity, IdentityKey recipientIdentity,
        string senderUuid, uint senderDevice, int ciphertextType, byte[] content, ECKeyPair trustRoot, long expiresMs)
    {
        byte[] cert = BuildCertificate(senderIdentity, senderUuid, senderDevice, trustRoot, expiresMs);
        return EncryptWithCertificate(senderIdentity, recipientIdentity, cert, ciphertextType, content);
    }

    private static byte[] BuildCertificate(IdentityKeyPair senderIdentity, string senderUuid, uint senderDevice,
        ECKeyPair trustRoot, long expiresMs)
    {
        ECKeyPair serverKey = Curve25519.GenerateKeyPair();
        var serverInner = new ServerCertificate.Types.Certificate
        {
            Id = 1,
            Key = Google.Protobuf.ByteString.CopyFrom(Curve25519.EncodePoint(serverKey.PublicKey)),
        };
        byte[] serverInnerBytes = serverInner.ToByteArray();
        var serverCert = new ServerCertificate
        {
            Certificate = Google.Protobuf.ByteString.CopyFrom(serverInnerBytes),
            Signature = Google.Protobuf.ByteString.CopyFrom(
                XEd25519.CalculateSignature(trustRoot.PrivateKey, serverInnerBytes, RandomNumberGenerator.GetBytes(64))),
        };
        var certInner = new SenderCertificate.Types.Certificate
        {
            UuidString = senderUuid,
            SenderDevice = senderDevice,
            Expires = (ulong)expiresMs,
            IdentityKey = Google.Protobuf.ByteString.CopyFrom(senderIdentity.PublicKey.Serialize()),
            Certificate_ = serverCert.ToByteString(),
        };
        byte[] certInnerBytes = certInner.ToByteArray();
        return new SenderCertificate
        {
            Certificate = Google.Protobuf.ByteString.CopyFrom(certInnerBytes),
            Signature = Google.Protobuf.ByteString.CopyFrom(
                XEd25519.CalculateSignature(serverKey.PrivateKey, certInnerBytes, RandomNumberGenerator.GetBytes(64))),
        }.ToByteArray();
    }

    private static byte[] EncryptCtrHmac(byte[] plaintext, byte[] cipherKey, byte[] macKey)
    {
        byte[] ctext = CryptoPrimitives.AesCtr(cipherKey, new byte[16], plaintext);
        byte[] mac = CryptoPrimitives.HmacSha256(macKey, ctext).AsSpan(0, 10).ToArray();
        var result = new byte[ctext.Length + 10];
        Buffer.BlockCopy(ctext, 0, result, 0, ctext.Length);
        Buffer.BlockCopy(mac, 0, result, ctext.Length, 10);
        return result;
    }

    // aes256_ctr_hmacsha256: data = AES-256-CTR(ct) || HMAC-SHA256(macKey, ct)[..10]. Zero CTR nonce.
    private static byte[] DecryptCtrHmac(byte[] data, byte[] cipherKey, byte[] macKey)
    {
        const int macLen = 10;
        if (data.Length < macLen) throw new InvalidMessageException("sealed sender ciphertext truncated");
        int ctLen = data.Length - macLen;
        byte[] ctext = data.AsSpan(0, ctLen).ToArray();
        byte[] theirMac = data.AsSpan(ctLen, macLen).ToArray();

        byte[] ourMac = CryptoPrimitives.HmacSha256(macKey, ctext).AsSpan(0, macLen).ToArray();
        if (!CryptographicOperations.FixedTimeEquals(ourMac, theirMac))
            throw new InvalidMessageException("sealed sender MAC mismatch");

        return CryptoPrimitives.AesCtr(cipherKey, new byte[16], ctext);
    }

    private static (string Uuid, uint Device) ExtractSender(SenderCertificate cert)
    {
        var inner = SenderCertificate.Types.Certificate.Parser.ParseFrom(cert.Certificate);

        string uuid = inner.SenderUuidCase switch
        {
            SenderCertificate.Types.Certificate.SenderUuidOneofCase.UuidString => inner.UuidString,
            SenderCertificate.Types.Certificate.SenderUuidOneofCase.UuidBytes => ServiceIds.StringFromBinary(inner.UuidBytes.Span) ?? "",
            _ => string.Empty,
        };
        if (string.IsNullOrEmpty(uuid))
            throw new InvalidMessageException("sealed sender certificate has no sender uuid");
        return (uuid.ToLowerInvariant(), inner.SenderDevice);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int o = 0;
        foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, result, o, p.Length); o += p.Length; }
        return result;
    }
}
