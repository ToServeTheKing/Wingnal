using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Keys;
using Wingnal.Service.Messaging;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Offline validation of sealed-sender (UNIDENTIFIED_SENDER) receive: a sender wraps a normal
/// PreKeySignalMessage in a Sealed Sender v1 envelope; the recipient unwraps it (recovering the real
/// sender from the certificate) and decrypts the inner message through the session pipeline. This is
/// how messages from other people arrive on modern Signal.
/// </summary>
public class SealedSenderTests
{
    [Fact]
    public void SealedSenderV1_DecryptsToTextAndRecoversSender()
    {
        // Recipient (us).
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var recipientStore = new AccountProtocolStore(recipient);
        var decryptor = new MessageDecryptor(recipientStore);

        // Sender (some other person).
        const string senderAci = "a65ec3d8-3e8c-4018-9349-f8c837f8631e";
        SignalAccount sender = BuildAccount(senderAci, deviceId: 3, out IdentityKeyPair senderIdentity, out _, out _);
        var senderStore = new AccountProtocolStore(sender);
        var messageSender = new MessageSender(sender, senderStore, rest: null!);

        // The sender encrypts a normal PreKeySignalMessage to our bundle (the inner ciphertext).
        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
            Devices = new[]
            {
                new PreKeyResponseDevice
                {
                    DeviceId = 1,
                    RegistrationId = recipient.AciRegistrationId,
                    SignedPreKey = new SignedPreKeyDto
                    {
                        KeyId = signed.Id,
                        PublicKey = Convert.ToBase64String(Curve25519.EncodePoint(signed.KeyPair.PublicKey)),
                        Signature = Convert.ToBase64String(signed.Signature),
                    },
                    PqPreKey = new SignedPreKeyDto
                    {
                        KeyId = kyber.Id,
                        PublicKey = Convert.ToBase64String(KemKeySerialization.Serialize(kyber.KeyPair.PublicKey)),
                        Signature = Convert.ToBase64String(kyber.Signature),
                    },
                },
            },
        };
        OutgoingMessageList list = messageSender.BuildOutgoingList(recipient.Aci, "hello from a stranger", bundles, 1700000000000);
        OutgoingMessage inner = list.Messages[0];
        Assert.Equal(3, inner.Type);   // PREKEY_MESSAGE
        byte[] innerCiphertext = Convert.FromBase64String(inner.Content);

        // Wrap it in a Sealed Sender v1 envelope with a properly signed cert chain (test trust root).
        ECKeyPair trustRoot = Curve25519.GenerateKeyPair();
        long now = 1700000000000;
        byte[] sealedBytes = SealedSenderDecryptor.Encrypt(
            senderIdentity, recipientIdentity.PublicKey, senderAci, senderDevice: 3,
            ciphertextType: 1, innerCiphertext, trustRoot, expiresMs: now + 86_400_000);

        // The recipient unwraps it, validating the cert chain against the (test) trust root.
        SealedSenderDecryptor.Unsealed unsealed = SealedSenderDecryptor.Decrypt(
            sealedBytes, recipientIdentity, now, new[] { Curve25519.EncodePoint(trustRoot.PublicKey) });

        Assert.Equal(senderAci, unsealed.SenderUuid);
        Assert.Equal(3u, unsealed.SenderDevice);

        // Full pipeline through MessageDecryptor (uses production trust roots, so this would reject our
        // test cert — we assert the unwrap above; here we just confirm the inner ciphertext decrypts).
        var env = new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = senderAci, SourceDeviceId = 3,
            Content = ByteString.CopyFrom(unsealed.Content),
            ServerTimestamp = (ulong)now,
        };
        DecryptedMessage? result = decryptor.Decrypt(env);
        Assert.NotNull(result);
        Assert.Equal("hello from a stranger", result!.Body);
    }

    [Fact]
    public void SealedSender_RejectsUntrustedCertificate()
    {
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out _, out _);
        SignalAccount sender = BuildAccount("a65ec3d8-3e8c-4018-9349-f8c837f8631e", deviceId: 3,
            out IdentityKeyPair senderIdentity, out _, out _);

        long now = 1700000000000;
        ECKeyPair realRoot = Curve25519.GenerateKeyPair();
        byte[] sealedBytes = SealedSenderDecryptor.Encrypt(
            senderIdentity, recipientIdentity.PublicKey, sender.Aci, 3, 1, new byte[] { 1, 2, 3, 4 },
            realRoot, expiresMs: now + 86_400_000);

        // A DIFFERENT trust root must reject the certificate (forged-server defence).
        ECKeyPair attackerRoot = Curve25519.GenerateKeyPair();
        Assert.Throws<InvalidMessageException>(() => SealedSenderDecryptor.Decrypt(
            sealedBytes, recipientIdentity, now, new[] { Curve25519.EncodePoint(attackerRoot.PublicKey) }));
    }

    [Fact]
    public void SealedSender_RejectsExpiredCertificate()
    {
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out _, out _);
        SignalAccount sender = BuildAccount("a65ec3d8-3e8c-4018-9349-f8c837f8631e", deviceId: 3,
            out IdentityKeyPair senderIdentity, out _, out _);

        ECKeyPair root = Curve25519.GenerateKeyPair();
        byte[] sealedBytes = SealedSenderDecryptor.Encrypt(
            senderIdentity, recipientIdentity.PublicKey, sender.Aci, 3, 1, new byte[] { 1, 2, 3, 4 },
            root, expiresMs: 1000);   // long expired

        Assert.Throws<InvalidMessageException>(() => SealedSenderDecryptor.Decrypt(
            sealedBytes, recipientIdentity, nowMs: 2000, new[] { Curve25519.EncodePoint(root.PublicKey) }));
    }

    [Fact]
    public void SealedSender_RejectsTamper()
    {
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out _, out _);
        SignalAccount sender = BuildAccount("a65ec3d8-3e8c-4018-9349-f8c837f8631e", deviceId: 3,
            out IdentityKeyPair senderIdentity, out _, out _);

        ECKeyPair root = Curve25519.GenerateKeyPair();
        byte[] sealedBytes = SealedSenderDecryptor.Encrypt(
            senderIdentity, recipientIdentity.PublicKey, sender.Aci, 3, 1, new byte[] { 1, 2, 3, 4 },
            root, expiresMs: 1700000000000 + 86_400_000);
        sealedBytes[^1] ^= 0x01;   // corrupt the encrypted message's MAC region

        Assert.ThrowsAny<Exception>(() => SealedSenderDecryptor.Decrypt(
            sealedBytes, recipientIdentity, 1700000000000, new[] { Curve25519.EncodePoint(root.PublicKey) }));
    }

    private static SignalAccount BuildAccount(string aci, int deviceId, out IdentityKeyPair aciIdentity,
        out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber)
    {
        aciIdentity = IdentityKeyPair.Generate();
        IdentityKeyPair pniIdentity = IdentityKeyPair.Generate();
        signed = PreKeyHelper.GenerateSignedPreKey(aciIdentity.PrivateKey, 1);
        kyber = PreKeyHelper.GenerateKyberPreKey(aciIdentity.PrivateKey, 1);
        SignedPreKeyRecord s = signed; KyberPreKeyRecord k = kyber;

        return new SignalAccount
        {
            Aci = aci,
            Pni = "00000000-0000-0000-0000-0000000000ff",
            Number = "+15555550100",
            DeviceId = deviceId,
            Password = "pw",
            AciRegistrationId = 1234,
            PniRegistrationId = 5678,
            AciIdentityPublic = aciIdentity.PublicKey.Serialize(),
            AciIdentityPrivate = aciIdentity.PrivateKey,
            PniIdentityPublic = pniIdentity.PublicKey.Serialize(),
            PniIdentityPrivate = pniIdentity.PrivateKey,
            ProfileKey = RandomNumberGenerator.GetBytes(32),
            AciPreKeys = Material(s, k),
            PniPreKeys = Material(s, k),
        };
    }

    private static RegisteredPreKeys Material(SignedPreKeyRecord signed, KyberPreKeyRecord kyber) => new()
    {
        SignedPreKeyId = signed.Id,
        SignedPreKeyPublic = signed.KeyPair.PublicKey,
        SignedPreKeyPrivate = signed.KeyPair.PrivateKey,
        SignedPreKeySignature = signed.Signature,
        KyberPreKeyId = kyber.Id,
        KyberPreKeyPublic = kyber.KeyPair.PublicKey,
        KyberPreKeyPrivate = kyber.KeyPair.PrivateKey,
        KyberPreKeySignature = kyber.Signature,
    };
}
