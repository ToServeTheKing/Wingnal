using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Keys;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Wingnal.Tests.Ratchet;
using Xunit;

namespace Wingnal.Tests.Messaging;

public class MessageDecryptorTests
{
    [Fact]
    public void Decrypt_IncomingPreKeyDataMessage_ReturnsText()
    {
        // Our linked account (recipient) with ACI identity + registered prekeys.
        SignalAccount account = BuildAccount(out IdentityKeyPair aciIdentity,
            out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var ourStore = new AccountProtocolStore(account);
        var decryptor = new MessageDecryptor(ourStore);

        // A sender builds a session to us from our prekey bundle and encrypts a DataMessage.
        const string senderAci = "11111111-1111-1111-1111-111111111111";
        var senderIdentity = IdentityKeyPair.Generate();
        var senderStore = new InMemorySignalProtocolStore(senderIdentity, registrationId: 42);
        var ourAddress = new SignalProtocolAddress(account.Aci, 1);

        var bundle = new PreKeyBundle(
            account.AciRegistrationId, deviceId: 1, preKeyId: null, preKeyPublic: null,
            signedPreKeyId: signed.Id, signedPreKeyPublic: signed.KeyPair.PublicKey,
            signedPreKeySignature: signed.Signature, identityKey: aciIdentity.PublicKey,
            kyberPreKeyId: kyber.Id, kyberPreKeyPublic: kyber.KeyPair.PublicKey,
            kyberPreKeySignature: kyber.Signature);

        new SessionBuilder(senderStore, senderStore, senderStore, senderStore, senderStore, ourAddress)
            .Process(bundle);

        var senderCipher = new SessionCipher(senderStore, senderStore, senderStore, senderStore, senderStore, ourAddress);

        var content = new Content { DataMessage = new DataMessage { Body = "hello from the phone", Timestamp = 1700000000000UL } };
        ICiphertextMessage ciphertext = senderCipher.Encrypt(Pad(content.ToByteArray()));

        var envelope = new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = senderAci,
            SourceDeviceId = 1,
            Content = ByteString.CopyFrom(ciphertext.Serialize()),
            ServerTimestamp = 1700000000001UL,
        };

        DecryptedMessage? result = decryptor.Decrypt(envelope);

        Assert.NotNull(result);
        Assert.Equal("hello from the phone", result!.Body);
        Assert.Equal(senderAci, result.PeerServiceId);
        Assert.False(result.Outgoing);
    }

    [Fact]
    public void Decrypt_AttachmentOnlyMessage_SurfacesPlaceholder()
    {
        SignalAccount account = BuildAccount(out IdentityKeyPair aciIdentity,
            out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var decryptor = new MessageDecryptor(new AccountProtocolStore(account));

        var senderIdentity = IdentityKeyPair.Generate();
        var senderStore = new InMemorySignalProtocolStore(senderIdentity, registrationId: 42);
        var ourAddress = new SignalProtocolAddress(account.Aci, 1);
        new SessionBuilder(senderStore, senderStore, senderStore, senderStore, senderStore, ourAddress).Process(
            new PreKeyBundle(account.AciRegistrationId, 1, null, null, signed.Id, signed.KeyPair.PublicKey,
                signed.Signature, aciIdentity.PublicKey, kyber.Id, kyber.KeyPair.PublicKey, kyber.Signature));
        var senderCipher = new SessionCipher(senderStore, senderStore, senderStore, senderStore, senderStore, ourAddress);

        // An image attachment with NO text body — previously dropped entirely.
        var content = new Content
        {
            DataMessage = new DataMessage
            {
                Timestamp = 1700000000000UL,
                Attachments = { new AttachmentPointer { ContentType = "image/jpeg", Size = 1234 } },
            },
        };
        ICiphertextMessage ciphertext = senderCipher.Encrypt(Pad(content.ToByteArray()));

        DecryptedMessage? result = decryptor.Decrypt(new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = "11111111-1111-1111-1111-111111111111",
            SourceDeviceId = 1,
            Content = ByteString.CopyFrom(ciphertext.Serialize()),
            ServerTimestamp = 1700000000001UL,
        });

        Assert.NotNull(result);
        Assert.Equal("📷 Photo", result!.Body);          // appears instead of vanishing
        Assert.NotNull(result.Attachment);               // pointer surfaced for the downloader
        Assert.Equal("image/jpeg", result.Attachment!.ContentType);
    }

    private static SignalAccount BuildAccount(out IdentityKeyPair aciIdentity,
        out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber)
    {
        aciIdentity = IdentityKeyPair.Generate();
        IdentityKeyPair pniIdentity = IdentityKeyPair.Generate();
        signed = PreKeyHelper.GenerateSignedPreKey(aciIdentity.PrivateKey, 1);
        kyber = PreKeyHelper.GenerateKyberPreKey(aciIdentity.PrivateKey, 1);

        return new SignalAccount
        {
            Aci = "00000000-0000-0000-0000-000000000000",
            Pni = "00000000-0000-0000-0000-0000000000ff",
            Number = "+15555550100",
            DeviceId = 2,
            Password = "pw",
            AciRegistrationId = 1234,
            PniRegistrationId = 5678,
            AciIdentityPublic = aciIdentity.PublicKey.Serialize(),
            AciIdentityPrivate = aciIdentity.PrivateKey,
            PniIdentityPublic = pniIdentity.PublicKey.Serialize(),
            PniIdentityPrivate = pniIdentity.PrivateKey,
            ProfileKey = RandomNumberGenerator.GetBytes(32),
            AciPreKeys = Material(signed, kyber),
            PniPreKeys = Material(signed, kyber),
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

    /// <summary>Signal's PushTransportDetails padding: 0x80 terminator, zero-filled to a 160-byte multiple.</summary>
    private static byte[] Pad(byte[] body)
    {
        int len = body.Length + 1;
        int parts = len / 160 + (len % 160 != 0 ? 1 : 0);
        if (parts == 0) parts = 1;
        var padded = new byte[parts * 160];
        Array.Copy(body, padded, body.Length);
        padded[body.Length] = 0x80;
        return padded;
    }
}
