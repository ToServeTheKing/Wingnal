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
/// Offline validation of the outgoing send path: MessageSender.BuildOutgoingList encrypts a padded
/// DataMessage to a recipient's prekey bundle (as the server would return it, base64 with type
/// prefixes), and the recipient's MessageDecryptor recovers the text. Exercises bundle base64/prefix
/// parsing, PushTransportDetails padding, PQXDH-as-initiator, and SPQR end-to-end.
/// </summary>
public class SendPathTests
{
    [Fact]
    public void BuildOutgoingList_ProducesDecryptableMessage()
    {
        // Recipient ("the phone"): account + protocol store that will decrypt.
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var recipientStore = new AccountProtocolStore(recipient);
        var decryptor = new MessageDecryptor(recipientStore);

        // Sender ("us", a linked device): account + protocol store that will encrypt.
        SignalAccount sender = BuildAccount("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", deviceId: 4,
            out _, out _, out _);
        var senderStore = new AccountProtocolStore(sender);
        var messageSender = new MessageSender(sender, senderStore, rest: null!);

        // The server's GET /v2/keys response for the recipient (one device), base64 with prefixes.
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

        const string text = "Hello from Wingnal";
        OutgoingMessageList list = messageSender.BuildOutgoingList(recipient.Aci, text, bundles, timestamp: 1700000000000);

        Assert.Single(list.Messages);
        OutgoingMessage m = list.Messages[0];
        Assert.Equal(3, m.Type);                 // PREKEY_MESSAGE
        Assert.Equal(1u, m.DestinationDeviceId);

        // Recipient decrypts it through the full pipeline.
        var envelope = new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = sender.Aci,
            SourceDeviceId = (uint)sender.DeviceId,
            Content = ByteString.CopyFrom(Convert.FromBase64String(m.Content)),
            ServerTimestamp = 1700000000001UL,
        };
        DecryptedMessage? result = decryptor.Decrypt(envelope);

        Assert.NotNull(result);
        Assert.Equal(text, result!.Body);
        Assert.False(result.Outgoing);
    }

    [Fact]
    public void SessionRecord_SurvivesSerializeRoundTrip_AndKeepsDecrypting()
    {
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var recipientStore = new AccountProtocolStore(recipient);
        var decryptor = new MessageDecryptor(recipientStore);

        SignalAccount sender = BuildAccount("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", deviceId: 4, out _, out _, out _);
        var senderStore = new AccountProtocolStore(sender);
        var messageSender = new MessageSender(sender, senderStore, rest: null!);

        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
            Devices = new[] { Device(1, recipient.AciRegistrationId, signed, kyber) },
        };
        var senderAddress = new SignalProtocolAddress(sender.Aci, (uint)sender.DeviceId);

        // Message 1 establishes the session on both sides.
        OutgoingMessageList list1 = messageSender.BuildOutgoingList(recipient.Aci, "one", bundles, 1700000000000);
        Assert.Equal("one", Decrypt(decryptor, sender, list1));

        // Simulate an app restart: serialize the recipient's session, then restore it into a fresh store.
        byte[] blob = recipientStore.LoadSession(senderAddress).Serialize();
        var restoredStore = new AccountProtocolStore(recipient);
        restoredStore.StoreSession(senderAddress, SessionRecord.Deserialize(blob));
        var restoredDecryptor = new MessageDecryptor(restoredStore);

        // Message 2 (reused sender session) must decrypt against the restored recipient session.
        OutgoingMessageList? list2 = messageSender.BuildFromExistingSessions(recipient.Aci, "two", 1700000000001);
        Assert.NotNull(list2);
        Assert.Equal("two", Decrypt(restoredDecryptor, sender, list2!));
    }

    [Fact]
    public void SqliteStore_PersistsSessionAcrossInstances()
    {
        string dir = Path.Combine(Path.GetTempPath(), "wingnal-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
                out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
            var store1 = new SqliteSignalProtocolStore(recipient, "protocol.db", onChanged: null, directory: dir);

            SignalAccount sender = BuildAccount("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", deviceId: 4, out _, out _, out _);
            var messageSender = new MessageSender(sender, new AccountProtocolStore(sender), rest: null!);
            var bundles = new PreKeyResponse
            {
                IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
                Devices = new[] { Device(1, recipient.AciRegistrationId, signed, kyber) },
            };
            var senderAddress = new SignalProtocolAddress(sender.Aci, (uint)sender.DeviceId);

            OutgoingMessageList list1 = messageSender.BuildOutgoingList(recipient.Aci, "one", bundles, 1700000000000);
            Assert.Equal("one", Decrypt(new MessageDecryptor(store1), sender, list1));

            // New store instance over the same DB directory = simulated app restart.
            var store2 = new SqliteSignalProtocolStore(recipient, "protocol.db", onChanged: null, directory: dir);
            Assert.True(store2.ContainsSession(senderAddress));
            Assert.Contains((uint)sender.DeviceId, store2.GetSubDeviceSessions(sender.Aci));

            OutgoingMessageList? list2 = messageSender.BuildFromExistingSessions(recipient.Aci, "two", 1700000000001);
            Assert.NotNull(list2);
            Assert.Equal("two", Decrypt(new MessageDecryptor(store2), sender, list2!));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort cleanup */ }
        }
    }

    [Fact]
    public void BidirectionalConversation_RoundTripsThroughOneSharedPerPeerSession()
    {
        // Alice and Bob each have ONE shared protocol store used for BOTH sending and receiving — the
        // same store object handles the initiator session it creates AND the inbound replies on that
        // same peer address, proving the unified per-peer session (no separate send/recv stores, no
        // initiator/responder clobber).
        SignalAccount alice = BuildAccount("aaaaaaaa-1111-2222-3333-444444444444", deviceId: 4,
            out IdentityKeyPair aliceIdentity, out SignedPreKeyRecord aliceSigned, out KyberPreKeyRecord aliceKyber);
        SignalAccount bob = BuildAccount("bbbbbbbb-5555-6666-7777-888888888888", deviceId: 1,
            out IdentityKeyPair bobIdentity, out SignedPreKeyRecord bobSigned, out KyberPreKeyRecord bobKyber);

        var aliceStore = new AccountProtocolStore(alice);
        var bobStore = new AccountProtocolStore(bob);

        var aliceSender = new MessageSender(alice, aliceStore, rest: null!);
        var bobSender = new MessageSender(bob, bobStore, rest: null!);
        var aliceDecryptor = new MessageDecryptor(aliceStore);
        var bobDecryptor = new MessageDecryptor(bobStore);

        var bobBundle = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(bobIdentity.PublicKey.Serialize()),
            Devices = new[] { Device(1, bob.AciRegistrationId, bobSigned, bobKyber) },
        };

        // 1) Alice → Bob (first message establishes the session on both sides).
        OutgoingMessageList a1 = aliceSender.BuildOutgoingList(bob.Aci, "hi bob", bobBundle, 1700000000000);
        Assert.Equal("hi bob", Decrypt(bobDecryptor, alice, a1));

        // 2) Bob → Alice, REUSING the session his store learned from the inbound prekey message
        //    (no prekey fetch — proves the shared store serves the reply direction too).
        OutgoingMessageList? b1 = bobSender.BuildFromExistingSessions(alice.Aci, "hey alice", 1700000000001);
        Assert.NotNull(b1);
        Assert.Equal("hey alice", Decrypt(aliceDecryptor, bob, b1!));

        // 3) Alice → Bob again (now also reusing, after the DH ratchet from Bob's reply).
        OutgoingMessageList? a2 = aliceSender.BuildFromExistingSessions(bob.Aci, "how are you", 1700000000002);
        Assert.NotNull(a2);
        Assert.Equal("how are you", Decrypt(bobDecryptor, alice, a2!));

        // 4) Bob → Alice once more.
        OutgoingMessageList? b2 = bobSender.BuildFromExistingSessions(alice.Aci, "doing great", 1700000000003);
        Assert.NotNull(b2);
        Assert.Equal("doing great", Decrypt(aliceDecryptor, bob, b2!));

        // Each side keeps exactly ONE session for the single peer device (no clobber / duplicate).
        Assert.Equal(new[] { 1u }, aliceStore.GetSubDeviceSessions(bob.Aci));
        Assert.Equal(new[] { 4u }, bobStore.GetSubDeviceSessions(alice.Aci));
    }

    [Fact]
    public void SentTranscript_DecryptsAsOutgoingToTheRealPeer()
    {
        // A second device of ours (the "recipient" of the sync transcript) that will decrypt it.
        SignalAccount ourOtherDevice = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var recipientStore = new AccountProtocolStore(ourOtherDevice);
        var decryptor = new MessageDecryptor(recipientStore);

        // Our sending device.
        SignalAccount sender = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 4, out _, out _, out _);
        var messageSender = new MessageSender(sender, new AccountProtocolStore(sender), rest: null!);

        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
            Devices = new[] { Device(1, ourOtherDevice.AciRegistrationId, signed, kyber) },
        };

        // Build the Sent transcript for a message we sent to "Bob" and encrypt it to our own account.
        const string bob = "bbbbbbbb-1111-2222-3333-444444444444";
        var dm = new DataMessage { Body = "hi bob", Timestamp = 1700000000000UL };
        Content transcript = MessageSender.BuildSentTranscript(bob, dm, 1700000000000);
        OutgoingMessageList list = messageSender.BuildOutgoingList(ourOtherDevice.Aci, Pad(transcript.ToByteArray()), bundles, 1700000000000);

        var envelope = new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = sender.Aci,
            SourceDeviceId = (uint)sender.DeviceId,
            Content = ByteString.CopyFrom(Convert.FromBase64String(list.Messages[0].Content)),
            ServerTimestamp = 1700000000001UL,
        };
        DecryptedMessage? result = decryptor.Decrypt(envelope);

        Assert.NotNull(result);
        Assert.True(result!.Outgoing);                 // shows as a message WE sent
        Assert.Equal(bob, result.PeerServiceId);       // routed to Bob's thread, not our own
        Assert.Equal("hi bob", result.Body);
    }

    // Signal PushTransportDetails padding (0x80 terminator, zero-filled to a 160-byte multiple).
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

    private static string Decrypt(MessageDecryptor decryptor, SignalAccount sender, OutgoingMessageList list)
    {
        var env = new Envelope
        {
            Type = list.Messages[0].Type == 3 ? Envelope.Types.Type.PrekeyMessage : Envelope.Types.Type.DoubleRatchet,
            SourceServiceId = sender.Aci,
            SourceDeviceId = (uint)sender.DeviceId,
            Content = ByteString.CopyFrom(Convert.FromBase64String(list.Messages[0].Content)),
            ServerTimestamp = 1UL,
        };
        return decryptor.Decrypt(env)!.Body;
    }

    [Fact]
    public void OneTimePreKey_IsUsedAndConsumed()
    {
        // Recipient with one one-time prekey registered.
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        PreKeyRecord otpk = PreKeyHelper.GenerateOneTimePreKeys(startId: 100, count: 1)[0];
        recipient.AciOneTimePreKeys.Add(new OneTimePreKey
        {
            Id = otpk.Id,
            Public = otpk.KeyPair.PublicKey,
            Private = otpk.KeyPair.PrivateKey,
        });

        bool persisted = false;
        var recipientStore = new AccountProtocolStore(recipient, onChanged: () => persisted = true);
        var decryptor = new MessageDecryptor(recipientStore);

        SignalAccount sender = BuildAccount("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", deviceId: 4, out _, out _, out _);
        var messageSender = new MessageSender(sender, new AccountProtocolStore(sender), rest: null!);

        // Bundle advertises the one-time prekey, so the sender includes DH4 and sets preKeyId.
        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
            Devices = new[]
            {
                new PreKeyResponseDevice
                {
                    DeviceId = 1,
                    RegistrationId = recipient.AciRegistrationId,
                    PreKey = new PreKeyDto
                    {
                        KeyId = otpk.Id,
                        PublicKey = Convert.ToBase64String(Curve25519.EncodePoint(otpk.KeyPair.PublicKey)),
                    },
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

        OutgoingMessageList list = messageSender.BuildOutgoingList(recipient.Aci, "hi via otpk", bundles, 1700000000000);

        var envelope = new Envelope
        {
            Type = Envelope.Types.Type.PrekeyMessage,
            SourceServiceId = sender.Aci,
            SourceDeviceId = (uint)sender.DeviceId,
            Content = ByteString.CopyFrom(Convert.FromBase64String(list.Messages[0].Content)),
            ServerTimestamp = 1700000000001UL,
        };
        DecryptedMessage? result = decryptor.Decrypt(envelope);

        Assert.NotNull(result);
        Assert.Equal("hi via otpk", result!.Body);
        Assert.True(persisted, "consuming the one-time prekey should trigger persistence");
        Assert.Empty(recipient.AciOneTimePreKeys);   // the used prekey was removed
    }

    [Fact]
    public void ExistingSession_IsReusedWithoutFetch_AndStillDecrypts()
    {
        SignalAccount recipient = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 1,
            out IdentityKeyPair recipientIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var recipientStore = new AccountProtocolStore(recipient);
        var decryptor = new MessageDecryptor(recipientStore);

        SignalAccount sender = BuildAccount("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", deviceId: 4, out _, out _, out _);
        var senderStore = new AccountProtocolStore(sender);
        var messageSender = new MessageSender(sender, senderStore, rest: null!);

        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(recipientIdentity.PublicKey.Serialize()),
            Devices = new[] { Device(1, recipient.AciRegistrationId, signed, kyber) },
        };

        // First send: establishes the session (fetch path).
        OutgoingMessageList first = messageSender.BuildOutgoingList(recipient.Aci, "first", bundles, 1700000000000);
        Assert.Single(first.Messages);
        Assert.Equal("first", decryptText(first));

        // The sender now has a session for device 1 — no fetch needed for the next send.
        Assert.Contains(1u, senderStore.GetSubDeviceSessions(recipient.Aci));

        // Second send: reuse path (no bundles).
        OutgoingMessageList? reuse = messageSender.BuildFromExistingSessions(recipient.Aci, "second", 1700000000001);
        Assert.NotNull(reuse);
        Assert.Single(reuse!.Messages);
        Assert.Equal("second", decryptText(reuse));

        string decryptText(OutgoingMessageList list)
        {
            var env = new Envelope
            {
                Type = list.Messages[0].Type == 3 ? Envelope.Types.Type.PrekeyMessage : Envelope.Types.Type.DoubleRatchet,
                SourceServiceId = sender.Aci,
                SourceDeviceId = (uint)sender.DeviceId,
                Content = ByteString.CopyFrom(Convert.FromBase64String(list.Messages[0].Content)),
                ServerTimestamp = 1UL,
            };
            return decryptor.Decrypt(env)!.Body;
        }
    }

    [Fact]
    public void BuildOutgoingList_SkipsOwnDeviceForNoteToSelf()
    {
        SignalAccount me = BuildAccount("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", deviceId: 4,
            out IdentityKeyPair myIdentity, out SignedPreKeyRecord signed, out KyberPreKeyRecord kyber);
        var store = new AccountProtocolStore(me);
        var sender = new MessageSender(me, store, rest: null!);

        // Note to Self: bundle lists our own device 4 (skip) + device 1 (the phone, target).
        var bundles = new PreKeyResponse
        {
            IdentityKey = Convert.ToBase64String(myIdentity.PublicKey.Serialize()),
            Devices = new[]
            {
                Device(4, me.AciRegistrationId, signed, kyber),
                Device(1, 999, signed, kyber),
            },
        };

        OutgoingMessageList list = sender.BuildOutgoingList(me.Aci, "note", bundles, 1700000000000);
        Assert.Single(list.Messages);
        Assert.Equal(1u, list.Messages[0].DestinationDeviceId);   // device 4 (ourself) skipped
    }

    private static PreKeyResponseDevice Device(uint id, uint reg, SignedPreKeyRecord signed, KyberPreKeyRecord kyber) => new()
    {
        DeviceId = id,
        RegistrationId = reg,
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
    };

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
