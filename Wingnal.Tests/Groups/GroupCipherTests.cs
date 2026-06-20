using System.Text;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// Offline validation of the Sender Key (group) messaging primitive: one sender distributes a sender
/// key to multiple receivers, all of whom decrypt; out-of-order / skipped iterations are handled; and
/// a tampered message (ciphertext or signature) is rejected. Exercises the byte-exact wire format via
/// Serialize/Parse round-trips.
/// </summary>
public class GroupCipherTests
{
    private static readonly SignalProtocolAddress Sender = new("aaaaaaaa-1111-2222-3333-444444444444", 1);
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    private static string Str(byte[] b) => Encoding.UTF8.GetString(b);

    [Fact]
    public void OneSender_DistributesToTwoReceivers_AllDecrypt()
    {
        Guid distId = Guid.NewGuid();

        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
        var senderCipher = new GroupSessionCipher(senderStore);

        // Send three messages over the wire.
        byte[] m0 = senderCipher.Encrypt(Sender, distId, Utf8("hello group")).Serialize();
        byte[] m1 = senderCipher.Encrypt(Sender, distId, Utf8("second")).Serialize();
        byte[] m2 = senderCipher.Encrypt(Sender, distId, Utf8("third")).Serialize();

        foreach (string _ in new[] { "receiver-a", "receiver-b" })
        {
            var store = new InMemorySenderKeyStore();
            // Members receive the SKDM (1:1) and install the receiving state.
            new GroupSessionBuilder(store).Process(Sender, SenderKeyDistributionMessage.Parse(skdm.Serialize()));
            var cipher = new GroupSessionCipher(store);

            Assert.Equal("hello group", Str(cipher.Decrypt(Sender, SenderKeyMessage.Parse(m0))));
            Assert.Equal("second", Str(cipher.Decrypt(Sender, SenderKeyMessage.Parse(m1))));
            Assert.Equal("third", Str(cipher.Decrypt(Sender, SenderKeyMessage.Parse(m2))));
        }
    }

    [Fact]
    public void OutOfOrder_AndSkippedIterations_Decrypt_ThenDuplicateRejected()
    {
        Guid distId = Guid.NewGuid();
        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
        var senderCipher = new GroupSessionCipher(senderStore);

        SenderKeyMessage m0 = senderCipher.Encrypt(Sender, distId, Utf8("zero"));
        SenderKeyMessage m1 = senderCipher.Encrypt(Sender, distId, Utf8("one"));
        SenderKeyMessage m2 = senderCipher.Encrypt(Sender, distId, Utf8("two"));
        SenderKeyMessage m3 = senderCipher.Encrypt(Sender, distId, Utf8("three"));

        var store = new InMemorySenderKeyStore();
        new GroupSessionBuilder(store).Process(Sender, skdm);
        var cipher = new GroupSessionCipher(store);

        // Arrive out of order: 2 (skips 0,1 → cached), then 0, 1 (from cache), then 3 (in order).
        Assert.Equal("two", Str(cipher.Decrypt(Sender, m2)));
        Assert.Equal("zero", Str(cipher.Decrypt(Sender, m0)));
        Assert.Equal("one", Str(cipher.Decrypt(Sender, m1)));
        Assert.Equal("three", Str(cipher.Decrypt(Sender, m3)));

        // Replaying a consumed iteration is a duplicate.
        Assert.Throws<DuplicateMessageException>(() => cipher.Decrypt(Sender, m0));
    }

    [Fact]
    public void TamperedCiphertext_IsRejected()
    {
        Guid distId = Guid.NewGuid();
        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
        byte[] wire = new GroupSessionCipher(senderStore).Encrypt(Sender, distId, Utf8("secret")).Serialize();

        var store = new InMemorySenderKeyStore();
        new GroupSessionBuilder(store).Process(Sender, skdm);
        var cipher = new GroupSessionCipher(store);

        // Flip a byte inside the protobuf/ciphertext region (covered by the signature).
        byte[] tampered = (byte[])wire.Clone();
        tampered[wire.Length - 70] ^= 0x01;
        Assert.Throws<InvalidMessageException>(() => cipher.Decrypt(Sender, SenderKeyMessage.Parse(tampered)));
    }

    [Fact]
    public void TamperedSignature_IsRejected()
    {
        Guid distId = Guid.NewGuid();
        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
        byte[] wire = new GroupSessionCipher(senderStore).Encrypt(Sender, distId, Utf8("secret")).Serialize();

        var store = new InMemorySenderKeyStore();
        new GroupSessionBuilder(store).Process(Sender, skdm);
        var cipher = new GroupSessionCipher(store);

        byte[] tampered = (byte[])wire.Clone();
        tampered[^1] ^= 0x01;   // last byte = end of the 64-byte signature
        Assert.Throws<InvalidMessageException>(() => cipher.Decrypt(Sender, SenderKeyMessage.Parse(tampered)));
    }

    [Fact]
    public void WrongSigner_IsRejected()
    {
        Guid distId = Guid.NewGuid();
        var senderStore = new InMemorySenderKeyStore();
        SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
        SenderKeyMessage genuine = new GroupSessionCipher(senderStore).Encrypt(Sender, distId, Utf8("hi"));

        // A different sender's distribution under the SAME chain id can't validate the genuine message's
        // signature (different signing key).
        var attackerStore = new InMemorySenderKeyStore();
        new GroupSessionBuilder(attackerStore).Process(Sender, new SenderKeyDistributionMessage(
            genuine.MessageVersion, distId, genuine.ChainId, 0,
            new byte[32], Wingnal.Protocol.Curve.Curve25519.GenerateKeyPair().PublicKey));
        var cipher = new GroupSessionCipher(attackerStore);
        Assert.Throws<InvalidMessageException>(() => cipher.Decrypt(Sender, genuine));
    }

    [Fact]
    public void Wire_RoundTrips_AndDistributionUuidIsRfc4122ByteOrder()
    {
        // RFC 4122 / network byte order = the hex digits in order (what libsignal's uuid crate emits).
        var id = Guid.Parse("12345678-9abc-def0-1122-334455667788");
        var skdm = new SenderKeyDistributionMessage(3, id, 0x7fffffff, 7,
            new byte[32], Wingnal.Protocol.Curve.Curve25519.GenerateKeyPair().PublicKey);

        SenderKeyDistributionMessage parsed = SenderKeyDistributionMessage.Parse(skdm.Serialize());
        Assert.Equal(id, parsed.DistributionId);
        Assert.Equal(0x7fffffffu, parsed.ChainId);
        Assert.Equal(7u, parsed.Iteration);

        // Field 1 must contain the 16 bytes in RFC 4122 order: 12 34 56 78 9a bc de f0 11 22 33 44 55 66 77 88.
        byte[] expected =
        {
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        };
        // serialized = [version][tag 0x0a][len 0x10][16 bytes]...
        Assert.Equal(expected, skdm.Serialize().AsSpan(3, 16).ToArray());
    }
}
