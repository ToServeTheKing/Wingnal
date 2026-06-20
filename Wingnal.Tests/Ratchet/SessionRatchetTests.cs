using System.Text;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.State;
using Xunit;

namespace Wingnal.Tests.Ratchet;

public class SessionRatchetTests
{
    private static readonly SignalProtocolAddress AliceAddress = new("+alice", 1);
    private static readonly SignalProtocolAddress BobAddress = new("+bob", 1);

    private static SessionCipher CipherFor(TestDevice self, SignalProtocolAddress remote) =>
        new(self.Store, self.Store, self.Store, self.Store, self.Store, remote);

    private static SessionBuilder BuilderFor(TestDevice self, SignalProtocolAddress remote) =>
        new(self.Store, self.Store, self.Store, self.Store, self.Store, remote);

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    private static string Str(byte[] b) => Encoding.UTF8.GetString(b);

    /// <summary>Serializes a ciphertext, re-parses it, and routes it to the correct decrypt method.
    /// An initiator keeps emitting <see cref="PreKeySignalMessage"/>s until it decrypts a reply, so
    /// callers cannot assume a plain <see cref="SignalMessage"/>.</summary>
    private static byte[] Deliver(SessionCipher receiver, ICiphertextMessage message) => message switch
    {
        PreKeySignalMessage pre => receiver.DecryptPreKeyMessage(PreKeySignalMessage.Parse(pre.Serialize())),
        SignalMessage sig => receiver.DecryptSignalMessage(SignalMessage.Parse(sig.Serialize())),
        _ => throw new InvalidOperationException($"unexpected message type {message.GetType()}"),
    };

    /// <summary>Establishes a PQXDH session and round-trips it through the serialized wire format.</summary>
    private static (SessionCipher alice, SessionCipher bob) Establish(
        TestDevice alice, TestDevice bob, bool oneTimePreKey = true, bool kyber = true)
    {
        PreKeyBundle bundle = bob.CreateBundle(oneTimePreKey, kyber);
        BuilderFor(alice, BobAddress).Process(bundle);

        SessionCipher aliceCipher = CipherFor(alice, BobAddress);
        SessionCipher bobCipher = CipherFor(bob, AliceAddress);

        // Alice's first message is a PreKeySignalMessage; Bob processes it to complete his side.
        var first = (PreKeySignalMessage)aliceCipher.Encrypt(Utf8("hello bob"));
        byte[] decrypted = bobCipher.DecryptPreKeyMessage(PreKeySignalMessage.Parse(first.Serialize()));
        Assert.Equal("hello bob", Str(decrypted));

        return (aliceCipher, bobCipher);
    }

    [Fact]
    public void FullPqxdhSession_RoundTripsBothDirections()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob);

        for (int i = 0; i < 10; i++)
        {
            string fromBob = $"reply {i}";
            var bobMsg = (SignalMessage)bobCipher.Encrypt(Utf8(fromBob));
            Assert.Equal(fromBob, Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(bobMsg.Serialize()))));

            string fromAlice = $"follow up {i}";
            var aliceMsg = (SignalMessage)aliceCipher.Encrypt(Utf8(fromAlice));
            Assert.Equal(fromAlice, Str(bobCipher.DecryptSignalMessage(SignalMessage.Parse(aliceMsg.Serialize()))));
        }
    }

    [Fact]
    public void ClassicX3dh_WithoutKyber_RoundTrips()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob, oneTimePreKey: true, kyber: false);

        var bobMsg = (SignalMessage)bobCipher.Encrypt(Utf8("classic"));
        Assert.Equal("classic", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(bobMsg.Serialize()))));
    }

    [Fact]
    public void Session_WithoutOneTimePreKey_RoundTrips()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob, oneTimePreKey: false);

        var bobMsg = (SignalMessage)bobCipher.Encrypt(Utf8("no one-time prekey"));
        Assert.Equal("no one-time prekey", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(bobMsg.Serialize()))));
    }

    [Fact]
    public void OutOfOrderDelivery_UsesSkippedMessageKeys()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob);

        // Bob sends three within one chain; Alice receives them out of order.
        var m0 = (SignalMessage)bobCipher.Encrypt(Utf8("m0"));
        var m1 = (SignalMessage)bobCipher.Encrypt(Utf8("m1"));
        var m2 = (SignalMessage)bobCipher.Encrypt(Utf8("m2"));

        Assert.Equal("m2", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(m2.Serialize()))));
        Assert.Equal("m0", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(m0.Serialize()))));
        Assert.Equal("m1", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(m1.Serialize()))));
    }

    [Fact]
    public void InterleavedRatchetSteps_RoundTrip()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob);

        // Each direction switch forces a DH ratchet step. Alice still has a pending prekey, so her
        // messages remain PreKeySignalMessages until she decrypts a reply from Bob.
        ICiphertextMessage a1 = aliceCipher.Encrypt(Utf8("a1"));
        ICiphertextMessage a2 = aliceCipher.Encrypt(Utf8("a2"));
        Assert.Equal("a1", Str(Deliver(bobCipher, a1)));
        ICiphertextMessage b1 = bobCipher.Encrypt(Utf8("b1"));
        Assert.Equal("b1", Str(Deliver(aliceCipher, b1)));
        Assert.Equal("a2", Str(Deliver(bobCipher, a2)));
        ICiphertextMessage a3 = aliceCipher.Encrypt(Utf8("a3"));
        Assert.Equal("a3", Str(Deliver(bobCipher, a3)));
    }

    [Fact]
    public void DuplicateMessage_IsRejected()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob);

        var bobMsg = (SignalMessage)bobCipher.Encrypt(Utf8("once"));
        Assert.Equal("once", Str(aliceCipher.DecryptSignalMessage(SignalMessage.Parse(bobMsg.Serialize()))));
        Assert.Throws<DuplicateMessageException>(
            () => aliceCipher.DecryptSignalMessage(SignalMessage.Parse(bobMsg.Serialize())));
    }

    [Fact]
    public void TamperedCiphertext_FailsMac()
    {
        var alice = new TestDevice();
        var bob = new TestDevice();
        (SessionCipher aliceCipher, SessionCipher bobCipher) = Establish(alice, bob);

        var bobMsg = (SignalMessage)bobCipher.Encrypt(Utf8("authentic"));
        byte[] wire = bobMsg.Serialize();
        wire[5] ^= 0x01;
        Assert.Throws<InvalidMessageException>(
            () => aliceCipher.DecryptSignalMessage(SignalMessage.Parse(wire)));
    }
}
