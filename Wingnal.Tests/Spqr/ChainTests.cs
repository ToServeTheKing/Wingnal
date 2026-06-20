using System.Text;
using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

public class ChainTests
{
    private static byte[] Key(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void A2bSendKeys_MatchB2aRecvKeys()
    {
        var a2b = new Chain(Key("1"), Direction.A2B, new ChainParams());
        var b2a = new Chain(Key("1"), Direction.B2A, new ChainParams());

        for (int i = 0; i < 10; i++)
        {
            (uint idx, byte[] sendKey) = a2b.SendKey(0);
            byte[] recvKey = b2a.RecvKey(0, idx);
            Assert.Equal(sendKey, recvKey);
        }
    }

    [Fact]
    public void OutOfOrderRecvKeys_Work()
    {
        var a2b = new Chain(Key("1"), Direction.A2B, new ChainParams());
        var b2a = new Chain(Key("1"), Direction.B2A, new ChainParams());

        var sent = new List<(uint idx, byte[] key)>();
        for (int i = 0; i < 5; i++) sent.Add(a2b.SendKey(0));

        // Receive out of order: 3, 1, 4, 0, 2.
        foreach (int i in new[] { 3, 1, 4, 0, 2 })
            Assert.Equal(sent[i].key, b2a.RecvKey(0, sent[i].idx));
    }

    [Fact]
    public void RequestingSameKeyTwice_Fails()
    {
        var a2b = new Chain(Key("1"), Direction.A2B, new ChainParams());
        var b2a = new Chain(Key("1"), Direction.B2A, new ChainParams());

        (uint idx, _) = a2b.SendKey(0);
        b2a.RecvKey(0, idx);
        Assert.Throws<SpqrException>(() => b2a.RecvKey(0, idx));
    }

    [Fact]
    public void AddEpoch_KeepsDirectionsInSync()
    {
        var a2b = new Chain(Key("seed"), Direction.A2B, new ChainParams());
        var b2a = new Chain(Key("seed"), Direction.B2A, new ChainParams());

        var secret = new EpochSecret(1, Key("epoch-1-secret-material!"));
        a2b.AddEpoch(secret);
        b2a.AddEpoch(secret);

        (uint idx, byte[] sendKey) = a2b.SendKey(1);
        Assert.Equal(sendKey, b2a.RecvKey(1, idx));
    }
}
