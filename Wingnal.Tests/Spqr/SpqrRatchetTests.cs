using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

/// <summary>
/// End-to-end SPQR ratchet tests (port of SparsePostQuantumRatchet v1.5.1 src/lib.rs `ratchet` test):
/// two parties (A2B/B2A) exchange pq_ratchet messages and must derive identical per-message keys
/// through a full ML-KEM handshake and epoch rollover. Exercises States + Chain + ML-KEM-768 +
/// Authenticator + the wire message format together.
/// </summary>
public class SpqrRatchetTests
{
    private static byte[] AuthKey()
    {
        var k = new byte[32];
        Array.Fill(k, (byte)41);
        return k;
    }

    private static SpqrRatchet Init(Direction dir) => SpqrRatchet.InitialState(new SpqrParams
    {
        Direction = dir,
        Version = SpqrVersion.V1,
        MinVersion = SpqrVersion.V1,
        AuthKey = AuthKey(),
        ChainParams = new ChainParams(),
    });

    [Fact]
    public void FirstMessage_KeysMatch()
    {
        var alex = Init(Direction.A2B);
        var blake = Init(Direction.B2A);

        SpqrRatchet.SendOutput s = alex.Send();
        byte[]? blakeKey = blake.Recv(s.Message);
        Assert.NotNull(s.Key);                 // first message carries a real salt (chain seeded at epoch 0)
        Assert.Equal(s.Key, blakeKey);
    }

    [Fact]
    public void Lockstep_KeysMatch_AcrossEpochRollover()
    {
        var alex = Init(Direction.A2B);
        var blake = Init(Direction.B2A);

        // 120 lockstep rounds is enough for the long pole (ek = 36 chunks) to complete and an epoch to
        // roll over (which exercises Chain.AddEpoch with the ML-KEM shared secret on both sides).
        for (int i = 0; i < 120; i++)
        {
            SpqrRatchet.SendOutput a = alex.Send();
            byte[]? bKey = blake.Recv(a.Message);
            Assert.Equal(a.Key, bKey);

            SpqrRatchet.SendOutput b = blake.Send();
            byte[]? aKey = alex.Recv(b.Message);
            Assert.Equal(b.Key, aKey);
        }
    }

    [Fact]
    public void Serialize_RoundTrips_AndConversationContinues()
    {
        var alex = Init(Direction.A2B);
        var blake = Init(Direction.B2A);

        // Advance partway (mid-handshake, before any epoch rollover).
        for (int i = 0; i < 20; i++)
        {
            SpqrRatchet.SendOutput a = alex.Send();
            Assert.Equal(a.Key, blake.Recv(a.Message));
            SpqrRatchet.SendOutput b = blake.Send();
            Assert.Equal(b.Key, alex.Recv(b.Message));
        }

        // Persist + restore both sides.
        alex = SpqrRatchet.Deserialize(alex.Serialize());
        blake = SpqrRatchet.Deserialize(blake.Serialize());

        // Continue long enough to roll over an epoch — keys must still match after restore.
        for (int i = 0; i < 120; i++)
        {
            SpqrRatchet.SendOutput a = alex.Send();
            Assert.Equal(a.Key, blake.Recv(a.Message));
            SpqrRatchet.SendOutput b = blake.Send();
            Assert.Equal(b.Key, alex.Recv(b.Message));
        }
    }

    [Fact]
    public void Random_KeysMatch()
    {
        var alex = Init(Direction.A2B);
        var blake = Init(Direction.B2A);
        var rng = new Random(12345);

        for (int i = 0; i < 400; i++)
        {
            if (rng.NextDouble() < 0.5)
            {
                SpqrRatchet.SendOutput a = alex.Send();
                if (rng.NextDouble() < 0.7) Assert.Equal(a.Key, blake.Recv(a.Message));
            }
            if (rng.NextDouble() < 0.5)
            {
                SpqrRatchet.SendOutput b = blake.Send();
                if (rng.NextDouble() < 0.7) Assert.Equal(b.Key, alex.Recv(b.Message));
            }
        }
    }
}
