using Wingnal.Protocol.ZkGroup.Curve;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>
/// GV2 Phase D2 gate: the Lizard 16-byte↔Ristretto encoding (curve25519-dalek-signal fork) must match the
/// fork's own test vectors byte-for-byte (encode), and decode must invert it (recover the original 16
/// bytes) — including for the dalek-pinned compressed points, so decode is validated independently of our
/// own encode. UuidCiphertext/ProfileKeyCiphertext decryption depends on this.
/// </summary>
public class LizardTests
{
    // dalek-signal lizard_ristretto.rs test_lizard_encode: data(16) -> compressed Ristretto(32).
    private static readonly (byte[] data, string point)[] Vectors =
    {
        (new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            "f0b7e34484f74cf00f15024b738539738646bbbe1e9bc7509a676815227e774f"),
        (new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
            "cc92e81f585afc5caac88660d8d17e9025a44489a363042123f6af0702156e65"),
        (new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            "c830573f8a8e7778671f76cdc796dc0a235cf177f197d9fcba06e84e96247444"),
    };

    [Fact]
    public void Encode_MatchesDalekSignalVectors()
    {
        foreach ((byte[] data, string point) in Vectors)
        {
            byte[] got = Lizard.Encode(data).Encode();
            Assert.Equal(point, Convert.ToHexString(got).ToLowerInvariant());
        }
    }

    [Fact]
    public void Decode_RecoversOriginal_FromPinnedPoints()
    {
        // Decode the dalek-pinned compressed points (NOT our own encode output) → validates decode alone.
        foreach ((byte[] data, string point) in Vectors)
        {
            Ristretto255 p = Ristretto255.Decode(Convert.FromHexString(point))!;
            byte[]? decoded = Lizard.Decode(p);
            Assert.NotNull(decoded);
            Assert.Equal(data, decoded);
        }
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var rng = new Random(1234);
        for (int i = 0; i < 50; i++)
        {
            var data = new byte[16];
            rng.NextBytes(data);
            byte[]? back = Lizard.Decode(Lizard.Encode(data));
            Assert.NotNull(back);
            Assert.Equal(data, back);
        }
    }
}
