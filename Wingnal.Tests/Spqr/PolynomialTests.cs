using System.Security.Cryptography;
using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

public class PolynomialTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(32)]
    [InlineData(50)]
    [InlineData(1184)] // ML-KEM-768 encapsulation key size
    [InlineData(1088)] // ML-KEM-768 ciphertext size
    public void Encode_ThenDecode_SystematicChunks_RoundTrips(int len)
    {
        byte[] msg = RandomNumberGenerator.GetBytes(len);
        var encoder = new Polynomial.Encoder(msg);
        var decoder = new Polynomial.Decoder(len);

        // Feed sequential chunks (the first ceil(M/16) are the systematic message chunks).
        ushort idx = 0;
        while (decoder.DecodedMessage() is null)
        {
            (ushort i, byte[] data) = encoder.ChunkAt(idx++);
            decoder.AddChunk(i, data);
            if (idx > 200) break; // safety
        }

        Assert.Equal(msg, decoder.DecodedMessage());
    }

    [Fact]
    public void Decode_FromRedundancyChunks_RecoversMessage()
    {
        // Drop early (systematic) chunks and rely on later redundancy chunks — the erasure-code case.
        byte[] msg = RandomNumberGenerator.GetBytes(50); // 25 symbols -> 2 points per poly
        var encoder = new Polynomial.Encoder(msg);
        var decoder = new Polynomial.Decoder(50);

        // 25 symbols across 16 polys => polys 0..8 have 2 points, 9..15 have 1; need 2 distinct chunks.
        // Use redundancy indices 7 and 13 (skip systematic 0 and 1 entirely).
        foreach (ushort idx in new ushort[] { 7, 13 })
        {
            (ushort i, byte[] data) = encoder.ChunkAt(idx);
            decoder.AddChunk(i, data);
        }

        Assert.Equal(msg, decoder.DecodedMessage());
    }
}
