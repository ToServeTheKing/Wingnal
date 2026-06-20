using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

/// <summary>
/// FIPS-203 ML-KEM-768 known-answer tests. Vector from C2SP/CCTV ML-KEM/intermediate/ML-KEM-768.txt.
/// The interop-critical operations — Encaps_internal(ek,m) and Decaps(dk,c), including A-matrix gen,
/// CBD sampling, NTT, d_u=10/d_v=4 compression, G/H/J hashing — are byte-identical between FIPS-203
/// IPD (this vector) and final FIPS-203, so loading the vector's ek/dk validates byte-exact interop
/// with the libcrux ML-KEM-768 the Signal phone uses. (Keygen's seed→keypair mapping differs by the
/// final-standard domain-separation byte, but that mapping is purely local and never crosses the wire,
/// so we keep the final-FIPS-203 rank byte and validate keygen by self-consistency instead.)
/// </summary>
public class MlKem768Tests
{
    private const string D = "f688563f7c66a5da2d8bdb5a5f3e07bd8dce6f7efcec7f41298d79863459f7cd";
    private const string Z = "d1d49a515250dbceb9f6e3fcc1c7d5306918964b21ddb22207e03e57f0600da8";
    private const string M = "3dc27ca0a6594b0e56320457c45a0f76bb8a213ea4a76d442186a0aefadbcdb9";
    private const string KExpected = "4b4eba37eff0315dc6009dcffb4dfbbb680f8f2ebde8715fa3d6daf70256a2d9";
    private const string Sha256Ct = "20aa4482448f118835dd9e35f73d49018b3b5eaec6bd7878aaef2941824b666d";

    private static string Sha256Hex(byte[] data) => TestHex.Encode(SHA256.HashData(data));

    private static byte[] Sha3_256(byte[] data)
    {
        var d = new Sha3Digest(256);
        d.BlockUpdate(data, 0, data.Length);
        var o = new byte[32];
        d.DoFinal(o, 0);
        return o;
    }

    [Fact]
    public void Encaps_MatchesKat()
    {
        byte[] ek = TestHex.Decode(MlKem768IpdVector.Ek);
        MlKem768.Encaps(ek, TestHex.Decode(M), out byte[] ct, out byte[] ss);
        Assert.Equal(1088, ct.Length);
        Assert.Equal(Sha256Ct, Sha256Hex(ct));
        Assert.Equal(KExpected, TestHex.Encode(ss));
    }

    [Fact]
    public void Decaps_RecoversKat()
    {
        byte[] dk = TestHex.Decode(MlKem768IpdVector.Dk);
        byte[] c = TestHex.Decode(MlKem768IpdVector.C);
        byte[] ss = MlKem768.Decaps(dk, c[..960], c[960..]);
        Assert.Equal(KExpected, TestHex.Encode(ss));
    }

    [Fact]
    public void Incremental_MatchesKat()
    {
        // Build the incremental header (rho || H(ek)) + pk2 from the vector's encapsulation key, then
        // verify encaps1/encaps2 reproduce the standard ciphertext c = ct1||ct2 and shared secret K.
        byte[] ek = TestHex.Decode(MlKem768IpdVector.Ek);
        var header = new byte[64];
        Array.Copy(ek, 1152, header, 0, 32);          // rho
        Array.Copy(Sha3_256(ek), 0, header, 32, 32);  // H(ek)
        byte[] pk2 = ek[..1152];

        Assert.True(MlKem768.EkMatchesHeader(pk2, header));

        MlKem768.Encaps1(header, TestHex.Decode(M), out byte[] ct1, out byte[] es, out byte[] ss);
        byte[] ct2 = MlKem768.Encaps2(pk2, es);
        Assert.Equal(960, ct1.Length);
        Assert.Equal(128, ct2.Length);

        var full = new byte[1088];
        Array.Copy(ct1, 0, full, 0, 960);
        Array.Copy(ct2, 0, full, 960, 128);
        Assert.Equal(Sha256Ct, Sha256Hex(full));
        Assert.Equal(KExpected, TestHex.Encode(ss));

        byte[] dk = TestHex.Decode(MlKem768IpdVector.Dk);
        Assert.Equal(KExpected, TestHex.Encode(MlKem768.DecapsIncremental(dk, ct1, ct2)));
    }

    [Fact]
    public void KeyGen_SelfConsistent()
    {
        // Keygen uses the final-FIPS-203 rank byte (local-only), so we validate structure + round-trip
        // rather than against the IPD vector's ek/dk hashes.
        MlKem768.KeyGen(TestHex.Decode(D), TestHex.Decode(Z), out byte[] ek, out byte[] dk);
        Assert.Equal(1184, ek.Length);
        Assert.Equal(2400, dk.Length);
        // dk layout = dkPke(1152) || ek(1184) || H(ek)(32) || z(32)
        Assert.Equal(TestHex.Encode(ek), TestHex.Encode(dk[1152..2336]));
        Assert.Equal(TestHex.Encode(Sha3_256(ek)), TestHex.Encode(dk[2336..2368]));
        Assert.Equal(Z, TestHex.Encode(dk[2368..2400]));

        MlKem768.Encaps(ek, TestHex.Decode(M), out byte[] ct, out byte[] ss);
        byte[] back = MlKem768.Decaps(dk, ct[..960], ct[960..]);
        Assert.Equal(ss, back);
    }

    [Fact]
    public void Incremental_RandomRoundTrip()
    {
        var rng = RandomNumberGenerator.Create();
        var d = new byte[32]; var z = new byte[32]; var m = new byte[32];
        rng.GetBytes(d); rng.GetBytes(z); rng.GetBytes(m);

        MlKem768.Keys keys = MlKem768.Generate(d, z);
        Assert.True(MlKem768.EkMatchesHeader(keys.Ek, keys.Header));
        MlKem768.Encaps1(keys.Header, m, out byte[] ct1, out byte[] es, out byte[] ss1);
        byte[] ct2 = MlKem768.Encaps2(keys.Ek, es);
        byte[] ss2 = MlKem768.DecapsIncremental(keys.Dk, ct1, ct2);
        Assert.Equal(ss1, ss2);
    }
}
