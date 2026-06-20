using Wingnal.Protocol.Identity;
using Wingnal.Protocol.State;
using Xunit;

namespace Wingnal.Tests.Identity;

/// <summary>
/// Validates the safety-number computation byte-exact against libsignal v0.96.1's own fingerprint test
/// vector (rust/protocol/src/fingerprint.rs, version 1, 5200 iterations). Matching this guarantees the
/// number Wingnal shows is the same one the official Signal app shows for the same keys.
/// </summary>
public class SafetyNumberTests
{
    private static readonly byte[] AliceIdentity =
        Convert.FromHexString("0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868");
    private static readonly byte[] BobIdentity =
        Convert.FromHexString("05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b");
    private const string AliceStableId = "+14152222222";
    private const string BobStableId = "+14153333333";
    private const string Expected = "300354477692869396892869876765458257569162576843440918079131";

    [Fact]
    public void MatchesLibsignalVector()
    {
        var alice = IdentityKey.Decode(AliceIdentity);
        var bob = IdentityKey.Decode(BobIdentity);

        string number = SafetyNumber.Generate(
            System.Text.Encoding.ASCII.GetBytes(AliceStableId), alice,
            System.Text.Encoding.ASCII.GetBytes(BobStableId), bob);

        Assert.Equal(Expected, number);
        Assert.Equal(60, number.Length);
    }

    [Fact]
    public void IsSymmetric_BothSidesComputeSameNumber()
    {
        var alice = IdentityKey.Decode(AliceIdentity);
        var bob = IdentityKey.Decode(BobIdentity);
        byte[] aId = System.Text.Encoding.ASCII.GetBytes(AliceStableId);
        byte[] bId = System.Text.Encoding.ASCII.GetBytes(BobStableId);

        // Alice's view (local=alice, remote=bob) must equal Bob's view (local=bob, remote=alice).
        string fromAlice = SafetyNumber.Generate(aId, alice, bId, bob);
        string fromBob = SafetyNumber.Generate(bId, bob, aId, alice);

        Assert.Equal(fromAlice, fromBob);
    }

    [Fact]
    public void DifferentKey_ProducesDifferentNumber()
    {
        var alice = IdentityKey.Decode(AliceIdentity);
        var bob = IdentityKey.Decode(BobIdentity);
        byte[] aId = System.Text.Encoding.ASCII.GetBytes(AliceStableId);
        byte[] bId = System.Text.Encoding.ASCII.GetBytes(BobStableId);

        string baseline = SafetyNumber.Generate(aId, alice, bId, bob);
        // A MITM swaps Bob's key — the safety number must change so the user notices.
        var mallory = IdentityKeyPair.Generate().PublicKey;
        string swapped = SafetyNumber.Generate(aId, alice, bId, mallory);

        Assert.NotEqual(baseline, swapped);
    }
}
