using System.Text;
using Wingnal.Protocol.ZkGroup;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Protocol.ZkGroup.ZkCredential;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>
/// GV2 Phase D2 (part 2) gate: the zkcredential MAC + issuance/presentation system. Reproduces poksho's
/// ShoSha256 vector and the credential SystemParams hardcoded serialization byte-for-byte, then the full
/// AuthCredentialWithPni issue→receive→present→verify flow (libsignal's own zkc.rs test, fixed seeds). Once
/// green, the storage-service auth header (Phase E) can be built.
/// </summary>
public class AuthCredentialTests
{
    [Fact]
    public void ShoSha256_MatchesPokshoVector()
    {
        var sho = new ShoSha256(Encoding.ASCII.GetBytes("asd"));
        sho.AbsorbAndRatchet(Encoding.ASCII.GetBytes("asdasd"));
        byte[] outp = sho.SqueezeAndRatchet(64);
        Assert.Equal(
            "ebe4ef29e18aa54137edd89c23f8bfeac2731c9f675da20e7c67d5ad68d7ee2d" +
            "40a45232b599552d46b520082fb2705971f07b3158b072b63ab0934a05e6af64",
            Convert.ToHexString(outp).ToLowerInvariant());
    }

    [Fact]
    public void CredentialSystemParams_MatchHardcoded()
    {
        const string expected =
            "589c8718e8263a53a78932b6212a46e7fd52de3ad157b5bb277dba494cfd3471" +
            "d4cc5f90685952917b33366efcce0512a1f8d70f974758266cb04fc424346d37" +
            "b20f49cb2a081c94b1771fd8c172ae21785c61ea2c7e31947ce351e7b5ff0702" +
            "8c5329beb87b317ffcd981e440819d91136c988d6d9fbea4a87e55ed24a5993a" +
            "a02f688ab1d3bd19056f94c8a44b8faddfa3c9c79c95ad44311a7bf00e5e862e" +
            "c2c399f0d689dfb8c2dc0d7caba32afcf58cf0d85f78195a0b5ab732f5655954" +
            "92cfd982321d1f9be4b21fe6a0214306023d6a05d0d23f67ddc1c0400e5e0a5e" +
            "92d17595131b7a095e740b884b8c9bb0226a39cfd027c769c4f4677c51f21b24" +
            "da81fb2bd1356a9d0650f6a63fcc90d93bd74a954ba6f75f0e9fca47a6d21734" +
            "bce7b28f06b76ef2c44d20a07026534e586eb8e1038874a93e44de362ce7bc08" +
            "44bffc88e390c62519e281aa6fd53ff9ddd1d9ba303cf70004278ea2ae66ce05" +
            "a2749d29eba56f3efe99e42902825c473dfc3c154c3762d2e76bd103f629d250" +
            "b2d9d5c243a4cf8f3be21a84f153f44e2733a105cf780a20f03d84fe1ebbeb0e";
        Assert.Equal(expected,
            Convert.ToHexString(CredentialSystem.SystemParams.Hardcoded.Serialize()).ToLowerInvariant());
    }

    [Fact]
    public void AuthCredentialWithPni_IssueReceivePresentVerify()
    {
        byte[] Seed(byte b) { var a = new byte[32]; Array.Fill(a, b); return a; }
        var aci = ServiceId.Aci(Repeat((byte)'a', 16));
        var pni = ServiceId.Pni(Repeat((byte)'p', 16));
        const ulong redemption = 12345UL * 86400;

        CredentialKeyPair credentialKey = CredentialKeyPair.Generate(Seed(1));
        var group = GroupSecretParams.Generate(Seed(2));

        IssuanceProof response = AuthCredentialWithPni.Issue(aci, pni, redemption, credentialKey, Seed(3));
        AuthCredentialWithPni credential =
            AuthCredentialWithPni.Receive(response, aci, pni, redemption, credentialKey.Public);

        byte[] presentation = credential.Present(credentialKey.Public, group, Seed(4));

        (UuidCiphertext gotAci, _) = AuthCredentialWithPni.VerifyPresentation(
            presentation, credentialKey, group.UidKeyPair.PublicKey, redemption);

        // The presentation's aci ciphertext should match encrypting the ACI directly under the group key.
        Assert.Equal(group.EncryptServiceId(aci).Serialize(), gotAci.Serialize());
    }

    [Fact]
    public void AuthCredentialResponse_Serialization_RoundTrips()
    {
        var aci = ServiceId.Aci(Repeat((byte)'a', 16));
        var pni = ServiceId.Pni(Repeat((byte)'p', 16));
        const ulong redemption = 12345UL * 86400;

        byte[] Seed(byte b) { var a = new byte[32]; Array.Fill(a, b); return a; }
        CredentialKeyPair credentialKey = CredentialKeyPair.Generate(Seed(1));
        var group = GroupSecretParams.Generate(Seed(2));

        // Server returns the serialized response (version 3 ‖ IssuanceProof); client parses + receives it.
        byte[] response = AuthCredentialWithPni.IssueResponse(aci, pni, redemption, credentialKey, Seed(3));
        Assert.Equal(3, response[0]);

        AuthCredentialWithPni credential =
            AuthCredentialWithPni.ReceiveResponse(response, aci, pni, redemption, credentialKey.Public);

        byte[] presentation = credential.Present(credentialKey.Public, group, Seed(4));
        AuthCredentialWithPni.VerifyPresentation(presentation, credentialKey, group.UidKeyPair.PublicKey, redemption);
    }

    private static byte[] Repeat(byte b, int n) { var a = new byte[n]; Array.Fill(a, b); return a; }
}
