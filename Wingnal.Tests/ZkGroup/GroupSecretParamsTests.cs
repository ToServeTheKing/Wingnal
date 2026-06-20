using Wingnal.Protocol.ZkGroup;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>GV2 Phase D gate (params + blob crypto): reproduces zkgroup's own
/// <c>test_encrypt_with_padding</c> vectors byte-for-byte. This exercises the full chain — the
/// master-key→GroupSecretParams SHO derivation (group_id then blob_key), the EncryptBlob nonce SHO, and
/// AES-256-GCM-SIV — so a pass also confirms the group-identifier derivation used to route group messages.</summary>
public class GroupSecretParamsTests
{
    private static byte[] Plaintext => "secret team"u8.ToArray();

    [Fact]
    public void EncryptBlobWithPadding_Pad0_MatchesZkgroupVector()
    {
        var gsp = GroupSecretParams.Generate(new byte[32]);
        byte[] ct = gsp.EncryptBlobWithPadding(new byte[32], Plaintext, 0);
        Assert.Equal(
            "3798afe9c65ffb35a63b2c048b16f19dd50ee9acc33cc925667a9abad4d4c6f86675fa8e32243e0831203700",
            Convert.ToHexString(ct).ToLowerInvariant());
        Assert.Equal(Plaintext, gsp.DecryptBlobWithPadding(ct));
    }

    [Fact]
    public void EncryptBlobWithPadding_Pad8_MatchesZkgroupVector()
    {
        var gsp = GroupSecretParams.Generate(new byte[32]);
        byte[] ct = gsp.EncryptBlobWithPadding(new byte[32], Plaintext, 8);
        Assert.Equal(
            "880a70e071b33f81e1219842c8514f34901abb734c191292ac325455d898da000484080099c620f86675fa8e32243e0831203700",
            Convert.ToHexString(ct).ToLowerInvariant());
        Assert.Equal(Plaintext, gsp.DecryptBlobWithPadding(ct));
    }

    [Fact]
    public void GroupIdentifier_IsDeterministicFromMasterKey()
    {
        var a = GroupSecretParams.Generate(new byte[32]);
        var b = GroupSecretParams.DeriveFromMasterKey(a.MasterKey);
        Assert.Equal(a.GroupIdentifier, b.GroupIdentifier);
        Assert.Equal(32, a.GroupIdentifier.Length);
    }

    // TEST_ARRAY_32_1 / TEST_ARRAY_16 from libsignal's integration_tests (test_integration_profile).
    private static byte[] TestArray32_1()
    {
        var b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte)(100 + i);
        return b;
    }

    private static readonly byte[] TestArray16 =
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    [Fact]
    public void EncryptServiceId_RoundTrips_UnderGroupKeys()
    {
        // Mirrors libsignal integration_tests: group derived from TEST_ARRAY_32_1, ACI = TEST_ARRAY_16.
        var gsp = GroupSecretParams.DeriveFromMasterKey(TestArray32_1());

        UuidCiphertext aciCt = gsp.EncryptServiceId(ServiceId.Aci(TestArray16));
        ServiceId back = gsp.DecryptServiceId(aciCt);
        Assert.False(back.IsPni);
        Assert.Equal(TestArray16, back.RawUuid);

        byte[] profileKey = TestArray32_1();
        ProfileKeyCiphertext pkCt = gsp.EncryptProfileKey(profileKey, TestArray16);
        Assert.Equal(profileKey, gsp.DecryptProfileKey(pkCt, TestArray16));

        // Serialized GroupPublicParams is the pinned 97-byte structure (reserved + id + 2 public keys).
        Assert.Equal(97, gsp.PublicParamsSerialized().Length);
    }
}
