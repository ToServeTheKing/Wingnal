using System.Text;
using Wingnal.Protocol.ZkGroup;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Protocol.ZkGroup.ZkCredential;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>
/// GV2 Phase D2 gate: the verifiable-encryption layer (zkcredential attributes + zkgroup uid/profile-key
/// encryption) must reproduce libsignal's own ciphertext test vectors byte-for-byte, the hardcoded
/// SystemParams must match the SHO-derived generators, and decryption must round-trip back to ACI/PNI and
/// the profile key. Once green, group rosters can be decrypted (Phase E).
/// </summary>
public class AttributeEncryptionTests
{
    private static readonly byte[] TestArray16 =
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    private static readonly byte[] TestArray16_1 =
        { 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115 };
    private static readonly byte[] TestArray32 = MakeRange(0);
    private static readonly byte[] TestArray32_1 = MakeRange(100);
    private static readonly byte[] TestArray32_2 = MakeRange(200);

    private static byte[] MakeRange(int start)
    {
        var b = new byte[32];
        for (int i = 0; i < 32; i++) b[i] = (byte)(start + i);
        return b;
    }

    [Fact]
    public void SystemParams_MatchHardcoded()
    {
        Assert.Equal(UidEncryption.SystemHardcoded, Concat(
            UidEncryption.SystemParams.Ga1.Encode(), UidEncryption.SystemParams.Ga2.Encode()));
        Assert.Equal(ProfileKeyEncryption.SystemHardcoded, Concat(
            ProfileKeyEncryption.SystemParams.Gb1.Encode(), ProfileKeyEncryption.SystemParams.Gb2.Encode()));
    }

    [Fact]
    public void UidEncryption_MatchesVector_AndRoundTrips()
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Test_Uid_Encryption"));
        sho.AbsorbAndRatchet(TestArray32);
        AttributeKeyPair keyPair = UidEncryption.DeriveKeyPair(sho);

        var aci = ServiceId.Aci(TestArray16);
        UidStruct uid = UidStruct.FromServiceId(aci);
        AttributeCiphertext ct = UidEncryption.Encrypt(keyPair, uid);

        const string expected =
            "f89ee7705a66036b908db884211b773ac543ee35c4a3086220fc3e1e35b4234c" +
            "fa1d2eea2cc2f4b4c42cff39a9dceb57293b5f8770ca60f9e9b74447bfd3bd3d";
        Assert.Equal(expected, Convert.ToHexString(ct.Serialize()).ToLowerInvariant());

        ServiceId back = UidEncryption.Decrypt(keyPair, ct);
        Assert.False(back.IsPni);
        Assert.Equal(TestArray16, back.RawUuid);
    }

    [Fact]
    public void PniEncryption_RoundTrips()
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Test_Pni_Encryption"));
        sho.AbsorbAndRatchet(Array.Empty<byte>());
        AttributeKeyPair keyPair = UidEncryption.DeriveKeyPair(sho);

        var pni = ServiceId.Pni(TestArray16);
        AttributeCiphertext ct = UidEncryption.Encrypt(keyPair, UidStruct.FromServiceId(pni));

        ServiceId back = UidEncryption.Decrypt(keyPair, ct);
        Assert.True(back.IsPni);
        Assert.Equal(TestArray16, back.RawUuid);
    }

    [Fact]
    public void ProfileKeyEncryption_MatchesVector_AndRoundTrips()
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Test_Profile_Key_Encryption"));
        sho.AbsorbAndRatchet(TestArray32_1);
        AttributeKeyPair keyPair = ProfileKeyEncryption.DeriveKeyPair(sho);

        ProfileKeyStruct pk = ProfileKeyStruct.New(TestArray32_1, TestArray16_1);
        AttributeCiphertext ct = ProfileKeyEncryption.Encrypt(keyPair, pk);

        const string expected =
            "5618cb4c7d721e012b22f077ef1264f6b143bb597a1d665a70aa84245f246d20" +
            "badb97474a56f4b5361aeca9d118b7004e140971990aab2af2432d3f8f7d213a";
        Assert.Equal(expected, Convert.ToHexString(ct.Serialize()).ToLowerInvariant());

        byte[] back = ProfileKeyEncryption.Decrypt(keyPair, ct, TestArray16_1);
        Assert.Equal(TestArray32_1, back);

        // additional round-trips with the other fixed test arrays
        foreach (byte[] profileKey in new[] { TestArray32, TestArray32_1, TestArray32_2 })
        {
            ProfileKeyStruct s = ProfileKeyStruct.New(profileKey, TestArray16);
            AttributeCiphertext c = ProfileKeyEncryption.Encrypt(keyPair, s);
            Assert.Equal(profileKey, ProfileKeyEncryption.Decrypt(keyPair, c, TestArray16));
        }
    }

    [Fact]
    public void UuidCiphertext_RoundTripsSerialization()
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Test_Uid_Encryption"));
        sho.AbsorbAndRatchet(TestArray32);
        AttributeKeyPair keyPair = UidEncryption.DeriveKeyPair(sho);
        AttributeCiphertext ct = UidEncryption.Encrypt(keyPair, UidStruct.FromServiceId(ServiceId.Aci(TestArray16)));

        var wrapped = new UuidCiphertext(ct);
        byte[] bytes = wrapped.Serialize();
        Assert.Equal(65, bytes.Length);
        Assert.Equal(0, bytes[0]);
        UuidCiphertext parsed = UuidCiphertext.Deserialize(bytes);
        Assert.Equal(bytes, parsed.Serialize());
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Array.Copy(a, r, a.Length);
        Array.Copy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
