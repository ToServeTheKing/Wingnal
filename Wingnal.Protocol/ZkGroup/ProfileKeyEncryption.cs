using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>
/// zkgroup's profile-key attribute (<c>ProfileKeyStruct</c>): M3 = single-Elligator hash of (profileKey‖uid),
/// M4 = single-Elligator encoding of the (bit-masked) 32-byte profile key. Verifiably-encrypted into a
/// <see cref="ProfileKeyCiphertext"/>; decryption recovers the profile key by inverting Elligator on M4 and
/// checking each candidate against M3.
/// </summary>
public readonly struct ProfileKeyStruct
{
    public readonly Ristretto255 M3;
    public readonly Ristretto255 M4;
    public readonly byte[] ProfileKey;   // 32 bytes (the original, un-masked)

    private ProfileKeyStruct(Ristretto255 m3, Ristretto255 m4, byte[] profileKey)
    {
        M3 = m3; M4 = m4; ProfileKey = profileKey;
    }

    public static ProfileKeyStruct New(byte[] profileKey32, byte[] uid16)
    {
        if (profileKey32.Length != 32 || uid16.Length != 16) throw new ArgumentException("bad sizes");
        var encoded = (byte[])profileKey32.Clone();
        encoded[0] &= 254;
        encoded[31] &= 63;
        Ristretto255 m3 = CalcM3(profileKey32, uid16);
        Ristretto255 m4 = Ristretto255.FromSingleElligatorBytes(encoded);
        return new ProfileKeyStruct(m3, m4, profileKey32);
    }

    internal static Ristretto255 CalcM3(byte[] profileKey32, byte[] uid16)
    {
        var sho = new ShoHmacSha256(
            Encoding.ASCII.GetBytes("Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3"));
        var combined = new byte[48];
        Array.Copy(profileKey32, 0, combined, 0, 32);
        Array.Copy(uid16, 0, combined, 32, 16);
        sho.AbsorbAndRatchet(combined);
        return Ristretto255.FromSingleElligatorBytes(sho.SqueezeAndRatchet(32));
    }

    public Ristretto255[] AsPoints() => new[] { M3, M4 };
}

/// <summary>The profile-key verifiable-encryption domain (analogous to <see cref="UidEncryption"/>).</summary>
public static class ProfileKeyEncryption
{
    public const string DomainId = "Signal_ZKGroup_20231011_ProfileKeyEncryption";

    public static readonly (Ristretto255 Gb1, Ristretto255 Gb2) SystemParams = GenerateSystemParams();

    private static (Ristretto255, Ristretto255) GenerateSystemParams()
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes(
            "Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate"));
        sho.AbsorbAndRatchet(Array.Empty<byte>());
        Ristretto255 gb1 = Ristretto255.FromUniformBytes(sho.SqueezeAndRatchet(64));
        Ristretto255 gb2 = Ristretto255.FromUniformBytes(sho.SqueezeAndRatchet(64));
        return (gb1, gb2);
    }

    public static readonly byte[] SystemHardcoded =
    {
        0xf6, 0xba, 0xa3, 0x17, 0xce, 0x18, 0x39, 0xc9, 0x3d, 0x61, 0x7e, 0x0c, 0xd8, 0x37, 0xd1,
        0x9d, 0xa9, 0xc8, 0xa4, 0xc5, 0x20, 0xbf, 0x7c, 0x51, 0xb1, 0xe6, 0xc2, 0xcb, 0x2a, 0x04,
        0x9c, 0x61, 0x2e, 0x01, 0x75, 0x89, 0x4c, 0x87, 0x30, 0xb2, 0x03, 0xab, 0x3b, 0xd9, 0x8e,
        0xcb, 0x2d, 0x81, 0xab, 0xac, 0xb6, 0x5f, 0x8a, 0x61, 0x24, 0xf4, 0x97, 0x71, 0xd1, 0x4a,
        0x98, 0x52, 0x12, 0x0c,
    };

    public static AttributeKeyPair DeriveKeyPair(ShoHmacSha256 sho) =>
        AttributeKeyPair.DeriveFrom(sho, SystemParams.Gb1, SystemParams.Gb2);

    public static AttributeCiphertext Encrypt(AttributeKeyPair keyPair, ProfileKeyStruct pk) =>
        keyPair.Encrypt(pk.M3, pk.M4);

    /// <summary>Decrypts a profile-key ciphertext back to the 32-byte profile key, given the member's uid.
    /// Port of zkgroup <c>ProfileKeyEncryptionDomain::decrypt</c>.</summary>
    public static byte[] Decrypt(AttributeKeyPair keyPair, AttributeCiphertext ct, byte[] uid16)
    {
        Ristretto255 m4 = keyPair.DecryptToSecondPoint(ct);
        (byte mask, Fe[] fes) = m4.ElligatorInverse();
        Ristretto255 targetM3 = ct.EA1.Multiply(keyPair.A1.Invert());

        byte[]? result = null;
        int found = 0;
        for (int i = 0; i < 8; i++)
        {
            if (((mask >> i) & 1) == 0) continue;
            byte[] candidate = fes[i].Encode();   // 32-byte field-element encoding
            for (int j = 0; j < 8; j++)
            {
                var pk = (byte[])candidate.Clone();
                if (((j >> 2) & 1) == 1) pk[0] |= 0x01;
                if (((j >> 1) & 1) == 1) pk[31] |= 0x80;
                if ((j & 1) == 1) pk[31] |= 0x40;
                Ristretto255 m3 = ProfileKeyStruct.CalcM3(pk, uid16);
                if (m3.ConstantTimeEquals(targetM3)) { result = pk; found++; }
            }
        }
        if (found != 1 || result is null) throw new ZkGroupVerificationException("profile key decrypt failed");
        return result;
    }
}
