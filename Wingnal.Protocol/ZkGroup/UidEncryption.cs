using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>A Signal service id (ACI or PNI) as the 16-byte raw UUID plus its kind, for zkgroup encoding.</summary>
public readonly struct ServiceId
{
    public readonly byte[] RawUuid;   // 16 bytes
    public readonly bool IsPni;

    public ServiceId(byte[] rawUuid16, bool isPni)
    {
        if (rawUuid16.Length != 16) throw new ArgumentException("uuid must be 16 bytes");
        RawUuid = rawUuid16; IsPni = isPni;
    }

    public static ServiceId Aci(byte[] uuid16) => new(uuid16, isPni: false);
    public static ServiceId Pni(byte[] uuid16) => new(uuid16, isPni: true);

    /// <summary>libsignal-core <c>service_id_binary</c>: ACI = 16 raw bytes; PNI = 0x01‖16.</summary>
    public byte[] ServiceIdBinary()
    {
        if (!IsPni) return (byte[])RawUuid.Clone();
        var b = new byte[17];
        b[0] = 0x01;
        Array.Copy(RawUuid, 0, b, 1, 16);
        return b;
    }
}

/// <summary>
/// zkgroup's UID attribute (<c>UidStruct</c>): M1 = hash-to-group of the service-id binary; M2 = the Lizard
/// encoding of the raw 16-byte UUID. The pair is verifiably-encrypted into a <see cref="UuidCiphertext"/>.
/// </summary>
public readonly struct UidStruct
{
    public readonly Ristretto255 M1;
    public readonly Ristretto255 M2;
    public readonly byte[] RawUuid;

    private UidStruct(Ristretto255 m1, Ristretto255 m2, byte[] rawUuid) { M1 = m1; M2 = m2; RawUuid = rawUuid; }

    public static UidStruct FromServiceId(ServiceId sid)
    {
        Ristretto255 m1 = CalcM1(sid);
        Ristretto255 m2 = Lizard.Encode(sid.RawUuid);
        return new UidStruct(m1, m2, sid.RawUuid);
    }

    internal static Ristretto255 CalcM1(ServiceId sid)
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Signal_ZKGroup_20200424_UID_CalcM1"));
        sho.AbsorbAndRatchet(sid.ServiceIdBinary());
        return Ristretto255.FromUniformBytes(sho.SqueezeAndRatchet(64));
    }

    public Ristretto255[] AsPoints() => new[] { M1, M2 };
}

/// <summary>
/// The UID verifiable-encryption domain: a fixed pair of generator points (G_a1, G_a2) derived
/// deterministically via the SHO. <see cref="SystemHardcoded"/> is libsignal's pinned serialization of
/// these two points and gates the derivation byte-for-byte.
/// </summary>
public static class UidEncryption
{
    public const string DomainId = "Signal_ZKGroup_20230419_UidEncryption";

    public static readonly (Ristretto255 Ga1, Ristretto255 Ga2) SystemParams = GenerateSystemParams();

    private static (Ristretto255, Ristretto255) GenerateSystemParams()
    {
        var sho = new ShoHmacSha256(
            Encoding.ASCII.GetBytes("Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate"));
        sho.AbsorbAndRatchet(Array.Empty<byte>());
        Ristretto255 ga1 = Ristretto255.FromUniformBytes(sho.SqueezeAndRatchet(64));
        Ristretto255 ga2 = Ristretto255.FromUniformBytes(sho.SqueezeAndRatchet(64));
        return (ga1, ga2);
    }

    /// <summary>zkgroup's pinned 64-byte serialization of (G_a1, G_a2) — the Phase D2 test gate.</summary>
    public static readonly byte[] SystemHardcoded =
    {
        0xa6, 0x32, 0x4c, 0x36, 0x8d, 0xf7, 0x34, 0x69, 0x11, 0x47, 0x98, 0x13, 0x48, 0xb6, 0xe7,
        0xeb, 0x42, 0xc3, 0x30, 0x7e, 0x71, 0x1b, 0x6c, 0x7e, 0xcc, 0xd3, 0x03, 0x2d, 0x45, 0x69,
        0x3f, 0x5a, 0x04, 0x80, 0x13, 0x52, 0x5b, 0x76, 0x12, 0x4b, 0xf2, 0x64, 0x0c, 0x5e, 0x93,
        0x69, 0xc7, 0x6e, 0xfb, 0xe8, 0x0a, 0xba, 0x2a, 0x24, 0xaa, 0x5d, 0x8e, 0x18, 0xa9, 0x8e,
        0xba, 0x14, 0xf8, 0x37,
    };

    public static AttributeKeyPair DeriveKeyPair(ShoHmacSha256 sho) =>
        AttributeKeyPair.DeriveFrom(sho, SystemParams.Ga1, SystemParams.Ga2);

    public static AttributeCiphertext Encrypt(AttributeKeyPair keyPair, UidStruct uid) =>
        keyPair.Encrypt(uid.M1, uid.M2);

    /// <summary>Decrypts a UID ciphertext back to a service id, trying both ACI and PNI interpretations and
    /// confirming via M1 (zkgroup <c>UidEncryptionDomain::decrypt</c>).</summary>
    public static ServiceId Decrypt(AttributeKeyPair keyPair, AttributeCiphertext ct)
    {
        Ristretto255 m2 = keyPair.DecryptToSecondPoint(ct);
        byte[]? uuid = Lizard.Decode(m2) ?? throw new ZkGroupVerificationException("lizard decode failed");

        var aci = ServiceId.Aci(uuid);
        var pni = ServiceId.Pni(uuid);
        Ristretto255 decryptedM1 = ct.EA1.Multiply(keyPair.A1.Invert());
        if (decryptedM1.ConstantTimeEquals(UidStruct.CalcM1(aci))) return aci;
        if (decryptedM1.ConstantTimeEquals(UidStruct.CalcM1(pni))) return pni;
        throw new ZkGroupVerificationException("uid ciphertext did not match ACI or PNI");
    }
}
