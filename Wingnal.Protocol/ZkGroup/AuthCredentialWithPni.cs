using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>
/// Port of zkgroup's <c>AuthCredentialWithPniZkc</c> — the authentication credential a client receives from
/// the chat server and presents (anonymously) to the storage service to act on a group. The presentation
/// proves possession of a valid credential over (aci, pni, redemptionTime) while only revealing the aci/pni
/// encrypted under the group's UID key. Built on the generic zkcredential issuance/presentation system.
/// </summary>
public sealed class AuthCredentialWithPni
{
    public const int PresentationVersion4 = 3;
    private static readonly byte[] Label = Encoding.ASCII.GetBytes("20240222_Signal_AuthCredentialZkc");

    public Credential Credential { get; }
    public UidStruct Aci { get; }
    public UidStruct Pni { get; }
    public ulong RedemptionTime { get; }

    private AuthCredentialWithPni(Credential credential, UidStruct aci, UidStruct pni, ulong redemptionTime)
    {
        Credential = credential; Aci = aci; Pni = pni; RedemptionTime = redemptionTime;
    }

    private const byte VersionZkc = 3;   // AuthCredentialWithPniVersion::Zkc

    // ── server side (offline tests): issue ──

    public static IssuanceProof Issue(ServiceId aci, ServiceId pni, ulong redemptionTime,
        CredentialKeyPair credentialKey, byte[] randomness)
    {
        return new IssuanceProofBuilder(Label)
            .AddAttribute(UidStruct.FromServiceId(aci).AsPoints())
            .AddAttribute(UidStruct.FromServiceId(pni).AsPoints())
            .AddPublicAttributeU64(redemptionTime)
            .Issue(credentialKey, randomness);
    }

    /// <summary>The serialized AuthCredentialWithPniResponse the chat server returns: version(3) ‖ IssuanceProof.</summary>
    public static byte[] IssueResponse(ServiceId aci, ServiceId pni, ulong redemptionTime,
        CredentialKeyPair credentialKey, byte[] randomness)
    {
        var b = new List<byte> { VersionZkc };
        b.AddRange(Issue(aci, pni, redemptionTime, credentialKey, randomness).Serialize());
        return b.ToArray();
    }

    // ── client side: receive a credential ──

    /// <summary>Receives the chat server's serialized AuthCredentialWithPniResponse using Signal's published
    /// credential public key (<see cref="ServerPublicParams.Production"/>).</summary>
    public static AuthCredentialWithPni ReceiveResponse(byte[] responseBytes, ServiceId aci, ServiceId pni,
        ulong redemptionTime, CredentialPublicKey? credentialPublicKey = null)
    {
        if (responseBytes.Length < 1 || responseBytes[0] != VersionZkc)
            throw new ZkGroupVerificationException("bad AuthCredentialWithPniResponse version");
        IssuanceProof proof = IssuanceProof.Deserialize(responseBytes.AsSpan(1));
        return Receive(proof, aci, pni, redemptionTime,
            credentialPublicKey ?? ServerPublicParams.Production.GenericCredentialPublicKey);
    }

    public static AuthCredentialWithPni Receive(IssuanceProof proof, ServiceId aci, ServiceId pni,
        ulong redemptionTime, CredentialPublicKey credentialPublicKey)
    {
        if (redemptionTime % 86400 != 0)
            throw new ZkGroupVerificationException("redemption time not day-aligned");
        UidStruct aciStruct = UidStruct.FromServiceId(aci);
        UidStruct pniStruct = UidStruct.FromServiceId(pni);
        Credential credential = new IssuanceProofBuilder(Label)
            .AddAttribute(aciStruct.AsPoints())
            .AddAttribute(pniStruct.AsPoints())
            .AddPublicAttributeU64(redemptionTime)
            .Verify(credentialPublicKey, proof);
        return new AuthCredentialWithPni(credential, aciStruct, pniStruct, redemptionTime);
    }

    // ── client side: build the presentation for a group ──

    public byte[] Present(CredentialPublicKey credentialPublicKey, GroupSecretParams group, byte[] randomness)
    {
        EncryptionKeyContext uidKey = UidKeyContext(group);
        PresentationProof proof = new PresentationProofBuilder(Label)
            .AddAttribute(Aci.AsPoints(), uidKey)
            .AddAttribute(Pni.AsPoints(), uidKey)
            .Present(credentialPublicKey, Credential, randomness);

        AttributeCiphertext aciCt = UidEncryption.Encrypt(group.UidKeyPair, Aci);
        AttributeCiphertext pniCt = UidEncryption.Encrypt(group.UidKeyPair, Pni);

        var b = new List<byte> { PresentationVersion4 };
        b.AddRange(proof.Serialize());
        b.AddRange(aciCt.Serialize());     // 64 bytes (no reserved byte at this layer)
        b.AddRange(pniCt.Serialize());     // 64 bytes
        Span<byte> rt = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(rt, RedemptionTime);
        b.AddRange(rt.ToArray());
        return b.ToArray();
    }

    internal static EncryptionKeyContext UidKeyContext(GroupSecretParams group) => new()
    {
        Id = UidEncryption.DomainId,
        Ga1 = UidEncryption.SystemParams.Ga1,
        Ga2 = UidEncryption.SystemParams.Ga2,
        A1 = group.UidKeyPair.A1,
        A2 = group.UidKeyPair.A2,
        PublicKeyA = group.UidKeyPair.PublicKey,
    };

    // ── verifying-server side (offline tests) ──

    /// <summary>Verifies a serialized presentation against the server's credential key and the group's
    /// public UID key. Returns the embedded (aci, pni) ciphertexts on success.</summary>
    public static (UuidCiphertext aci, UuidCiphertext pni) VerifyPresentation(
        byte[] presentation, CredentialKeyPair credentialKey, Ristretto255 groupUidPublicKey, ulong redemptionTime)
    {
        int o = 0;
        if (presentation.Length < 1 || presentation[0] != PresentationVersion4)
            throw new ZkGroupVerificationException("bad presentation version");
        o = 1;
        var proof = new PresentationProof
        {
            Cx0 = ReadPoint(presentation, ref o),
            Cx1 = ReadPoint(presentation, ref o),
            Cv = ReadPoint(presentation, ref o),
        };
        ulong cyLen = BinaryPrimitives.ReadUInt64LittleEndian(presentation.AsSpan(o, 8)); o += 8;
        var cy = new Ristretto255[cyLen];
        for (ulong i = 0; i < cyLen; i++) cy[i] = ReadPoint(presentation, ref o);
        proof.Cy = cy;
        ulong proofLen = BinaryPrimitives.ReadUInt64LittleEndian(presentation.AsSpan(o, 8)); o += 8;
        proof.PokshoProof = presentation.AsSpan(o, (int)proofLen).ToArray(); o += (int)proofLen;

        var aciCt = AttributeCiphertext.Deserialize(presentation.AsSpan(o, 64)); o += 64;
        var pniCt = AttributeCiphertext.Deserialize(presentation.AsSpan(o, 64)); o += 64;
        ulong embeddedRedemption = BinaryPrimitives.ReadUInt64LittleEndian(presentation.AsSpan(o, 8)); o += 8;
        if (embeddedRedemption != redemptionTime)
            throw new ZkGroupVerificationException("redemption time mismatch");

        var pubKey = new EncryptionKeyContext
        {
            Id = UidEncryption.DomainId,
            Ga1 = UidEncryption.SystemParams.Ga1,
            Ga2 = UidEncryption.SystemParams.Ga2,
            PublicKeyA = groupUidPublicKey,
        };
        bool ok = new PresentationProofVerifier(Label)
            .AddAttribute(aciCt.AsPoints(), pubKey)
            .AddAttribute(pniCt.AsPoints(), pubKey)
            .AddPublicAttributeU64(redemptionTime)
            .Verify(credentialKey, proof);
        if (!ok) throw new ZkGroupVerificationException("presentation proof did not verify");
        return (new UuidCiphertext(aciCt), new UuidCiphertext(pniCt));
    }

    private static Ristretto255 ReadPoint(byte[] b, ref int o)
    {
        Ristretto255 p = Ristretto255.Decode(b.AsSpan(o, 32)) ?? throw new ZkGroupVerificationException("bad point");
        o += 32;
        return p;
    }
}
