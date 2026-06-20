using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>
/// zkgroup's <c>GroupSecretParams</c> derived from the 32-byte group master key (which arrives in the
/// <c>GroupContextV2</c> of group messages and via Storage Service). Provides the 32-byte group identifier
/// (used to key a group conversation) and AES-256-GCM-SIV encryption of the group's title/avatar/etc.
/// "blobs" under the derived blob key. Byte-exact with libsignal zkgroup.
///
/// NOTE: the member-hiding ciphertext + credential layer (UuidCiphertext, AuthCredentialWithPni, …) is
/// NOT here yet — it requires porting the zkcredential crate + the dalek-fork "Lizard" 16-byte→point
/// encoding (see docs/GROUPS.md Phase D remainder). This type covers group-id derivation (enough for
/// receiving group messages) and blob decryption.
/// </summary>
public sealed class GroupSecretParams
{
    private const int MasterKeyLen = 32;

    public byte[] MasterKey { get; }
    public byte[] GroupIdentifier { get; }   // 32 bytes
    private readonly byte[] _blobKey;          // 32-byte AES key

    /// <summary>The group's UID verifiable-encryption key pair (encrypts/decrypts member ACIs/PNIs).</summary>
    public AttributeKeyPair UidKeyPair { get; }

    /// <summary>The group's profile-key verifiable-encryption key pair.</summary>
    public AttributeKeyPair ProfileKeyKeyPair { get; }

    private GroupSecretParams(byte[] masterKey, byte[] groupId, byte[] blobKey,
        AttributeKeyPair uidKeyPair, AttributeKeyPair profileKeyKeyPair)
    {
        MasterKey = masterKey;
        GroupIdentifier = groupId;
        _blobKey = blobKey;
        UidKeyPair = uidKeyPair;
        ProfileKeyKeyPair = profileKeyKeyPair;
    }

    public static GroupSecretParams Generate(byte[] randomness)
    {
        var sho = new ShoHmacSha256(Ascii("Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate"));
        sho.AbsorbAndRatchet(randomness);
        return DeriveFromMasterKey(sho.SqueezeAndRatchet(MasterKeyLen));
    }

    public static GroupSecretParams DeriveFromMasterKey(byte[] masterKey)
    {
        if (masterKey.Length != MasterKeyLen) throw new ArgumentException("master key must be 32 bytes");
        var sho = new ShoHmacSha256(
            Ascii("Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey"));
        sho.AbsorbAndRatchet(masterKey);
        byte[] groupId = sho.SqueezeAndRatchet(32);
        byte[] blobKey = sho.SqueezeAndRatchet(32);
        // The SAME sho continues into both encryption key pairs (order: uid then profile-key).
        AttributeKeyPair uidKeyPair = UidEncryption.DeriveKeyPair(sho);
        AttributeKeyPair profileKeyKeyPair = ProfileKeyEncryption.DeriveKeyPair(sho);
        return new GroupSecretParams((byte[])masterKey.Clone(), groupId, blobKey, uidKeyPair, profileKeyKeyPair);
    }

    // ── public params + member-ciphertext helpers (the visible part of the group) ──

    /// <summary>The group's public params: group id + the two encryption public keys (97 bytes serialized).</summary>
    public byte[] PublicParamsSerialized()
    {
        var b = new byte[97];
        b[0] = 0;   // reserved
        Array.Copy(GroupIdentifier, 0, b, 1, 32);
        Array.Copy(UidKeyPair.PublicKey.Encode(), 0, b, 33, 32);
        Array.Copy(ProfileKeyKeyPair.PublicKey.Encode(), 0, b, 65, 32);
        return b;
    }

    public UuidCiphertext EncryptServiceId(ServiceId serviceId) =>
        new(UidEncryption.Encrypt(UidKeyPair, UidStruct.FromServiceId(serviceId)));

    public ServiceId DecryptServiceId(UuidCiphertext ciphertext) =>
        UidEncryption.Decrypt(UidKeyPair, ciphertext.Ciphertext);

    public ProfileKeyCiphertext EncryptProfileKey(byte[] profileKey32, byte[] aciUuid16) =>
        new(ProfileKeyEncryption.Encrypt(ProfileKeyKeyPair, ProfileKeyStruct.New(profileKey32, aciUuid16)));

    public byte[] DecryptProfileKey(ProfileKeyCiphertext ciphertext, byte[] aciUuid16) =>
        ProfileKeyEncryption.Decrypt(ProfileKeyKeyPair, ciphertext.Ciphertext, aciUuid16);

    // ── blob encryption (AES-256-GCM-SIV; RFC 8452) ──

    public byte[] EncryptBlobWithPadding(byte[] randomness, byte[] plaintext, uint paddingLen)
    {
        var padded = new byte[4 + plaintext.Length + (int)paddingLen];
        BinaryPrimitives.WriteUInt32BigEndian(padded, paddingLen);
        Array.Copy(plaintext, 0, padded, 4, plaintext.Length);
        return EncryptBlob(randomness, padded);
    }

    public byte[] EncryptBlob(byte[] randomness, byte[] plaintext)
    {
        var sho = new ShoHmacSha256(Ascii("Signal_ZKGroup_20200424_Random_GroupSecretParams_EncryptBlob"));
        sho.AbsorbAndRatchet(randomness);
        byte[] nonce = sho.SqueezeAndRatchet(12);
        byte[] ct = GcmSiv(forEncryption: true, _blobKey, nonce, plaintext);
        var result = new byte[ct.Length + 12 + 1];   // ciphertext‖nonce‖reserved(0)
        Array.Copy(ct, result, ct.Length);
        Array.Copy(nonce, 0, result, ct.Length, 12);
        return result;
    }

    public byte[] DecryptBlobWithPadding(byte[] ciphertext)
    {
        byte[] dec = DecryptBlob(ciphertext);
        if (dec.Length < 4) throw new ArgumentException("blob too short");
        uint padLen = BinaryPrimitives.ReadUInt32BigEndian(dec);
        int plen = dec.Length - 4 - (int)padLen;
        if (plen < 0) throw new ArgumentException("bad padding length");
        var pt = new byte[plen];
        Array.Copy(dec, 4, pt, 0, plen);
        return pt;
    }

    public byte[] DecryptBlob(byte[] ciphertext)
    {
        if (ciphertext.Length < 12 + 1) throw new ArgumentException("blob too short");
        int unreserved = ciphertext.Length - 1;   // drop trailing reserved byte
        var nonce = new byte[12];
        Array.Copy(ciphertext, unreserved - 12, nonce, 0, 12);
        var ct = new byte[unreserved - 12];
        Array.Copy(ciphertext, 0, ct, 0, ct.Length);
        return GcmSiv(forEncryption: false, _blobKey, nonce, ct);
    }

    private static byte[] GcmSiv(bool forEncryption, byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = new GcmSivBlockCipher(new AesEngine());
        cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), 128, nonce));
        var outBuf = new byte[cipher.GetOutputSize(input.Length)];
        int n = cipher.ProcessBytes(input, 0, input.Length, outBuf, 0);
        n += cipher.DoFinal(outBuf, n);
        if (n != outBuf.Length) Array.Resize(ref outBuf, n);
        return outBuf;
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
}
