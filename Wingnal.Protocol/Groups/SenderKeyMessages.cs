using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;

namespace Wingnal.Protocol.Groups;

/// <summary>
/// Shared constants + helpers for the Sender Key (group) wire format. Byte-exact with libsignal
/// (rust/protocol: <c>protocol.rs</c>, <c>proto/wire.proto</c>, tag v0.96.1).
/// </summary>
internal static class SenderKeyWire
{
    /// <summary>libsignal <c>SENDERKEY_MESSAGE_CURRENT_VERSION</c> — the low nibble of the version byte.</summary>
    public const int CurrentVersion = 3;

    /// <summary>Version byte: high nibble = message version, low nibble = current ciphertext version.</summary>
    public static byte VersionByte(int messageVersion) =>
        (byte)(((messageVersion & 0xF) << 4) | CurrentVersion);

    /// <summary>A UUID's 16 bytes in RFC 4122 / network (big-endian) order — what libsignal's uuid
    /// crate emits via <c>as_bytes()</c>. (.NET's default <see cref="Guid.ToByteArray()"/> is
    /// mixed-endian; the <c>bigEndian</c> overload gives the RFC-4122 order directly.)</summary>
    public static byte[] DistributionBytes(Guid id) => id.ToByteArray(bigEndian: true);

    public static Guid DistributionId(byte[] be)
    {
        if (be.Length != 16) throw new InvalidMessageException("bad distribution id length");
        return new Guid(be, bigEndian: true);
    }
}

/// <summary>
/// A group message ("SenderKeyMessage"): <c>version || protobuf(distribution_uuid, chain_id,
/// iteration, ciphertext) || signature[64]</c>. The signature is XEdDSA over <c>version||protobuf</c>
/// using the sender's per-distribution signing key.
/// </summary>
public sealed class SenderKeyMessage
{
    private const int SignatureLen = 64;

    public int MessageVersion { get; }
    public Guid DistributionId { get; }
    public uint ChainId { get; }
    public uint Iteration { get; }
    public byte[] Ciphertext { get; }
    private readonly byte[] _serialized;

    /// <summary>Builds + signs a SenderKeyMessage. <paramref name="signingPrivateKey"/> is the raw
    /// 32-byte Curve25519 private signing scalar.</summary>
    public SenderKeyMessage(int messageVersion, Guid distributionId, uint chainId, uint iteration,
        byte[] ciphertext, byte[] signingPrivateKey)
    {
        MessageVersion = messageVersion;
        DistributionId = distributionId;
        ChainId = chainId;
        Iteration = iteration;
        Ciphertext = ciphertext;

        var proto = new ProtoWriter();
        proto.WriteBytes(1, SenderKeyWire.DistributionBytes(distributionId));
        proto.WriteUInt32(2, chainId);
        proto.WriteUInt32(3, iteration);
        proto.WriteBytes(4, ciphertext);
        byte[] protoBytes = proto.ToArray();

        var signed = new byte[1 + protoBytes.Length];
        signed[0] = SenderKeyWire.VersionByte(messageVersion);
        Array.Copy(protoBytes, 0, signed, 1, protoBytes.Length);

        byte[] signature = XEd25519.CalculateSignature(signingPrivateKey, signed, RandomNumberGenerator.GetBytes(64));

        _serialized = new byte[signed.Length + SignatureLen];
        Array.Copy(signed, 0, _serialized, 0, signed.Length);
        Array.Copy(signature, 0, _serialized, signed.Length, SignatureLen);
    }

    // Distinct parameter order (serialized first) so this doesn't collide with the signing ctor above.
    private SenderKeyMessage(byte[] serialized, int version, Guid id, uint chainId, uint iteration, byte[] ciphertext)
    {
        _serialized = serialized;
        MessageVersion = version;
        DistributionId = id;
        ChainId = chainId;
        Iteration = iteration;
        Ciphertext = ciphertext;
    }

    public byte[] Serialize() => _serialized;

    public static SenderKeyMessage Parse(byte[] serialized)
    {
        if (serialized.Length < 1 + SignatureLen)
            throw new InvalidMessageException("SenderKeyMessage too short");

        int version = (serialized[0] >> 4) & 0xF;
        var reader = new ProtoReader(serialized.AsSpan(1, serialized.Length - 1 - SignatureLen));

        byte[]? distribution = null, ciphertext = null;
        uint chainId = 0, iteration = 0;
        while (reader.TryReadTag(out int field, out int wireType))
        {
            switch (field)
            {
                case 1: distribution = reader.ReadBytes(); break;
                case 2: chainId = reader.ReadUInt32(); break;
                case 3: iteration = reader.ReadUInt32(); break;
                case 4: ciphertext = reader.ReadBytes(); break;
                default: reader.SkipField(wireType); break;
            }
        }
        if (distribution is null || ciphertext is null)
            throw new InvalidMessageException("incomplete SenderKeyMessage");

        return new SenderKeyMessage(serialized, version, SenderKeyWire.DistributionId(distribution),
            chainId, iteration, ciphertext);
    }

    /// <summary>Verifies the XEdDSA signature against the signer's public key (raw 32-byte Montgomery).</summary>
    public bool VerifySignature(byte[] signingPublicKey)
    {
        int splitAt = _serialized.Length - SignatureLen;
        return XEd25519.VerifySignature(
            signingPublicKey,
            _serialized.AsSpan(0, splitAt),
            _serialized.AsSpan(splitAt, SignatureLen));
    }
}

/// <summary>
/// A SenderKeyDistributionMessage (SKDM): <c>version || protobuf(distribution_uuid, chain_id,
/// iteration, chain_key[32], signing_key[33])</c>. Sent (1:1, sealed) to each group member so they can
/// build a receiving sender-key state. No signature of its own — the included signing public key
/// authenticates subsequent SenderKeyMessages.
/// </summary>
public sealed class SenderKeyDistributionMessage
{
    public int MessageVersion { get; }
    public Guid DistributionId { get; }
    public uint ChainId { get; }
    public uint Iteration { get; }
    public byte[] ChainKey { get; }            // 32-byte chain key seed
    public byte[] SigningKeyPublic { get; }    // raw 32-byte Montgomery public
    private readonly byte[] _serialized;

    public SenderKeyDistributionMessage(int messageVersion, Guid distributionId, uint chainId,
        uint iteration, byte[] chainKey, byte[] signingKeyPublic)
    {
        MessageVersion = messageVersion;
        DistributionId = distributionId;
        ChainId = chainId;
        Iteration = iteration;
        ChainKey = chainKey;
        SigningKeyPublic = signingKeyPublic;

        var proto = new ProtoWriter();
        proto.WriteBytes(1, SenderKeyWire.DistributionBytes(distributionId));
        proto.WriteUInt32(2, chainId);
        proto.WriteUInt32(3, iteration);
        proto.WriteBytes(4, chainKey);
        proto.WriteBytes(5, Curve25519.EncodePoint(signingKeyPublic));
        byte[] protoBytes = proto.ToArray();

        _serialized = new byte[1 + protoBytes.Length];
        _serialized[0] = SenderKeyWire.VersionByte(messageVersion);
        Array.Copy(protoBytes, 0, _serialized, 1, protoBytes.Length);
    }

    private SenderKeyDistributionMessage(int version, Guid id, uint chainId, uint iteration,
        byte[] chainKey, byte[] signingPublic, byte[] serialized)
    {
        MessageVersion = version;
        DistributionId = id;
        ChainId = chainId;
        Iteration = iteration;
        ChainKey = chainKey;
        SigningKeyPublic = signingPublic;
        _serialized = serialized;
    }

    public byte[] Serialize() => _serialized;

    public static SenderKeyDistributionMessage Parse(byte[] serialized)
    {
        if (serialized.Length < 1) throw new InvalidMessageException("SKDM too short");

        int version = (serialized[0] >> 4) & 0xF;
        var reader = new ProtoReader(serialized.AsSpan(1));

        byte[]? distribution = null, chainKey = null, signingKey = null;
        uint chainId = 0, iteration = 0;
        while (reader.TryReadTag(out int field, out int wireType))
        {
            switch (field)
            {
                case 1: distribution = reader.ReadBytes(); break;
                case 2: chainId = reader.ReadUInt32(); break;
                case 3: iteration = reader.ReadUInt32(); break;
                case 4: chainKey = reader.ReadBytes(); break;
                case 5: signingKey = Curve25519.DecodePoint(reader.ReadBytes()); break;
                default: reader.SkipField(wireType); break;
            }
        }
        if (distribution is null || chainKey is null || signingKey is null)
            throw new InvalidMessageException("incomplete SenderKeyDistributionMessage");

        return new SenderKeyDistributionMessage(version, SenderKeyWire.DistributionId(distribution),
            chainId, iteration, chainKey, signingKey, serialized);
    }
}
