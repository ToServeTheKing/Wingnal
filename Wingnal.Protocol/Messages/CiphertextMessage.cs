using System.Security.Cryptography;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Messages;

/// <summary>Thrown when a ciphertext is malformed or fails authentication.</summary>
public sealed class InvalidMessageException : Exception
{
    public InvalidMessageException(string message) : base(message) { }
}

/// <summary>Thrown when a message key has already been used (duplicate / replayed message).</summary>
public sealed class DuplicateMessageException : Exception
{
    public DuplicateMessageException(string message) : base(message) { }
}

/// <summary>
/// Thrown when a peer presents an identity key that differs from the one we previously trusted (a
/// possible man-in-the-middle, or a legitimate reinstall). The session is NOT established until the
/// user verifies the new safety number and approves it.
/// </summary>
public sealed class UntrustedIdentityException : Exception
{
    public State.SignalProtocolAddress Address { get; }
    public State.IdentityKey Identity { get; }

    public UntrustedIdentityException(State.SignalProtocolAddress address, State.IdentityKey identity)
        : base($"untrusted identity for {address.Name}.{address.DeviceId}")
    {
        Address = address;
        Identity = identity;
    }
}

public enum CiphertextMessageType
{
    Whisper = 2,
    PreKey = 3,
}

public interface ICiphertextMessage
{
    CiphertextMessageType Type { get; }
    byte[] Serialize();
}

/// <summary>
/// A Double Ratchet message ("WhisperMessage"): version || protobuf(ratchetKey, counter,
/// previousCounter, ciphertext) || MAC[8]. The MAC is HMAC-SHA256 over sender||receiver identity
/// keys and (version||protobuf), truncated to 8 bytes.
/// </summary>
public sealed class SignalMessage : ICiphertextMessage
{
    private const int MacLength = 8;

    public int MessageVersion { get; }
    public byte[] SenderRatchetKey { get; }   // raw 32-byte Montgomery key
    public uint Counter { get; }
    public uint PreviousCounter { get; }
    public byte[] Body { get; }               // ciphertext
    public byte[]? PqRatchet { get; }         // SPQR field 5 (null/empty when SPQR disabled)
    private readonly byte[] _serialized;

    public CiphertextMessageType Type => CiphertextMessageType.Whisper;

    public SignalMessage(int messageVersion, byte[] macKey, byte[] senderRatchetKey, uint counter,
        uint previousCounter, byte[] ciphertext, IdentityKey senderIdentity, IdentityKey receiverIdentity,
        byte[]? pqRatchet = null)
    {
        MessageVersion = messageVersion;
        SenderRatchetKey = senderRatchetKey;
        Counter = counter;
        PreviousCounter = previousCounter;
        Body = ciphertext;
        PqRatchet = pqRatchet is { Length: > 0 } ? pqRatchet : null;

        var proto = new ProtoWriter();
        proto.WriteBytes(1, Curve25519.EncodePoint(senderRatchetKey));
        proto.WriteUInt32(2, counter);
        proto.WriteUInt32(3, previousCounter);
        proto.WriteBytes(4, ciphertext);
        if (PqRatchet is not null) proto.WriteBytes(5, PqRatchet);
        byte[] protoBytes = proto.ToArray();

        byte version = (byte)((messageVersion << 4) | messageVersion);
        var message = new byte[1 + protoBytes.Length];
        message[0] = version;
        Array.Copy(protoBytes, 0, message, 1, protoBytes.Length);

        byte[] mac = GetMac(senderIdentity, receiverIdentity, macKey, message);
        _serialized = new byte[message.Length + MacLength];
        Array.Copy(message, 0, _serialized, 0, message.Length);
        Array.Copy(mac, 0, _serialized, message.Length, MacLength);
    }

    private SignalMessage(int version, byte[] senderRatchetKey, uint counter, uint previousCounter,
        byte[] body, byte[]? pqRatchet, byte[] serialized)
    {
        MessageVersion = version;
        SenderRatchetKey = senderRatchetKey;
        Counter = counter;
        PreviousCounter = previousCounter;
        Body = body;
        PqRatchet = pqRatchet is { Length: > 0 } ? pqRatchet : null;
        _serialized = serialized;
    }

    public byte[] Serialize() => _serialized;

    public static SignalMessage Parse(byte[] serialized)
    {
        if (serialized.Length < 1 + MacLength)
            throw new InvalidMessageException("message too short");

        int version = (serialized[0] >> 4) & 0xF;
        var reader = new ProtoReader(serialized.AsSpan(1, serialized.Length - 1 - MacLength));

        byte[]? ratchetKey = null;
        uint counter = 0, previousCounter = 0;
        byte[]? body = null, pqRatchet = null;
        while (reader.TryReadTag(out int field, out int wireType))
        {
            switch (field)
            {
                case 1: ratchetKey = Curve25519.DecodePoint(reader.ReadBytes()); break;
                case 2: counter = reader.ReadUInt32(); break;
                case 3: previousCounter = reader.ReadUInt32(); break;
                case 4: body = reader.ReadBytes(); break;
                case 5: pqRatchet = reader.ReadBytes(); break;
                default: reader.SkipField(wireType); break;
            }
        }

        if (ratchetKey is null || body is null)
            throw new InvalidMessageException("incomplete SignalMessage");

        return new SignalMessage(version, ratchetKey, counter, previousCounter, body, pqRatchet, serialized);
    }

    public bool VerifyMac(IdentityKey senderIdentity, IdentityKey receiverIdentity, byte[] macKey)
    {
        int splitAt = _serialized.Length - MacLength;
        byte[] theirMac = _serialized.AsSpan(splitAt).ToArray();
        byte[] ourMac = GetMac(senderIdentity, receiverIdentity, macKey, _serialized.AsSpan(0, splitAt).ToArray());
        return CryptographicOperations.FixedTimeEquals(theirMac, ourMac);
    }

    private static byte[] GetMac(IdentityKey sender, IdentityKey receiver, byte[] macKey, byte[] message)
    {
        using var hmac = new HMACSHA256(macKey);
        hmac.TransformBlock(sender.Serialize(), 0, 33, null, 0);
        hmac.TransformBlock(receiver.Serialize(), 0, 33, null, 0);
        hmac.TransformFinalBlock(message, 0, message.Length);
        return hmac.Hash!.AsSpan(0, MacLength).ToArray();
    }
}

/// <summary>
/// A PreKeySignalMessage: carries the X3DH/PQXDH session-setup material (which prekeys the sender
/// used, its base/identity keys, the optional Kyber ciphertext) wrapping an inner SignalMessage.
/// </summary>
public sealed class PreKeySignalMessage : ICiphertextMessage
{
    public int MessageVersion { get; }
    public uint RegistrationId { get; }
    public uint? PreKeyId { get; }
    public uint SignedPreKeyId { get; }
    public uint? KyberPreKeyId { get; }
    public byte[]? KyberCiphertext { get; }
    public byte[] BaseKey { get; }            // raw 32
    public IdentityKey IdentityKey { get; }
    public SignalMessage Message { get; }
    private readonly byte[] _serialized;

    public CiphertextMessageType Type => CiphertextMessageType.PreKey;

    public PreKeySignalMessage(int messageVersion, uint registrationId, uint? preKeyId, uint signedPreKeyId,
        uint? kyberPreKeyId, byte[]? kyberCiphertext, byte[] baseKey, IdentityKey identityKey, SignalMessage message)
    {
        MessageVersion = messageVersion;
        RegistrationId = registrationId;
        PreKeyId = preKeyId;
        SignedPreKeyId = signedPreKeyId;
        KyberPreKeyId = kyberPreKeyId;
        KyberCiphertext = kyberCiphertext;
        BaseKey = baseKey;
        IdentityKey = identityKey;
        Message = message;

        var proto = new ProtoWriter();
        proto.WriteUInt32(5, registrationId);
        if (preKeyId.HasValue) proto.WriteUInt32(1, preKeyId.Value);
        proto.WriteUInt32(6, signedPreKeyId);
        if (kyberPreKeyId.HasValue) proto.WriteUInt32(7, kyberPreKeyId.Value);
        if (kyberCiphertext is not null) proto.WriteBytes(8, kyberCiphertext);
        proto.WriteBytes(2, Curve25519.EncodePoint(baseKey));
        proto.WriteBytes(3, identityKey.Serialize());
        proto.WriteBytes(4, message.Serialize());
        byte[] protoBytes = proto.ToArray();

        byte version = (byte)((messageVersion << 4) | messageVersion);
        _serialized = new byte[1 + protoBytes.Length];
        _serialized[0] = version;
        Array.Copy(protoBytes, 0, _serialized, 1, protoBytes.Length);
    }

    public byte[] Serialize() => _serialized;

    public static PreKeySignalMessage Parse(byte[] serialized)
    {
        if (serialized.Length < 1) throw new InvalidMessageException("message too short");

        int version = (serialized[0] >> 4) & 0xF;
        var reader = new ProtoReader(serialized.AsSpan(1));

        uint registrationId = 0, signedPreKeyId = 0;
        uint? preKeyId = null, kyberPreKeyId = null;
        byte[]? kyberCiphertext = null, baseKey = null, identityKey = null, message = null;
        while (reader.TryReadTag(out int field, out int wireType))
        {
            switch (field)
            {
                case 5: registrationId = reader.ReadUInt32(); break;
                case 1: preKeyId = reader.ReadUInt32(); break;
                case 6: signedPreKeyId = reader.ReadUInt32(); break;
                case 7: kyberPreKeyId = reader.ReadUInt32(); break;
                case 8: kyberCiphertext = reader.ReadBytes(); break;
                case 2: baseKey = Curve25519.DecodePoint(reader.ReadBytes()); break;
                case 3: identityKey = reader.ReadBytes(); break;
                case 4: message = reader.ReadBytes(); break;
                default: reader.SkipField(wireType); break;
            }
        }

        if (baseKey is null || identityKey is null || message is null)
            throw new InvalidMessageException("incomplete PreKeySignalMessage");

        return new PreKeySignalMessage(version, registrationId, preKeyId, signedPreKeyId, kyberPreKeyId,
            kyberCiphertext, baseKey, State.IdentityKey.Decode(identityKey), SignalMessage.Parse(message));
    }
}
