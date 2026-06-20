using Wingnal.Protocol.Groups;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Decrypts an unsealed (authenticated) <see cref="Envelope"/> into a 1:1 text. Handles
/// PREKEY_MESSAGE (establishes the session) and DOUBLE_RATCHET envelopes; returns null for envelope
/// types or content kinds we don't surface yet (receipts, sealed sender, non-text sync, etc.).
/// </summary>
public sealed class MessageDecryptor
{
    private readonly ISignalProtocolStore _store;
    private readonly Account.ProfileKeyStore? _profileKeys;
    private readonly ISenderKeyStore? _senderKeys;

    public MessageDecryptor(ISignalProtocolStore store, Account.ProfileKeyStore? profileKeys = null,
        ISenderKeyStore? senderKeys = null)
    {
        _store = store;
        _profileKeys = profileKeys;
        _senderKeys = senderKeys;
    }

    /// <summary>The full result of decrypting an envelope: the sender, the parsed <see cref="Content"/>
    /// (null for envelope types we don't session-decrypt), and the surfaced 1:1 text (if any).</summary>
    public sealed record Result(string Sender, uint SenderDevice, Content? Content, DecryptedMessage? Message);

    /// <summary>Surfaced-text-only view, kept for callers/tests that just want the chat bubble.</summary>
    public DecryptedMessage? Decrypt(Envelope envelope) => DecryptEnvelope(envelope).Message;

    public Result DecryptEnvelope(Envelope envelope)
    {
        string sender = ResolveServiceId(envelope.SourceServiceId, envelope.SourceServiceIdBinary);
        uint senderDevice = envelope.SourceDeviceId;
        byte[] ciphertext = envelope.Content.ToByteArray();
        bool isPreKey;

        switch (envelope.Type)
        {
            case Envelope.Types.Type.PrekeyMessage:
                isPreKey = true;
                break;
            case Envelope.Types.Type.DoubleRatchet:
                isPreKey = false;
                break;
            case Envelope.Types.Type.UnidentifiedSender:
                // Sealed sender: unwrap to the real sender + inner ciphertext, then decrypt as usual.
                SealedSenderDecryptor.Unsealed u = SealedSenderDecryptor.Decrypt(
                    ciphertext, _store.GetIdentityKeyPair(), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                sender = u.SenderUuid;
                senderDevice = u.SenderDevice;
                ciphertext = u.Content;
                if (u.CiphertextType == 7)                    // 7 = group sender-key (GroupsV2 G1 receive)
                    return DecryptGroupSenderKey(sender, senderDevice, ciphertext, envelope);
                isPreKey = u.CiphertextType == 1;            // PREKEY_MESSAGE
                if (u.CiphertextType is not (1 or 2))         // 2 = MESSAGE; 8 = plaintext
                    return new Result(sender, senderDevice, null, null);
                break;
            default:
                return new Result(sender, senderDevice, null, null); // receipts, etc.
        }

        var address = new SignalProtocolAddress(sender, senderDevice);
        var cipher = new SessionCipher(_store, _store, _store, _store, _store, address);
        byte[] padded = isPreKey
            ? cipher.DecryptPreKeyMessage(PreKeySignalMessage.Parse(ciphertext))
            : cipher.DecryptSignalMessage(SignalMessage.Parse(ciphertext));

        byte[] plaintext = StripPadding(padded);
        var content = Content.Parser.ParseFrom(plaintext);

        // Capture the sender's profile key so we can later send THEM sealed-sender messages.
        if (_profileKeys is not null && content.DataMessage?.ProfileKey is { Length: 32 } pk)
            _profileKeys.Store(sender, pk.ToByteArray());

        // Install any group sender key the peer distributed (so their future group messages decrypt).
        ProcessDistributionIfPresent(content, sender, senderDevice);

        DecryptedMessage? message = SurfaceText(content, sender, senderDevice, envelope);
        return new Result(sender, senderDevice, content, message);
    }

    /// <summary>Decrypts a group (Sender Key) message that arrived as a sealed-sender SENDERKEY envelope,
    /// and surfaces it routed to its group thread. Requires a sender-key store; otherwise the message is
    /// dropped (we couldn't have its sender key without one).</summary>
    private Result DecryptGroupSenderKey(string sender, uint senderDevice, byte[] senderKeyMessage, Envelope envelope)
    {
        if (_senderKeys is null) return new Result(sender, senderDevice, null, null);
        var address = new SignalProtocolAddress(sender, senderDevice);
        byte[] padded = new GroupMessageProcessor(_senderKeys).DecryptGroupMessage(address, senderKeyMessage);
        var content = Content.Parser.ParseFrom(StripPadding(padded));

        if (_profileKeys is not null && content.DataMessage?.ProfileKey is { Length: 32 } pk)
            _profileKeys.Store(sender, pk.ToByteArray());

        DecryptedMessage? message = SurfaceText(content, sender, senderDevice, envelope);
        return new Result(sender, senderDevice, content, message);
    }

    private void ProcessDistributionIfPresent(Content content, string sender, uint senderDevice)
    {
        if (_senderKeys is null || content.SenderKeyDistributionMessage.IsEmpty) return;
        var address = new SignalProtocolAddress(sender, senderDevice);
        new GroupMessageProcessor(_senderKeys)
            .ProcessDistribution(address, content.SenderKeyDistributionMessage.ToByteArray());
    }

    private static DecryptedMessage? SurfaceText(Content content, string sender, uint senderDevice, Envelope envelope)
    {
        // Direct incoming 1:1 message (text, or a placeholder for media/reactions so it still appears).
        if (content.DataMessage is { } dm)
        {
            string? text = Describe(dm);
            if (text is not null)
            {
                long ts = dm.Timestamp != 0 ? (long)dm.Timestamp : (long)envelope.ServerTimestamp;
                (string? groupId, byte[]? masterKey) = GroupContext(dm.GroupV2);
                return new DecryptedMessage(sender, senderDevice, text, ts, Outgoing: false)
                {
                    Attachment = dm.Attachments.Count > 0 ? dm.Attachments[0] : null,
                    GroupId = groupId, GroupMasterKey = masterKey,
                };
            }
        }

        // Transcript of a message we sent from another device (synced to us).
        if (content.SyncMessage?.Sent is { } sent && sent.Message is { } sentMsg && Describe(sentMsg) is { } sentText)
        {
            string peer = sent.DestinationServiceId ?? sender;
            long ts = sent.Timestamp != 0 ? (long)sent.Timestamp : (long)envelope.ServerTimestamp;
            (string? groupId, byte[]? masterKey) = GroupContext(sentMsg.GroupV2);
            return new DecryptedMessage(peer, senderDevice, sentText, ts, Outgoing: true)
            {
                Attachment = sentMsg.Attachments.Count > 0 ? sentMsg.Attachments[0] : null,
                GroupId = groupId, GroupMasterKey = masterKey,
            };
        }

        return null;
    }

    /// <summary>Derives the (groupId, masterKey) from a GroupContextV2, or (null, null) for a 1:1 message.</summary>
    private static (string? groupId, byte[]? masterKey) GroupContext(GroupContextV2? groupV2)
    {
        if (groupV2?.MasterKey is { Length: 32 } mk)
        {
            byte[] key = mk.ToByteArray();
            return (GroupMessageProcessor.GroupIdHex(key), key);
        }
        return (null, null);
    }

    /// <summary>The display text for a DataMessage: the body, else a placeholder for an attachment or
    /// reaction (so media/reactions show up instead of being silently dropped). Null = nothing to show
    /// (receipts, typing, empty).</summary>
    private static string? Describe(DataMessage dm)
    {
        if (!string.IsNullOrEmpty(dm.Body)) return dm.Body;

        if (dm.Reaction is { } r && !string.IsNullOrEmpty(r.Emoji))
            return r.Remove ? "removed a reaction" : $"reacted {r.Emoji}";

        if (dm.Attachments.Count > 0)
            return DescribeAttachment(dm.Attachments[0], dm.Attachments.Count);

        return null;
    }

    private static string DescribeAttachment(AttachmentPointer a, int count)
    {
        string label =
            (a.Flags & (uint)AttachmentPointer.Types.Flags.VoiceMessage) != 0 ? "🎙 Voice message" :
            !string.IsNullOrEmpty(a.ContentType) && a.ContentType.StartsWith("image/") ? "📷 Photo" :
            !string.IsNullOrEmpty(a.ContentType) && a.ContentType.StartsWith("video/") ? "🎥 Video" :
            !string.IsNullOrEmpty(a.FileName) ? $"📎 {a.FileName}" : "📎 Attachment";
        return count > 1 ? $"{label} (+{count - 1} more)" : label;
    }

    /// <summary>Resolves a service id, preferring the string form and falling back to the binary form
    /// (16-byte ACI UUID, or 1-byte prefix + 16-byte UUID for PNI).</summary>
    private static string ResolveServiceId(string asString, Google.Protobuf.ByteString binary) =>
        !string.IsNullOrEmpty(asString) ? asString : ServiceIds.StringFromBinary(binary.Span) ?? string.Empty;

    /// <summary>Removes Signal's PushTransportDetails padding (0x80 terminator + trailing zeros).</summary>
    private static byte[] StripPadding(byte[] message) => MessagePadding.Strip(message);
}
