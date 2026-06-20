namespace Wingnal.Service.Messaging;

/// <summary>A decrypted 1:1 text message (incoming, or a synced transcript of one we sent). When the
/// message carried media, <see cref="Attachment"/> is the first attachment pointer (download separately).</summary>
public sealed record DecryptedMessage(
    string PeerServiceId,
    uint SenderDeviceId,
    string Body,
    long Timestamp,
    bool Outgoing)
{
    public Protos.AttachmentPointer? Attachment { get; init; }

    /// <summary>For a group (GroupsV2) message, the lowercase-hex group identifier this belongs to; null for
    /// a 1:1 message. When set, the conversation is keyed by the group rather than by <see cref="PeerServiceId"/>.</summary>
    public string? GroupId { get; init; }

    /// <summary>For a group message, the 32-byte group master key (from GroupContextV2) — persisted so the
    /// group can later be fetched/decrypted from the storage service.</summary>
    public byte[]? GroupMasterKey { get; init; }
}
