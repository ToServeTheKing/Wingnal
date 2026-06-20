namespace Wingnal.Service.Groups;

/// <summary>A group's state after decrypting the storage-service <c>Group</c> blob with the group's
/// secret params: plaintext title/roster/revision the app can render.</summary>
public sealed record DecryptedGroup(
    string Title,
    string? Description,
    uint Revision,
    IReadOnlyList<DecryptedGroupMember> Members);

/// <summary>A decrypted group member: their service id (lowercase UUID string), role, and join revision.</summary>
public sealed record DecryptedGroupMember(string ServiceId, bool IsPni, GroupMemberRole Role, uint JoinedAtRevision);

public enum GroupMemberRole { Unknown = 0, Default = 1, Administrator = 2 }
