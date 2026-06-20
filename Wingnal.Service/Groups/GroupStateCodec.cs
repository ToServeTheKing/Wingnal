using Wingnal.Protocol.ZkGroup;
using Wingnal.Service.Protos.Groups;

namespace Wingnal.Service.Groups;

/// <summary>
/// Decrypts a storage-service <c>Group</c> proto into a plaintext <see cref="DecryptedGroup"/> using the
/// group's <see cref="GroupSecretParams"/>: member service ids via the UID ciphertext (Phase D2), the title
/// via the AES-256-GCM-SIV attribute blob (Phase D1). All member identity fields on the wire are zkgroup
/// ciphertexts, so this is the read half of Phase E. Pure/offline (no network).
/// </summary>
public static class GroupStateCodec
{
    public static DecryptedGroup Decode(Group group, GroupSecretParams gsp)
    {
        string title = DecryptBlobTitle(group.Title.ToByteArray(), gsp);
        string? description = group.Description.IsEmpty
            ? null : DecryptBlobDescription(group.Description.ToByteArray(), gsp);

        var members = new List<DecryptedGroupMember>(group.Members.Count);
        foreach (Member m in group.Members)
        {
            UuidCiphertext ct = UuidCiphertext.Deserialize(m.UserId.Span);
            ServiceId sid = gsp.DecryptServiceId(ct);
            members.Add(new DecryptedGroupMember(
                ServiceIdString(sid), sid.IsPni, (GroupMemberRole)(int)m.Role, m.JoinedAtVersion));
        }

        return new DecryptedGroup(title, description, group.Version, members);
    }

    internal static string DecryptBlobTitle(byte[] encrypted, GroupSecretParams gsp)
    {
        if (encrypted.Length == 0) return string.Empty;
        var blob = GroupAttributeBlob.Parser.ParseFrom(gsp.DecryptBlobWithPadding(encrypted));
        return blob.ContentCase == GroupAttributeBlob.ContentOneofCase.Title ? blob.Title : string.Empty;
    }

    internal static string? DecryptBlobDescription(byte[] encrypted, GroupSecretParams gsp)
    {
        if (encrypted.Length == 0) return null;
        var blob = GroupAttributeBlob.Parser.ParseFrom(gsp.DecryptBlobWithPadding(encrypted));
        return blob.ContentCase == GroupAttributeBlob.ContentOneofCase.DescriptionText ? blob.DescriptionText : null;
    }

    /// <summary>A zkgroup service id → canonical lowercase UUID string (PNI prefixed with "PNI:").</summary>
    internal static string ServiceIdString(ServiceId sid)
    {
        string uuid = new Guid(sid.RawUuid, bigEndian: true).ToString("D").ToLowerInvariant();
        return sid.IsPni ? $"PNI:{uuid}" : uuid;
    }
}
