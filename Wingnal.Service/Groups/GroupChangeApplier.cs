using Wingnal.Protocol.ZkGroup;
using Wingnal.Service.Protos.Groups;

namespace Wingnal.Service.Groups;

/// <summary>
/// Applies a storage-service <c>GroupChange.Actions</c> delta to a local <see cref="DecryptedGroup"/>,
/// decrypting the change's encrypted member/title fields with the group's secret params. Handles the core
/// membership/attribute actions (add/remove/promote members, modify title/description); other action kinds
/// (pending/requesting/banned members, access control, timer) are recognised and skipped for now. The read
/// half of Phase F — incremental reconciliation of <c>GET /v2/groups/logs</c>.
///
/// NOTE: server-signature verification of each change is a separate step (<see cref="GroupSignatureVerifier"/>)
/// that needs Signal's published server sig key; callers should verify BEFORE applying.
/// </summary>
public static class GroupChangeApplier
{
    public static DecryptedGroup Apply(DecryptedGroup current, GroupChange.Types.Actions actions, GroupSecretParams gsp)
    {
        var members = new List<DecryptedGroupMember>(current.Members);
        string title = current.Title;
        string? description = current.Description;
        uint revision = actions.Version;

        foreach (GroupChange.Types.Actions.Types.AddMemberAction add in actions.AddMembers)
        {
            if (add.Added is not { } m) continue;
            string id = DecryptId(m.UserId.Span, gsp);
            members.RemoveAll(x => x.ServiceId == id);
            members.Add(new DecryptedGroupMember(id, IsPni(id), (GroupMemberRole)(int)m.Role, revision));
        }

        foreach (GroupChange.Types.Actions.Types.DeleteMemberAction del in actions.DeleteMembers)
        {
            string id = DecryptId(del.DeletedUserId.Span, gsp);
            members.RemoveAll(x => x.ServiceId == id);
        }

        foreach (GroupChange.Types.Actions.Types.ModifyMemberRoleAction mod in actions.ModifyMemberRoles)
        {
            string id = DecryptId(mod.UserId.Span, gsp);
            for (int i = 0; i < members.Count; i++)
                if (members[i].ServiceId == id)
                    members[i] = members[i] with { Role = (GroupMemberRole)(int)mod.Role };
        }

        // Promoting a pending/requesting member adds them (their userId comes from the presentation/userId field).
        foreach (var promo in actions.PromoteMembersPendingProfileKey)
        {
            if (promo.UserId.IsEmpty) continue;   // userId is set in newer change epochs
            string id = DecryptId(promo.UserId.Span, gsp);
            if (members.All(x => x.ServiceId != id))
                members.Add(new DecryptedGroupMember(id, IsPni(id), GroupMemberRole.Default, revision));
        }

        if (actions.ModifyTitle is { } mt && !mt.Title.IsEmpty)
            title = GroupStateCodec.DecryptBlobTitle(mt.Title.ToByteArray(), gsp);
        if (actions.ModifyDescription is { } md && !md.Description.IsEmpty)
            description = GroupStateCodec.DecryptBlobDescription(md.Description.ToByteArray(), gsp);

        return current with { Title = title, Description = description, Revision = revision, Members = members };
    }

    private static string DecryptId(ReadOnlySpan<byte> uuidCiphertext, GroupSecretParams gsp) =>
        GroupStateCodec.ServiceIdString(gsp.DecryptServiceId(UuidCiphertext.Deserialize(uuidCiphertext)));

    private static bool IsPni(string serviceId) => serviceId.StartsWith("PNI:", StringComparison.Ordinal);
}
