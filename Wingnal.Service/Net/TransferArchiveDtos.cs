namespace Wingnal.Service.Net;

/// <summary>
/// The descriptor the server returns from <c>GET /v1/devices/transfer_archive</c> once the primary has
/// uploaded the link'n'sync message-history archive (Signal-Server <c>RemoteAttachment</c>). The archive
/// itself is fetched from the CDN and decrypted with keys derived from the provisioning
/// <c>ephemeralBackupKey</c>. See docs/SYNC.md.
/// </summary>
public sealed class TransferArchiveDescriptor
{
    public int Cdn { get; set; }
    public string? Key { get; set; }

    /// <summary>Set instead of cdn/key when the primary reported it couldn't produce an archive
    /// (Signal-Server <c>RemoteAttachmentError</c>: e.g. CONTINUE_WITHOUT_UPLOAD / RELINK_REQUESTED).</summary>
    public string? Error { get; set; }

    public bool IsError => !string.IsNullOrEmpty(Error);
}
