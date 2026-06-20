namespace Wingnal.Service.Net;

/// <summary>Endpoints and identifiers for talking to the Signal production service.</summary>
public static class SignalServiceConfig
{
    /// <summary>HTTPS base for the chat/account REST API.</summary>
    public const string ServiceUrl = "https://chat.signal.org";

    /// <summary>WSS base for the authenticated and provisioning WebSockets.</summary>
    public const string WebSocketUrl = "wss://chat.signal.org";

    /// <summary>HTTPS base for the group storage service (GroupsV2). Separate host from chat, but chains to
    /// the same bundled Signal CA (<c>SignalTrust</c>), so the existing pin applies.</summary>
    public const string StorageUrl = "https://storage.signal.org";

    /// <summary>Unauthenticated socket used during secondary-device linking.</summary>
    public const string ProvisioningWebSocketPath = "/v1/websocket/provisioning/";

    /// <summary>Authenticated chat socket (used post-link to send/receive messages).</summary>
    public const string ChatWebSocketPath = "/v1/websocket/";

    /// <summary>Sent as the User-Agent / X-Signal-Agent on requests.</summary>
    public const string UserAgent = "Wingnal";

    /// <summary>CDN base URL for an AttachmentPointer's <c>cdnNumber</c>. 0/absent = legacy cdn0; 2/3 are
    /// the current attachment/backup CDNs. (cdn1 was retired.)</summary>
    public static string CdnUrl(uint cdnNumber) => cdnNumber switch
    {
        0 => "https://cdn.signal.org",
        2 => "https://cdn2.signal.org",
        3 => "https://cdn3.signal.org",
        _ => "https://cdn2.signal.org",
    };
}
