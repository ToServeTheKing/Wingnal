using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Google.Protobuf;
using Wingnal.Service.Net;
using Wingnal.Service.Protos.Groups;

namespace Wingnal.Service.Groups;

/// <summary>
/// Client for Signal's group storage service (<c>storage.signal.org</c>, GroupsV2). All requests authenticate
/// with a per-call Basic header whose username is hex(GroupPublicParams) and password is
/// hex(AuthCredentialWithPni presentation) — the server matches the encrypted member identities without
/// learning the caller's ACI. TLS pins to the bundled Signal CA via <see cref="SignalTrust"/>.
///
/// LIVE-UNTESTED (headless): the actual storage-service round-trip. The request/response shapes and auth
/// header follow Signal-Android's <c>PushServiceSocket</c> / <c>GroupsV2AuthorizationString</c>.
/// </summary>
public sealed class GroupsApiClient : IDisposable
{
    private readonly HttpClient _http;

    public GroupsApiClient(HttpClient? http = null) => _http = http ?? CreatePinnedClient();

    private static HttpClient CreatePinnedClient()
    {
        var handler = new SocketsHttpHandler();
        handler.SslOptions.RemoteCertificateValidationCallback =
            (sender, cert, chain, errors) => SignalTrust.Validate(sender, cert, chain, errors);
        return new HttpClient(handler) { BaseAddress = new Uri(SignalServiceConfig.StorageUrl) };
    }

    /// <summary>The Basic authorization value for a group call: base64(hex(publicParams):hex(presentation)).</summary>
    public static string AuthHeader(byte[] groupPublicParams, byte[] authPresentation)
    {
        string user = Convert.ToHexString(groupPublicParams).ToLowerInvariant();
        string pass = Convert.ToHexString(authPresentation).ToLowerInvariant();
        return Convert.ToBase64String(Encoding.ASCII.GetBytes($"{user}:{pass}"));
    }

    /// <summary>GET /v2/groups/ — the current encrypted group state (decode with <see cref="GroupStateCodec"/>).</summary>
    public async Task<Group> GetGroupAsync(byte[] groupPublicParams, byte[] authPresentation, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/v2/groups/");
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader(groupPublicParams, authPresentation));
        using HttpResponseMessage resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        await EnsureOkAsync(resp).ConfigureAwait(false);
        byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return GroupResponse.Parser.ParseFrom(body).Group;
    }

    /// <summary>GET /v2/groups/logs/{fromRevision} — incremental changes from a known revision.</summary>
    public async Task<GroupChanges> GetGroupLogsAsync(byte[] groupPublicParams, byte[] authPresentation,
        uint fromRevision, uint maxSupportedChangeEpoch = 6, bool includeFirstState = true, CancellationToken ct = default)
    {
        string path = $"/v2/groups/logs/{fromRevision}?maxSupportedChangeEpoch={maxSupportedChangeEpoch}" +
                      $"&includeFirstState={includeFirstState.ToString().ToLowerInvariant()}&includeLastState=false";
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader(groupPublicParams, authPresentation));
        using HttpResponseMessage resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        await EnsureOkAsync(resp).ConfigureAwait(false);
        byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return GroupChanges.Parser.ParseFrom(body);
    }

    /// <summary>PATCH /v2/groups/ — apply a group change; returns the server's signed change + new state.</summary>
    public async Task<GroupChangeResponse> PatchGroupAsync(byte[] groupPublicParams, byte[] authPresentation,
        GroupChange.Types.Actions actions, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Patch, "/v2/groups/")
        {
            Content = new ByteArrayContent(actions.ToByteArray())
            { Headers = { ContentType = new MediaTypeHeaderValue("application/x-protobuf") } },
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", AuthHeader(groupPublicParams, authPresentation));
        using HttpResponseMessage resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        await EnsureOkAsync(resp).ConfigureAwait(false);
        byte[] body = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return GroupChangeResponse.Parser.ParseFrom(body);
    }

    private static async Task EnsureOkAsync(HttpResponseMessage resp)
    {
        if (resp.IsSuccessStatusCode) return;
        string reason = resp.StatusCode == HttpStatusCode.Forbidden
            ? " (403 — credential presentation rejected or not a member)" : "";
        string body = "";
        try { body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false); } catch { /* ignore */ }
        throw new GroupsApiException((int)resp.StatusCode, $"group storage request failed: {(int)resp.StatusCode}{reason} {body}");
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>A non-success response from the group storage service (403 = rejected presentation / not a member).</summary>
public sealed class GroupsApiException : Exception
{
    public int StatusCode { get; }
    public GroupsApiException(int statusCode, string message) : base(message) => StatusCode = statusCode;
}
