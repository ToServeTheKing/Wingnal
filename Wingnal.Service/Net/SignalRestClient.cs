using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Wingnal.Service.Net;

/// <summary>Thin typed HTTP client for the Signal account/keys/messages REST API.</summary>
public sealed class SignalRestClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _http;

    public SignalRestClient(HttpClient? http = null)
    {
        _http = http ?? CreatePinnedClient();
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(SignalServiceConfig.UserAgent);
        _http.DefaultRequestHeaders.Add("X-Signal-Agent", SignalServiceConfig.UserAgent);
    }

    private static HttpClient CreatePinnedClient()
    {
        var handler = new SocketsHttpHandler();
        handler.SslOptions.RemoteCertificateValidationCallback =
            (sender, cert, chain, errors) => SignalTrust.Validate(sender, cert, chain, errors);
        return new HttpClient(handler) { BaseAddress = new Uri(SignalServiceConfig.ServiceUrl) };
    }

    /// <summary>
    /// Registers this client as a new secondary device. Authenticates with Basic(number:password)
    /// using the password this device generated; returns the assigned aci/pni/deviceId.
    /// </summary>
    public async Task<LinkDeviceResponse> LinkDeviceAsync(
        string number, string password, LinkDeviceRequest request, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Put, "/v1/devices/link")
        {
            Content = JsonContent.Create(request),
        };
        string token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{number}:{password}"));
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", token);

        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException(
                $"device link failed: {(int)response.StatusCode} {response.ReasonPhrase} {body}");
        }

        return await response.Content.ReadFromJsonAsync<LinkDeviceResponse>(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("empty link response");
    }

    /// <summary>Fetches prekey bundles for a recipient. <paramref name="deviceId"/> may be "*" for all
    /// of the recipient's devices. <paramref name="authToken"/> is Basic {aci.deviceId:password}.</summary>
    public async Task<PreKeyResponse> GetPreKeysAsync(string serviceId, string deviceId, string authToken, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Get, $"/v2/keys/{serviceId}/{deviceId}");
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException($"get prekeys failed: {(int)response.StatusCode} {response.ReasonPhrase} {body}");
        }
        return await response.Content.ReadFromJsonAsync<PreKeyResponse>(Json, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("empty prekey response");
    }

    /// <summary>Sends a list of per-device encrypted messages to a destination. Returns the raw body on
    /// a device-mismatch (409) / stale-devices (410) so the caller can react; throws on other failures.</summary>
    public async Task<(bool Ok, HttpStatusCode Status, string Body)> SendMessagesAsync(
        string serviceId, OutgoingMessageList messages, string authToken, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Put, $"/v1/messages/{serviceId}")
        {
            Content = JsonContent.Create(messages, options: Json),
        };
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.Gone)
            return (false, response.StatusCode, body);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"send failed: {(int)response.StatusCode} {response.ReasonPhrase} {body}");
        return (true, response.StatusCode, body);
    }

    /// <summary>Uploads prekeys for an identity (PUT /v2/keys?identity={aci|pni}). Used to register
    /// one-time prekeys after linking. <paramref name="authToken"/> is Basic {aci.deviceId:password}.</summary>
    public async Task UploadPreKeysAsync(string identity, SetKeysRequest request, string authToken, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Put, $"/v2/keys?identity={identity}")
        {
            Content = JsonContent.Create(request, options: Json),
        };
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException($"upload prekeys failed: {(int)response.StatusCode} {response.ReasonPhrase} {body}");
        }
    }

    /// <summary>
    /// Long-polls <c>GET /v1/devices/transfer_archive</c> for the link'n'sync message-history archive
    /// the primary uploads after linking. Returns the descriptor (cdn/key, or an error), or null on a
    /// 204 timeout (poll again). Auth: Basic {aci.deviceId:password}. SCAFFOLD — see docs/SYNC.md; the
    /// download+import side isn't built yet.
    /// </summary>
    public async Task<TransferArchiveDescriptor?> WaitForTransferArchiveAsync(string authToken, int timeoutSeconds, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Get, $"/v1/devices/transfer_archive?timeout={timeoutSeconds}");
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NoContent)
            return null; // long-poll elapsed with no archive yet
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException($"wait transfer archive failed: {(int)response.StatusCode} {response.ReasonPhrase} {body}");
        }
        return await response.Content.ReadFromJsonAsync<TransferArchiveDescriptor>(Json, ct).ConfigureAwait(false);
    }

    /// <summary>Fetches a sealed-sender delivery certificate (GET /v1/certificate/delivery). Returns the
    /// raw SenderCertificate bytes, valid ~24h; callers should cache it.</summary>
    public async Task<byte[]> GetSenderCertificateAsync(string authToken, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Get, "/v1/certificate/delivery");
        msg.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new HttpRequestException($"get delivery certificate failed: {(int)response.StatusCode} {body}");
        }
        var dto = await response.Content.ReadFromJsonAsync<DeliveryCertificateDto>(Json, ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("empty certificate response");
        return Convert.FromBase64String(dto.Certificate ?? throw new InvalidOperationException("no certificate"));
    }

    /// <summary>Sends sealed-sender messages: NO account auth, just the recipient's unidentified-access
    /// key header. Metadata-minimized. Returns the same (ok/status/body) shape as the authenticated send
    /// so callers can fall back on rejection.</summary>
    public async Task<(bool Ok, HttpStatusCode Status, string Body)> SendSealedMessagesAsync(
        string serviceId, OutgoingMessageList messages, byte[] accessKey, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Put, $"/v1/messages/{serviceId}")
        {
            Content = JsonContent.Create(messages, options: Json),
        };
        msg.Headers.Add("Unidentified-Access-Key", Convert.ToBase64String(accessKey));
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return (response.IsSuccessStatusCode, response.StatusCode, body);
    }

    private sealed class DeliveryCertificateDto { public string? Certificate { get; set; } }

    public void Dispose() => _http.Dispose();
}
