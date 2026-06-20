using System.Net.Http.Headers;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Attachments;

/// <summary>
/// Downloads an <see cref="AttachmentPointer"/> from the Signal CDN and decrypts it. The download is
/// GET <c>{cdnUrl}/attachments/{cdnKey|cdnId}</c>; decryption is <see cref="AttachmentCipher"/>
/// (AES-256-CBC + HMAC-SHA256 + whole-blob SHA-256 digest). Used for contact/group sync blobs now and
/// media later.
/// </summary>
public sealed class AttachmentDownloader : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    /// <param name="http">Optional shared client. If null, a cert-pinned client is created (see
    /// SHORTCUTS.md re: CDN cert pinning). Auth: the CDN serves attachments without account auth.</param>
    public AttachmentDownloader(HttpClient? http = null)
    {
        if (http is null)
        {
            var handler = new SocketsHttpHandler();
            handler.SslOptions.RemoteCertificateValidationCallback =
                (sender, cert, chain, errors) => SignalTrust.Validate(sender, cert, chain, errors);
            _http = new HttpClient(handler);
            _ownsClient = true;
        }
        else
        {
            _http = http;
        }
        _http.DefaultRequestHeaders.UserAgent.TryParseAdd(SignalServiceConfig.UserAgent);
    }

    /// <summary>Downloads + decrypts the attachment, returning the plaintext bytes.</summary>
    public async Task<byte[]> DownloadAsync(AttachmentPointer pointer, CancellationToken ct = default)
    {
        if (pointer.Key is null || pointer.Key.Length != 64)
            throw new InvalidAttachmentException("attachment pointer has no/invalid 64-byte key");

        string location = LocationFor(pointer);
        string url = $"{SignalServiceConfig.CdnUrl(pointer.CdnNumber)}/attachments/{location}";

        using var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"attachment download failed: {(int)response.StatusCode} {response.ReasonPhrase}");

        byte[] blob = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        byte[]? digest = pointer.HasDigest ? pointer.Digest.ToByteArray() : null;
        int? size = pointer.HasSize ? (int)pointer.Size : null;
        return AttachmentCipher.Decrypt(blob, pointer.Key.ToByteArray(), digest, size);
    }

    /// <summary>Raw CDN GET (no attachment decryption) for a cdn-number + object key — used for the
    /// link'n'sync transfer archive, which is decrypted by <c>BackupReader</c> with a MessageBackupKey
    /// rather than an attachment key.</summary>
    public async Task<byte[]> DownloadRawAsync(uint cdnNumber, string cdnKey, CancellationToken ct = default)
    {
        string url = $"{SignalServiceConfig.CdnUrl(cdnNumber)}/attachments/{cdnKey}";
        using var msg = new HttpRequestMessage(HttpMethod.Get, url);
        msg.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using HttpResponseMessage response = await _http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"archive download failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    private static string LocationFor(AttachmentPointer pointer)
    {
        // cdn2/cdn3 use a string cdnKey; the legacy cdn0 uses a numeric cdnId.
        if (pointer.AttachmentIdentifierCase == AttachmentPointer.AttachmentIdentifierOneofCase.CdnKey)
            return pointer.CdnKey;
        if (pointer.AttachmentIdentifierCase == AttachmentPointer.AttachmentIdentifierOneofCase.CdnId)
            return pointer.CdnId.ToString();
        throw new InvalidAttachmentException("attachment pointer has no cdn id/key");
    }

    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }
}
