using Wingnal.Service.Diagnostics;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Attachments;

/// <summary>
/// Downloads + decrypts an inbound <see cref="AttachmentPointer"/> and saves the plaintext to a local
/// media file, returning its path (for the chat UI to show/open). Best-effort: returns null on any
/// failure so a missing/expired attachment never breaks message display. Reuses the tested
/// <see cref="AttachmentDownloader"/> (CDN GET) + <see cref="AttachmentCipher"/> (AES-CBC + HMAC + digest).
/// </summary>
public sealed class AttachmentService
{
    private readonly string _mediaDir;

    public AttachmentService(string? mediaDir = null)
    {
        _mediaDir = mediaDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal", "media");
        Directory.CreateDirectory(_mediaDir);
    }

    public async Task<string?> SaveAsync(AttachmentPointer pointer, CancellationToken ct = default)
    {
        try
        {
            using var downloader = new AttachmentDownloader();
            byte[] plaintext = await downloader.DownloadAsync(pointer, ct).ConfigureAwait(false);
            string path = Path.Combine(_mediaDir, FileNameFor(pointer));
            await File.WriteAllBytesAsync(path, plaintext, ct).ConfigureAwait(false);
            return path;
        }
        catch (Exception ex)
        {
            FileLog.Write($"attachment: download failed: {ex.GetType().Name}: {ex.Message}");
            return null;   // show the placeholder; don't break the message
        }
    }

    /// <summary>Writes pre-decrypted bytes to the media folder (test/local helper); returns the path.</summary>
    public string Save(byte[] plaintext, string extension)
    {
        string path = Path.Combine(_mediaDir, Guid.NewGuid().ToString("N") + Normalize(extension));
        File.WriteAllBytes(path, plaintext);
        return path;
    }

    private string FileNameFor(AttachmentPointer p)
    {
        string ext = !string.IsNullOrEmpty(p.FileName) && Path.HasExtension(p.FileName)
            ? Path.GetExtension(p.FileName)
            : ExtensionForContentType(p.ContentType);
        return Guid.NewGuid().ToString("N") + ext;
    }

    private static string ExtensionForContentType(string? contentType) => contentType switch
    {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "video/mp4" => ".mp4",
        "audio/aac" or "audio/mp4" => ".m4a",
        _ => ".bin",
    };

    private static string Normalize(string ext) => ext.StartsWith('.') ? ext : "." + ext;
}
