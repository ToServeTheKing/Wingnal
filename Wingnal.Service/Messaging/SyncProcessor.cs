using Google.Protobuf;
using Wingnal.Service.Account;
using Wingnal.Service.Attachments;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Applies inbound <see cref="SyncMessage"/>s pushed by the primary device: downloads + imports the
/// contacts blob (SyncMessage.Contacts → <see cref="ContactsStore"/>) so the conversation list can show
/// names, and records read state (SyncMessage.Read). The contact-import mapping is factored into
/// <see cref="ImportContacts"/> so it can be tested offline without the CDN.
/// </summary>
public sealed class SyncProcessor
{
    private readonly ContactsStore _contacts;
    private readonly ProfileKeyStore? _profileKeys;
    private readonly AttachmentDownloader _downloader;

    /// <summary>Raised for each read receipt synced from the primary (senderAci, message timestamp).</summary>
    public event Action<string, long>? ReadReceiptReceived;

    public SyncProcessor(ContactsStore contacts, ProfileKeyStore? profileKeys = null,
        AttachmentDownloader? downloader = null)
    {
        _contacts = contacts;
        _profileKeys = profileKeys;
        _downloader = downloader ?? new AttachmentDownloader();
    }

    public async Task ProcessAsync(SyncMessage sync, CancellationToken ct = default)
    {
        if (sync.Contacts?.Blob is { } pointer)
        {
            try
            {
                byte[] blob = await _downloader.DownloadAsync(pointer, ct).ConfigureAwait(false);
                int n = ImportContacts(blob);
                FileLog.Write($"sync: imported {n} contact(s)");
            }
            catch (Exception ex)
            {
                FileLog.Write($"sync: contacts import failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        foreach (SyncMessage.Types.Read read in sync.Read)
        {
            string? aci = AciOf(read.SenderAci, read.SenderAciBinary);
            if (aci is not null)
                ReadReceiptReceived?.Invoke(aci, (long)read.Timestamp);
        }
    }

    /// <summary>Parses a decrypted contacts blob and upserts each contact. Returns the count. Pure
    /// (no network) — the offline-testable core of contacts sync.</summary>
    public int ImportContacts(byte[] blob)
    {
        int count = 0, keys = 0;
        foreach (ContactRecord record in ContactRecordStream.Parse(blob))
        {
            string? aci = AciOf(record.Details.Aci, record.Details.AciBinary);
            if (aci is null) continue;   // ACI-less contacts (e164-only) can't key a conversation yet

            string? name = string.IsNullOrWhiteSpace(record.Details.Name) ? null : record.Details.Name;
            string? number = string.IsNullOrWhiteSpace(record.Details.Number) ? null : record.Details.Number;
            _contacts.Upsert(new Contact(aci, number, name, (int)record.Details.InboxPosition));

            // Keep the contact's profile key so we can fetch + decrypt their profile name later, even
            // when the primary had no system-contact name for them (so the row isn't left as a raw ACI).
            if (_profileKeys is not null && record.Details.HasProfileKey)
            {
                byte[] pk = record.Details.ProfileKey.ToByteArray();
                if (pk.Length == 32) { _profileKeys.Store(aci, pk); keys++; }
            }
            count++;
        }
        FileLog.Write($"sync: imported {count} contact(s), {keys} profile key(s)");
        return count;
    }

    /// <summary>Prefers the string ACI; falls back to the 16-byte binary form. Returns lowercase
    /// canonical UUID, or null if neither is present/valid.</summary>
    private static string? AciOf(string asString, ByteString binary)
    {
        if (!string.IsNullOrEmpty(asString) && Guid.TryParse(asString, out Guid g))
            return g.ToString("D").ToLowerInvariant();
        return ServiceIds.StringFromBinary(binary.Span);
    }
}
