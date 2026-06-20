using Wingnal.Service.Account;
using Wingnal.Service.Attachments;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Messaging;
using Wingnal.Service.Net;

namespace Wingnal.Service.Sync;

/// <summary>
/// Link'n'sync message-history backfill. After a re-link where the primary offered link+sync, the
/// account carries a one-time <c>EphemeralBackupKey</c>. This:
/// <list type="number">
/// <item>long-polls <c>GET /v1/devices/transfer_archive</c> for the descriptor the primary uploads;</item>
/// <item>downloads the encrypted archive from the CDN;</item>
/// <item>derives the <see cref="MessageBackupKey"/> (ephemeralBackupKey + our ACI);</item>
/// <item>decrypts + decompresses + parses it (<see cref="BackupReader"/>); and</item>
/// <item>imports it into the contact/message stores (<see cref="BackupImporter"/>).</item>
/// </list>
/// The crypto + parse + import core is offline-tested; the poll/download is live-only. See docs/SYNC.md.
/// </summary>
public sealed class MessageHistoryImporter
{
    private readonly SignalAccount _account;
    private readonly SignalRestClient _rest;
    private readonly MessageStore _messages;
    private readonly ContactsStore _contacts;

    public MessageHistoryImporter(SignalAccount account, SignalRestClient rest, MessageStore messages, ContactsStore contacts)
    {
        _account = account;
        _rest = rest;
        _messages = messages;
        _contacts = contacts;
    }

    /// <param name="ShouldRetry">True when the failure was transient (timed out / network / parse error)
    /// so the caller should KEEP the ephemeral key and retry on the next launch, rather than losing the
    /// one-time chance at history. False when done (imported) or the primary definitively has no archive.</param>
    public sealed record Result(bool Imported, BackupImporter.ImportSummary? Summary, string Detail, bool ShouldRetry = false);

    /// <summary>Returns whether a backfill is even possible (the primary offered link+sync at link).</summary>
    public bool IsAvailable => _account.EphemeralBackupKey is { Length: 32 };

    /// <summary>
    /// Runs the backfill once. Polls up to <paramref name="maxPolls"/> times (each a long-poll of
    /// <paramref name="pollTimeoutSeconds"/>). Returns the import summary; the caller should clear
    /// <see cref="SignalAccount.EphemeralBackupKey"/> and persist on success so it doesn't re-run.
    /// </summary>
    public async Task<Result> ImportAsync(int maxPolls = 12, int pollTimeoutSeconds = 30, CancellationToken ct = default)
    {
        if (_account.EphemeralBackupKey is not { Length: 32 } ephemeral)
            return new Result(false, null, "no ephemeral backup key (link+sync not offered)");
        if (!Guid.TryParse(_account.Aci, out Guid aci))
            return new Result(false, null, "account ACI is not a valid UUID");

        string auth = _account.BasicAuthToken();
        TransferArchiveDescriptor? descriptor = null;
        try
        {
            for (int i = 0; i < maxPolls && descriptor is null; i++)
                descriptor = await _rest.WaitForTransferArchiveAsync(auth, pollTimeoutSeconds, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Network hiccup while polling — keep the key and try again next launch.
            FileLog.Write($"link'n'sync: poll failed (will retry): {ex.GetType().Name}: {ex.Message}");
            return new Result(false, null, "transfer archive poll failed", ShouldRetry: true);
        }

        if (descriptor is null)
            return new Result(false, null, "transfer archive not available (timed out)", ShouldRetry: true);
        if (descriptor.IsError || string.IsNullOrEmpty(descriptor.Key))
            return new Result(false, null, $"primary reported no archive: {descriptor.Error}", ShouldRetry: false);

        try
        {
            using var downloader = new AttachmentDownloader();
            byte[] file = await downloader.DownloadRawAsync((uint)descriptor.Cdn, descriptor.Key!, ct).ConfigureAwait(false);

            MessageBackupKey key = BackupKey.ForLinkAndSync(ephemeral, aci);
            BackupContents backup = BackupReader.Read(file, key);
            BackupImporter.ImportSummary summary = new BackupImporter(_messages, _contacts, _account.Aci).Import(backup);

            FileLog.Write($"link'n'sync: imported {summary.Messages} message(s), {summary.Contacts} contact(s)");
            return new Result(true, summary, $"imported {summary.Messages} messages, {summary.Contacts} contacts");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Download/decrypt/parse failed — keep the key so a later launch can retry the (still-valid) archive.
            FileLog.Write($"link'n'sync: download/import failed (will retry): {ex.GetType().Name}: {ex.Message}");
            return new Result(false, null, $"history import failed: {ex.Message}", ShouldRetry: true);
        }
    }
}
