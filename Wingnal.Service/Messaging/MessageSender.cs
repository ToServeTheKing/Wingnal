using Google.Protobuf;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Ratchet;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Sends an unsealed (authenticated) 1:1 text. Fetches the recipient's prekey bundles, establishes a
/// PQXDH session per device (initiator/Alice — SPQR runs automatically), encrypts a padded
/// DataMessage, and PUTs the per-device ciphertexts to /v1/messages. To message your own account
/// ("Note to Self"), pass your own ACI as the destination; your own device is skipped.
/// </summary>
public sealed class MessageSender
{
    private readonly SignalAccount _account;
    private readonly ISignalProtocolStore _store;
    private readonly SignalRestClient _rest;
    private readonly Account.ProfileKeyStore? _profileKeys;
    private byte[]? _senderCertificate;   // cached delivery certificate (~24h)

    public MessageSender(SignalAccount account, ISignalProtocolStore store, SignalRestClient rest,
        Account.ProfileKeyStore? profileKeys = null)
    {
        _account = account;
        _store = store;
        _rest = rest;
        _profileKeys = profileKeys;
    }

    public sealed record SendResult(bool Ok, int DeviceCount, string Detail);

    // Sesame §3.3: if the recipient's device set changed (server 409 mismatched / 410 stale), re-fetch
    // the authoritative device list and retry, bounded to avoid looping on a malicious/buggy server.
    private const int MaxSendAttempts = 3;

    public async Task<SendResult> SendTextAsync(string destinationServiceId, string text, CancellationToken ct = default)
    {
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var dataMessage = new DataMessage { Body = text, Timestamp = (ulong)timestamp };
        var content = new Content { DataMessage = dataMessage };
        SendResult result = await SendContentAsync(destinationServiceId, content, timestamp, ct).ConfigureAwait(false);

        // Multi-device: after messaging someone else, sync a "Sent" transcript to our OWN account so the
        // user's other linked devices show the outgoing message. (Note-to-Self already reaches them, since
        // that send targets our other devices directly.) Best-effort — never fails the real send.
        if (result.Ok && !IsSelf(destinationServiceId))
            await TrySyncSentTranscriptAsync(destinationServiceId, dataMessage, timestamp, ct).ConfigureAwait(false);

        return result;
    }

    /// <summary>Builds the <see cref="Content"/> that syncs an outgoing message to our other devices: a
    /// <c>SyncMessage.Sent</c> carrying the destination, timestamp, and the exact DataMessage we sent.</summary>
    public static Content BuildSentTranscript(string destinationServiceId, DataMessage message, long timestamp)
    {
        var sent = new SyncMessage.Types.Sent
        {
            DestinationServiceId = destinationServiceId,
            Timestamp = (ulong)timestamp,
            Message = message,
        };
        sent.UnidentifiedStatus.Add(new SyncMessage.Types.Sent.Types.UnidentifiedDeliveryStatus
        {
            DestinationServiceId = destinationServiceId,
            Unidentified = false,
        });
        return new Content { SyncMessage = new SyncMessage { Sent = sent } };
    }

    private async Task TrySyncSentTranscriptAsync(string destinationServiceId, DataMessage message, long timestamp, CancellationToken ct)
    {
        try
        {
            Content transcript = BuildSentTranscript(destinationServiceId, message, timestamp);
            SendResult r = await SendContentAsync(_account.Aci, transcript, timestamp, ct).ConfigureAwait(false);
            FileLog.Write($"send: synced Sent transcript to self ok={r.Ok} detail={r.Detail}");
        }
        catch (Exception ex)
        {
            FileLog.Write($"send: Sent transcript sync FAILED {ex.GetType().Name}: {ex.Message}");
        }
    }

    private bool IsSelf(string serviceId) =>
        string.Equals(serviceId, _account.Aci, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Best-effort sealed-sender (metadata-minimized) delivery: if we know the recipient's profile key
    /// and can get a delivery certificate, re-wrap the already-built per-device ciphertexts as sealed
    /// envelopes and send them WITHOUT our auth credentials, using the recipient's unidentified-access
    /// key. Returns true only on success; ANY missing prerequisite or failure returns false so the
    /// caller falls back to the (working) authenticated send. The inner ciphertext is reused, so the
    /// ratchet is not advanced twice.
    /// </summary>
    private async Task<bool> TrySealedAsync(string destinationServiceId, OutgoingMessageList authList, CancellationToken ct)
    {
        try
        {
            if (_profileKeys is null || IsSelf(destinationServiceId)) return false;
            byte[]? profileKey = _profileKeys.Get(destinationServiceId);
            if (profileKey is null) return false;

            _senderCertificate ??= await _rest.GetSenderCertificateAsync(_account.BasicAuthToken(), ct).ConfigureAwait(false);
            byte[] accessKey = Wingnal.Service.Crypto.UnidentifiedAccess.DeriveAccessKey(profileKey);
            IdentityKeyPair ourIdentity = _account.AciIdentityKeyPair;

            var sealedMessages = new List<OutgoingMessage>(authList.Messages.Length);
            foreach (OutgoingMessage m in authList.Messages)
            {
                IdentityKey? theirIdentity = _store.GetIdentity(new SignalProtocolAddress(destinationServiceId, m.DestinationDeviceId));
                if (theirIdentity is null) return false;   // need their identity to seal

                byte[] inner = DecodeBase64(m.Content);
                int innerType = m.Type == 3 ? 1 : 2;        // PREKEY_MESSAGE / MESSAGE (sealed inner type)
                byte[] sealedBytes = SealedSenderDecryptor.EncryptWithCertificate(ourIdentity, theirIdentity, _senderCertificate, innerType, inner);
                sealedMessages.Add(new OutgoingMessage
                {
                    Type = 6,                               // UNIDENTIFIED_SENDER
                    DestinationDeviceId = m.DestinationDeviceId,
                    DestinationRegistrationId = m.DestinationRegistrationId,
                    Content = Convert.ToBase64String(sealedBytes),
                });
            }

            var sealedList = new OutgoingMessageList
            {
                Messages = sealedMessages.ToArray(),
                Timestamp = authList.Timestamp,
                Online = authList.Online,
                Urgent = authList.Urgent,
            };
            (bool ok, _, _) = await _rest.SendSealedMessagesAsync(destinationServiceId, sealedList, accessKey, ct).ConfigureAwait(false);
            return ok;
        }
        catch
        {
            return false;   // any problem → fall back to authenticated send (never regress)
        }
    }

    /// <summary>Sends our other devices a SyncMessage.Request for each of <paramref name="types"/> (a
    /// sync Content to our own ACI), asking the primary to push account state (contacts, blocked,
    /// configuration). GROUPS is intentionally omitted — it was removed from the sync protocol (groups
    /// now live in the storage service; see docs/GROUPS.md). Best-effort: returns the first failure.</summary>
    public async Task<SendResult> SendSyncRequestsAsync(IEnumerable<SyncMessage.Types.Request.Types.Type> types,
        CancellationToken ct = default)
    {
        SendResult last = new(true, 0, "no requests");
        foreach (SyncMessage.Types.Request.Types.Type type in types)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var content = new Content
            {
                SyncMessage = new SyncMessage { Request = new SyncMessage.Types.Request { Type = type } },
            };
            last = await SendContentAsync(_account.Aci, content, timestamp, ct).ConfigureAwait(false);
            if (!last.Ok) return last;
        }
        return last;
    }

    /// <summary>Encrypts a padded <see cref="Content"/> and sends it per-device (reuse-first, then
    /// fetch+establish on 409/410). The 1:1 text and sync-request paths both funnel through here.</summary>
    public async Task<SendResult> SendContentAsync(string destinationServiceId, Content content, long timestamp,
        CancellationToken ct = default)
    {
        byte[] padded = AddPadding(content.ToByteArray());
        string auth = _account.BasicAuthToken();

        // Reuse path (Sesame): if we already have sessions for this recipient's devices, encrypt with
        // them and send WITHOUT a /v2/keys fetch. Only fall back to fetching when there's no session
        // (first message) or the server reports the device set changed (409/410).
        OutgoingMessageList? reuse = BuildFromExistingSessions(destinationServiceId, padded, timestamp);
        if (reuse is { Messages.Length: > 0 })
        {
            if (await TrySealedAsync(destinationServiceId, reuse, ct).ConfigureAwait(false))
                return new SendResult(true, reuse.Messages.Length, $"sent sealed to {reuse.Messages.Length} device(s) (reused sessions)");
            (bool ok, var status, string body) = await _rest.SendMessagesAsync(destinationServiceId, reuse, auth, ct).ConfigureAwait(false);
            if (ok)
                return new SendResult(true, reuse.Messages.Length, $"sent to {reuse.Messages.Length} device(s) (reused sessions)");
            if (status is not (System.Net.HttpStatusCode.Conflict or System.Net.HttpStatusCode.Gone))
                return new SendResult(false, reuse.Messages.Length, $"{(int)status}: {body}");
            // device set changed — fall through to the fetch+establish path below.
        }

        for (int attempt = 1; attempt <= MaxSendAttempts; attempt++)
        {
            // "*" returns the recipient's current device set, so a re-fetch reconciles both missing
            // (added) and stale (removed/rotated) devices.
            PreKeyResponse bundles = await _rest.GetPreKeysAsync(destinationServiceId, "*", auth, ct).ConfigureAwait(false);

            OutgoingMessageList list = BuildOutgoingList(destinationServiceId, padded, bundles, timestamp);
            if (list.Messages.Length == 0)
                return new SendResult(false, 0, "no target devices (only our own device present)");

            if (await TrySealedAsync(destinationServiceId, list, ct).ConfigureAwait(false))
                return new SendResult(true, list.Messages.Length, $"sent sealed to {list.Messages.Length} device(s)");

            (bool ok, var status, string body) = await _rest.SendMessagesAsync(destinationServiceId, list, auth, ct).ConfigureAwait(false);
            if (ok)
                return new SendResult(true, list.Messages.Length, $"sent to {list.Messages.Length} device(s)");

            bool deviceSetChanged = status is System.Net.HttpStatusCode.Conflict or System.Net.HttpStatusCode.Gone;
            if (!deviceSetChanged || attempt == MaxSendAttempts)
                return new SendResult(false, list.Messages.Length, $"{(int)status}: {body}");
            // else: device set changed — loop to re-fetch and retry.
        }
        return new SendResult(false, 0, "device set kept changing after retries");
    }

    /// <summary>Pure (no network): encrypt a padded text DataMessage to every device in the bundle and
    /// build the per-device outgoing list. Exposed for offline testing.</summary>
    public OutgoingMessageList BuildOutgoingList(string destinationServiceId, string text, PreKeyResponse bundles, long timestamp)
    {
        var content = new Content { DataMessage = new DataMessage { Body = text, Timestamp = (ulong)timestamp } };
        return BuildOutgoingList(destinationServiceId, AddPadding(content.ToByteArray()), bundles, timestamp);
    }

    /// <summary>Encrypt already-padded Content bytes to every device in the bundle.</summary>
    public OutgoingMessageList BuildOutgoingList(string destinationServiceId, byte[] padded, PreKeyResponse bundles, long timestamp)
    {
        IdentityKey theirIdentity = IdentityKey.Decode(DecodeBase64(bundles.IdentityKey));
        var messages = new List<OutgoingMessage>();
        foreach (PreKeyResponseDevice dev in bundles.Devices)
        {
            // Skip our own device when messaging our own account (Note to Self).
            if (string.Equals(destinationServiceId, _account.Aci, StringComparison.OrdinalIgnoreCase)
                && dev.DeviceId == (uint)_account.DeviceId)
                continue;

            var address = new SignalProtocolAddress(destinationServiceId, dev.DeviceId);
            PreKeyBundle bundle = BuildBundle(theirIdentity, dev);

            new SessionBuilder(_store, _store, _store, _store, _store, address).Process(bundle);
            ICiphertextMessage cipher = new SessionCipher(_store, _store, _store, _store, _store, address).Encrypt(padded);

            int wireType = cipher.Type == CiphertextMessageType.PreKey ? 3 : 1;  // PREKEY_MESSAGE / DOUBLE_RATCHET
            messages.Add(new OutgoingMessage
            {
                Type = wireType,
                DestinationDeviceId = dev.DeviceId,
                DestinationRegistrationId = dev.RegistrationId,
                Content = Convert.ToBase64String(cipher.Serialize()),
            });
        }

        return new OutgoingMessageList
        {
            Messages = messages.ToArray(),
            Timestamp = timestamp,
            Online = false,
            Urgent = true,
        };
    }

    /// <summary>Encrypt to every device of <paramref name="destinationServiceId"/> that already has a
    /// session, reusing it (no prekey fetch). Returns null if there are no existing sessions. Public for
    /// offline testing.</summary>
    public OutgoingMessageList? BuildFromExistingSessions(string destinationServiceId, string text, long timestamp)
    {
        var content = new Content { DataMessage = new DataMessage { Body = text, Timestamp = (ulong)timestamp } };
        return BuildFromExistingSessions(destinationServiceId, AddPadding(content.ToByteArray()), timestamp);
    }

    /// <summary>Reuse existing sessions to encrypt already-padded Content bytes.</summary>
    public OutgoingMessageList? BuildFromExistingSessions(string destinationServiceId, byte[] padded, long timestamp)
    {
        IReadOnlyList<uint> deviceIds = _store.GetSubDeviceSessions(destinationServiceId);
        if (deviceIds.Count == 0) return null;

        var messages = new List<OutgoingMessage>();
        foreach (uint deviceId in deviceIds)
        {
            if (string.Equals(destinationServiceId, _account.Aci, StringComparison.OrdinalIgnoreCase)
                && deviceId == (uint)_account.DeviceId)
                continue;

            var address = new SignalProtocolAddress(destinationServiceId, deviceId);
            uint registrationId = _store.LoadSession(address).State.RemoteRegistrationId;
            ICiphertextMessage cipher = new SessionCipher(_store, _store, _store, _store, _store, address).Encrypt(padded);
            messages.Add(new OutgoingMessage
            {
                Type = cipher.Type == CiphertextMessageType.PreKey ? 3 : 1,
                DestinationDeviceId = deviceId,
                DestinationRegistrationId = registrationId,
                Content = Convert.ToBase64String(cipher.Serialize()),
            });
        }

        return new OutgoingMessageList
        {
            Messages = messages.ToArray(),
            Timestamp = timestamp,
            Online = false,
            Urgent = true,
        };
    }

    private static PreKeyBundle BuildBundle(IdentityKey theirIdentity, PreKeyResponseDevice dev)
    {
        byte[] signedPreKey = Curve25519.DecodePoint(DecodeBase64(dev.SignedPreKey.PublicKey));
        byte[]? preKey = dev.PreKey is { } pk ? Curve25519.DecodePoint(DecodeBase64(pk.PublicKey)) : null;
        byte[]? kyber = dev.PqPreKey is { } qk ? KemKeySerialization.Deserialize(DecodeBase64(qk.PublicKey)) : null;

        return new PreKeyBundle(
            registrationId: dev.RegistrationId,
            deviceId: dev.DeviceId,
            preKeyId: dev.PreKey?.KeyId,
            preKeyPublic: preKey,
            signedPreKeyId: dev.SignedPreKey.KeyId,
            signedPreKeyPublic: signedPreKey,
            signedPreKeySignature: DecodeBase64(dev.SignedPreKey.Signature),
            identityKey: theirIdentity,
            kyberPreKeyId: dev.PqPreKey?.KeyId,
            kyberPreKeyPublic: kyber,
            kyberPreKeySignature: dev.PqPreKey is { } q ? DecodeBase64(q.Signature) : null);
    }

    // Signal serializes keys/signatures as base64 (sometimes URL-safe and/or without padding).
    private static byte[] DecodeBase64(string s)
    {
        string t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    // Signal PushTransportDetails padding (shared with the group path + the receive-side strip).
    private static byte[] AddPadding(byte[] message) => MessagePadding.Add(message);
}
