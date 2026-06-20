using Google.Protobuf;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Provisioning;

/// <summary>
/// Drives the secondary-device linking handshake over the provisioning WebSocket: receives the
/// provisioning address, surfaces a QR URI for the primary phone to scan, then awaits and decrypts
/// the <see cref="ProvisionMessage"/> the phone sends back.
/// </summary>
public sealed class ProvisioningManager
{
    private readonly ProvisioningCipher _cipher = new();

    /// <summary>
    /// Connects, invokes <paramref name="onQrReady"/> with the QR URI once the provisioning address
    /// arrives, then returns the decrypted provision message after the phone responds.
    /// </summary>
    /// <summary>libsignal/Signal-Desktop link+sync capability token advertised in the QR so the primary
    /// offers a message-history transfer archive (see docs/SYNC.md).</summary>
    public const string LinkAndSyncCapability = "backup5";

    public async Task<ProvisionMessage> LinkAsync(Func<string, Task> onQrReady, CancellationToken ct,
        IReadOnlyList<string>? capabilities = null)
    {
        using var socket = new SignalWebSocket();
        var uri = new Uri(SignalServiceConfig.WebSocketUrl + SignalServiceConfig.ProvisioningWebSocketPath);
        await socket.ConnectAsync(uri, headers: null, ct).ConfigureAwait(false);

        // Frame 1: server assigns this client a provisioning address.
        WebSocketRequestMessage addressRequest = await socket.ReadRequestAsync(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("provisioning socket closed before address");
        var address = ProvisioningUuid.Parser.ParseFrom(addressRequest.Body);
        await socket.SendResponseAsync(addressRequest.Id, 200, "OK", ct).ConfigureAwait(false);

        await onQrReady(BuildQrUri(address.Uuid, _cipher.PublicKey, capabilities)).ConfigureAwait(false);

        // Frame 2: the phone has scanned the QR and sent the encrypted provision message.
        WebSocketRequestMessage envelopeRequest = await socket.ReadRequestAsync(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException("provisioning socket closed before envelope");
        var envelope = ProvisionEnvelope.Parser.ParseFrom(envelopeRequest.Body);
        await socket.SendResponseAsync(envelopeRequest.Id, 200, "OK", ct).ConfigureAwait(false);

        return _cipher.Decrypt(envelope);
    }

    /// <summary>Builds the <c>sgnl://linkdevice</c> URI encoded into the linking QR code. Optional
    /// <paramref name="capabilities"/> are added as a comma-separated <c>capabilities</c> param (e.g.
    /// <see cref="LinkAndSyncCapability"/> to request message-history transfer).</summary>
    public static string BuildQrUri(string provisioningUuid, byte[] ephemeralPublicKey,
        IReadOnlyList<string>? capabilities = null)
    {
        string pubKey = Convert.ToBase64String(ephemeralPublicKey);
        string uri = $"sgnl://linkdevice?uuid={Uri.EscapeDataString(provisioningUuid)}&pub_key={Uri.EscapeDataString(pubKey)}";
        if (capabilities is { Count: > 0 })
            uri += $"&capabilities={Uri.EscapeDataString(string.Join(',', capabilities))}";
        return uri;
    }
}
