using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Connects the authenticated chat WebSocket and delivers incoming 1:1 texts. The server pushes
/// queued messages as PUT /api/v1/message (Envelope body); we ack each with 200 and answer
/// keepalives. Decryption failures are surfaced via <paramref name="onError"/> but still acked so the
/// queue drains (see SHORTCUTS.md).
/// </summary>
public sealed class ChatReceiver
{
    private readonly SignalAccount _account;
    private readonly MessageDecryptor _decryptor;

    public ChatReceiver(SignalAccount account, ISignalProtocolStore store,
        Account.ProfileKeyStore? profileKeys = null, ISenderKeyStore? senderKeys = null)
    {
        _account = account;
        _decryptor = new MessageDecryptor(store, profileKeys, senderKeys);
    }

    public async Task ReceiveAsync(
        Func<DecryptedMessage, Task> onMessage,
        Action<Envelope, Exception>? onError,
        CancellationToken ct,
        Func<SyncMessage, Task>? onSync = null,
        Func<string, ReceiptMessage, Task>? onReceipt = null,
        Func<string, TypingMessage, Task>? onTyping = null)
    {
        using var socket = new SignalWebSocket();
        var uri = new Uri($"{SignalServiceConfig.WebSocketUrl}{SignalServiceConfig.ChatWebSocketPath}");
        var headers = new Dictionary<string, string> { ["Authorization"] = $"Basic {_account.BasicAuthToken()}" };

        FileLog.Write($"chat: connecting login={_account.Aci}.{_account.DeviceId} (Authorization header)");
        try
        {
            await socket.ConnectAsync(uri, headers, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            FileLog.Write($"chat: CONNECT FAILED {ex.GetType().Name}: {ex.Message}");
            throw;
        }
        FileLog.Write("chat: connected (websocket upgrade OK)");

        using var loopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task keepAlive = KeepAliveLoopAsync(socket, loopCts.Token);

        int frames = 0;
        while (!ct.IsCancellationRequested)
        {
            WebSocketRequestMessage? request = await socket.ReadRequestAsync(ct).ConfigureAwait(false);
            if (request is null)
            {
                FileLog.Write($"chat: socket closed after {frames} frame(s). {socket.CloseReason}");
                break;
            }

            frames++;
            bool isMessage = request.Verb == "PUT" && request.Path == "/api/v1/message";
            FileLog.Write($"chat: frame #{frames} verb={request.Verb} path={request.Path} bodyLen={request.Body?.Length ?? 0}");

            if (!isMessage)
            {
                // keepalive, queue-empty, etc. — ack immediately.
                await socket.SendResponseAsync(request.Id, 200, "OK", ct).ConfigureAwait(false);
                continue;
            }

            Envelope envelope = Envelope.Parser.ParseFrom(request.Body);
            FileLog.Write($"chat: envelope type={envelope.Type} from={envelope.SourceServiceId}.{envelope.SourceDeviceId} contentLen={envelope.Content?.Length ?? 0}");
            try
            {
                MessageDecryptor.Result result = _decryptor.DecryptEnvelope(envelope);
                // Ack only after a successful decrypt, so a message we can't yet handle is redelivered.
                await socket.SendResponseAsync(request.Id, 200, "OK", ct).ConfigureAwait(false);

                if (result.Message is { } message)
                {
                    FileLog.Write($"chat: decrypted text from {message.PeerServiceId} outgoing={message.Outgoing}");
                    await onMessage(message).ConfigureAwait(false);
                }

                if (onSync is not null && result.Content?.SyncMessage is { } sync)
                {
                    FileLog.Write("chat: handling sync message");
                    await onSync(sync).ConfigureAwait(false);
                }

                if (onReceipt is not null && result.Content?.ReceiptMessage is { } receipt)
                {
                    FileLog.Write($"chat: {receipt.Type} receipt from {result.Sender} for {receipt.Timestamp.Count} message(s)");
                    await onReceipt(result.Sender, receipt).ConfigureAwait(false);
                }

                if (onTyping is not null && result.Content?.TypingMessage is { } typing)
                {
                    FileLog.Write($"chat: typing {typing.Action} from {result.Sender}");
                    await onTyping(result.Sender, typing).ConfigureAwait(false);
                }

                if (result.Message is null && result.Content is null)
                    FileLog.Write($"chat: decrypted, nothing surfaced (type={envelope.Type})");
            }
            catch (Exception ex)
            {
                FileLog.Dump($"failed-envelope-{frames}.bin", request.Body!.ToByteArray());
                FileLog.Write($"chat: DECRYPT FAILED type={envelope.Type} (not acked, will redeliver):{Environment.NewLine}{ex}");
                onError?.Invoke(envelope, ex);
            }
        }

        loopCts.Cancel();
        try { await keepAlive.ConfigureAwait(false); } catch (OperationCanceledException) { }
    }

    private static async Task KeepAliveLoopAsync(SignalWebSocket socket, CancellationToken ct)
    {
        ulong id = 1;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                await socket.SendKeepAliveAsync(id++, ct).ConfigureAwait(false);
                FileLog.Write("chat: sent keepalive");
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { FileLog.Write($"chat: keepalive stopped: {ex.GetType().Name}: {ex.Message}"); }
    }
}
