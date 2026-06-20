using System.Net.WebSockets;
using Google.Protobuf;
using Wingnal.Service.Protos;

namespace Wingnal.Service.Net;

/// <summary>
/// Wraps a <see cref="ClientWebSocket"/> with Signal's request/response framing: every binary frame
/// is a <see cref="WebSocketMessage"/>. Incoming REQUEST frames are surfaced to the caller; the
/// caller answers them with <see cref="SendResponseAsync"/>.
/// </summary>
public sealed class SignalWebSocket : IDisposable
{
    private readonly ClientWebSocket _socket = new();
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    public async Task ConnectAsync(Uri uri, IReadOnlyDictionary<string, string>? headers, CancellationToken ct)
    {
        _socket.Options.AddSubProtocol("binary");
        _socket.Options.RemoteCertificateValidationCallback = SignalTrust.Validate;
        _socket.Options.SetRequestHeader("X-Signal-Agent", SignalServiceConfig.UserAgent);
        if (headers is not null)
            foreach ((string name, string value) in headers)
                _socket.Options.SetRequestHeader(name, value);

        await _socket.ConnectAsync(uri, ct).ConfigureAwait(false);
    }

    /// <summary>Reads the next inbound REQUEST frame, or null if the socket closed.</summary>
    public async Task<WebSocketRequestMessage?> ReadRequestAsync(CancellationToken ct)
    {
        while (true)
        {
            WebSocketMessage? message = await ReadMessageAsync(ct).ConfigureAwait(false);
            if (message is null)
                return null;
            if (message.Type == WebSocketMessage.Types.Type.Request && message.Request is not null)
                return message.Request;
            // RESPONSE / keepalive frames are ignored for the provisioning flow.
        }
    }

    public Task SendResponseAsync(ulong id, uint status, string message, CancellationToken ct)
    {
        var frame = new WebSocketMessage
        {
            Type = WebSocketMessage.Types.Type.Response,
            Response = new WebSocketResponseMessage { Id = id, Status = status, Message = message },
        };
        return SendMessageAsync(frame, ct);
    }

    /// <summary>Sends a keepalive request (GET /v1/keepalive) to keep the server from dropping us.</summary>
    public Task SendKeepAliveAsync(ulong id, CancellationToken ct)
    {
        var frame = new WebSocketMessage
        {
            Type = WebSocketMessage.Types.Type.Request,
            Request = new WebSocketRequestMessage { Id = id, Verb = "GET", Path = "/v1/keepalive" },
        };
        return SendMessageAsync(frame, ct);
    }

    /// <summary>Describes why the last read ended (close status/description, or the live socket state).</summary>
    public string CloseReason =>
        $"state={_socket.State} status={_socket.CloseStatus} desc={_socket.CloseStatusDescription}";

    private async Task<WebSocketMessage?> ReadMessageAsync(CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        WebSocketReceiveResult result;
        do
        {
            result = await _socket.ReceiveAsync(chunk, ct).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
                return null;
            buffer.Write(chunk, 0, result.Count);
        }
        while (!result.EndOfMessage);

        return WebSocketMessage.Parser.ParseFrom(buffer.ToArray());
    }

    private async Task SendMessageAsync(WebSocketMessage message, CancellationToken ct)
    {
        byte[] bytes = message.ToByteArray();
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _socket.SendAsync(bytes, WebSocketMessageType.Binary, endOfMessage: true, ct).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
        _sendLock.Dispose();
    }
}
