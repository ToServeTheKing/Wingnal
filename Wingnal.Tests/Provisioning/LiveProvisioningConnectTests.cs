using Wingnal.Service.Net;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Provisioning;

/// <summary>
/// Live connectivity test against chat.signal.org. Excluded from the default run (hits the network);
/// run explicitly: dotnet test --filter "Category=Live". Proves the pinned Signal CA lets the TLS
/// handshake + provisioning WebSocket upgrade succeed and that we receive the provisioning address.
/// </summary>
[Trait("Category", "Live")]
public class LiveProvisioningConnectTests
{
    [Fact]
    public async Task ProvisioningSocket_Connects_AndReceivesUuid()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var socket = new SignalWebSocket();
        var uri = new Uri(SignalServiceConfig.WebSocketUrl + SignalServiceConfig.ProvisioningWebSocketPath);

        await socket.ConnectAsync(uri, headers: null, cts.Token);

        WebSocketRequestMessage? request = await socket.ReadRequestAsync(cts.Token);
        Assert.NotNull(request);

        var address = ProvisioningUuid.Parser.ParseFrom(request!.Body);
        Assert.False(string.IsNullOrEmpty(address.Uuid));
    }
}
