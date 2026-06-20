using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Wingnal.Service.Net;
using Xunit;
using Xunit.Abstractions;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Live send: loads the persisted account and sends a 1:1 text over the real Signal network. Gated by
/// the WINGNAL_SEND_TO env var (the destination ACI) so it never transmits by accident; set it to your
/// own ACI to message Note to Self. Optional WINGNAL_SEND_TEXT overrides the body. Excluded from default
/// runs. Run: $env:WINGNAL_SEND_TO="&lt;aci&gt;"; dotnet test --filter "Category=Live".
/// </summary>
[Trait("Category", "Live")]
public class SendLiveTests
{
    private readonly ITestOutputHelper _o;
    public SendLiveTests(ITestOutputHelper o) => _o = o;

    [Fact]
    public async Task SendsTextToConfiguredDestination()
    {
        string? dest = Environment.GetEnvironmentVariable("WINGNAL_SEND_TO");
        if (string.IsNullOrWhiteSpace(dest)) { _o.WriteLine("WINGNAL_SEND_TO not set; skipping live send"); return; }
        string text = Environment.GetEnvironmentVariable("WINGNAL_SEND_TEXT") ?? "Hello from Wingnal 🐦";

        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Packages", "cdb9e5d5-57cc-4e6a-954d-85bc9da6892e_cnsc1k9bd01st", "LocalCache", "Local", "Wingnal");
        SignalAccount? account = new AccountStore(Directory.Exists(dir) ? dir : null).Load();
        if (account is null) { _o.WriteLine("no linked account; skipping"); return; }

        var store = new AccountProtocolStore(account);
        using var rest = new SignalRestClient();
        var sender = new MessageSender(account, store, rest);

        _o.WriteLine($"sending \"{text}\" to {dest} ...");
        MessageSender.SendResult result = await sender.SendTextAsync(dest, text);
        _o.WriteLine($"result: ok={result.Ok} devices={result.DeviceCount} detail={result.Detail}");
        Assert.True(result.Ok, $"send failed: {result.Detail}");
    }
}
