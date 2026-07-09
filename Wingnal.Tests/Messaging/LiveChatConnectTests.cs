using Wingnal.Service.Account;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Messaging;
using Xunit;
using Xunit.Abstractions;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Live diagnostic: loads the persisted account and connects the authenticated chat socket for a few
/// seconds, letting ChatReceiver log connect/frames/close to wingnal.log. Skipped by default because it
/// logs in as the real account — which disconnects the running app ("Connected elsewhere") and spams its
/// log. To run it manually, remove the Skip below. Requires a linked account on this machine.
/// </summary>
[Trait("Category", "Live")]
public class LiveChatConnectTests
{
    private readonly ITestOutputHelper _output;
    public LiveChatConnectTests(ITestOutputHelper output) => _output = output;

    [Fact(Skip = "Live diagnostic — connects as the real account. Remove this Skip to run manually.")]
    public async Task ConnectsAuthenticatedSocket_AndLogs()
    {
        // The packaged WinUI app redirects LocalApplicationData into its package container.
        string packagedDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Packages", "cdb9e5d5-57cc-4e6a-954d-85bc9da6892e_cnsc1k9bd01st", "LocalCache", "Local", "Wingnal");

        var accountStore = new AccountStore(Directory.Exists(packagedDir) ? packagedDir : null);
        SignalAccount? account = accountStore.Load();
        if (account is null)
        {
            _output.WriteLine($"no linked account found (looked in {packagedDir}); skipping");
            return;
        }
        _output.WriteLine($"loaded account aci={account.Aci} device={account.DeviceId}");

        FileLog.Write("=== LiveChatConnectTests starting ===");
        var store = new AccountProtocolStore(account);
        var receiver = new ChatReceiver(account, store);

        var received = new List<DecryptedMessage>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await receiver.ReceiveAsync(
                m => { received.Add(m); return Task.CompletedTask; },
                (_, _) => { },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
        }

        _output.WriteLine($"received {received.Count} text message(s); see {FileLog.LogPath}");
    }
}
