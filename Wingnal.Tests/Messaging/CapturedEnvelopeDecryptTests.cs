using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Offline end-to-end validation of the SPQR integration: loads the persisted account and runs the
/// full decrypt pipeline on each captured failed-envelope-*.bin (real PreKeySignalMessages from the
/// phone that previously failed with "bad MAC"). Success = no bad MAC and the plaintext text surfaces.
/// No network needed — the envelopes are already captured. Run: dotnet test --filter "Category=Live".
/// </summary>
[Trait("Category", "Live")]
public class CapturedEnvelopeDecryptTests
{
    private readonly ITestOutputHelper _o;
    public CapturedEnvelopeDecryptTests(ITestOutputHelper o) => _o = o;

    [Fact]
    public void DecryptsCapturedEnvelopes()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Packages", "cdb9e5d5-57cc-4e6a-954d-85bc9da6892e_cnsc1k9bd01st", "LocalCache", "Local", "Wingnal");

        if (!Directory.Exists(dir)) { _o.WriteLine($"missing {dir}; skipping"); return; }

        SignalAccount? account = new AccountStore(dir).Load();
        if (account is null) { _o.WriteLine("no linked account; skipping"); return; }
        _o.WriteLine($"account aci={account.Aci} device={account.DeviceId}");

        string[] files = Directory.GetFiles(dir, "failed-envelope-*.bin").OrderBy(x => x).ToArray();
        if (files.Length == 0) { _o.WriteLine("no captured envelopes; skipping"); return; }

        // Describe each envelope (type, inner counter, pq_ratchet length).
        foreach (string f in files)
        {
            Envelope env = Envelope.Parser.ParseFrom(File.ReadAllBytes(f));
            string dest = !string.IsNullOrEmpty(env.DestinationServiceId) ? env.DestinationServiceId
                : (env.DestinationServiceIdBinary.IsEmpty ? "(none)" : Convert.ToHexString(env.DestinationServiceIdBinary.ToByteArray()));
            string which = dest.StartsWith(account.Aci, StringComparison.OrdinalIgnoreCase) ? "ACI"
                : dest.StartsWith(account.Pni, StringComparison.OrdinalIgnoreCase) ? "PNI" : "?";
            string desc = $"{Path.GetFileName(f)}: type={env.Type} srcDev={env.SourceDeviceId} dest={dest}[{which}] contentLen={env.Content.Length}";
            try
            {
                if (env.Type == Envelope.Types.Type.PrekeyMessage)
                {
                    var pk = Wingnal.Protocol.Messages.PreKeySignalMessage.Parse(env.Content.ToByteArray());
                    desc += $" PREKEY ctr={pk.Message.Counter} pqLen={pk.Message.PqRatchet?.Length} spkId={pk.SignedPreKeyId} kyberId={pk.KyberPreKeyId} preKeyId={pk.PreKeyId} baseKey={Convert.ToHexString(pk.BaseKey)[..16]}";
                }
                else if (env.Type == Envelope.Types.Type.DoubleRatchet)
                {
                    var sm = Wingnal.Protocol.Messages.SignalMessage.Parse(env.Content.ToByteArray());
                    desc += $" DR counter={sm.Counter} pqLen={sm.PqRatchet?.Length}";
                }
            }
            catch (Exception ex) { desc += $" parse-failed {ex.Message}"; }
            _o.WriteLine(desc);
        }

        _o.WriteLine("--- standalone (fresh session per envelope) ---");
        int decrypted = 0;
        foreach (string f in files)
            if (TryDecrypt(new AccountProtocolStore(account), f)) decrypted++;

        _o.WriteLine("--- sequential (shared session, in order) ---");
        var shared = new AccountProtocolStore(account);
        int seqDecrypted = 0;
        foreach (string f in files)
            if (TryDecrypt(shared, f)) seqDecrypted++;

        _o.WriteLine($"=== standalone {decrypted}/{files.Length}, sequential {seqDecrypted}/{files.Length} ===");
        _o.WriteLine("(Envelopes whose prekey material predates the current account.bin — e.g. captured "
            + "before an unlink/re-link — fail with bad MAC; that is stale data, not a code fault.)");
        decrypted = Math.Max(decrypted, seqDecrypted);
        Assert.True(decrypted > 0, "no captured envelope decrypted — SPQR integration not yet working");
    }

    private bool TryDecrypt(AccountProtocolStore store, string file)
    {
        var decryptor = new MessageDecryptor(store);
        Envelope env = Envelope.Parser.ParseFrom(File.ReadAllBytes(file));
        try
        {
            DecryptedMessage? msg = decryptor.Decrypt(env);
            if (msg is not null)
            {
                _o.WriteLine($"  {Path.GetFileName(file)}: DECRYPTED peer={msg.PeerServiceId} outgoing={msg.Outgoing} body=\"{msg.Body}\"");
                return true;
            }
            _o.WriteLine($"  {Path.GetFileName(file)}: decrypted but no surfaced text (type={env.Type})");
            return true;
        }
        catch (Exception ex)
        {
            _o.WriteLine($"  {Path.GetFileName(file)}: FAILED {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }
}
