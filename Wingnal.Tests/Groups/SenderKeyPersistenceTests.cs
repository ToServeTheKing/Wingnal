using System.Text;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Xunit;

namespace Wingnal.Tests.Groups;

/// <summary>
/// GV2 Phase A gate: the Sender Key (group) state survives an app restart. A receiving member's chain —
/// including its skipped-key cache — must persist to SQLite so out-of-order group messages still decrypt
/// after the store is reopened.
/// </summary>
public class SenderKeyPersistenceTests
{
    private static readonly SignalProtocolAddress Sender = new("aaaaaaaa-1111-2222-3333-444444444444", 1);
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    private static string Str(byte[] b) => Encoding.UTF8.GetString(b);

    [Fact]
    public void RecordSerialization_RoundTrips()
    {
        var distId = Guid.NewGuid();
        var store = new InMemorySenderKeyStore();
        new GroupSessionBuilder(store).Create(Sender, distId);
        SenderKeyRecord original = store.LoadSenderKey(Sender, distId)!;

        SenderKeyRecord restored = SenderKeyRecord.Deserialize(original.Serialize());

        // The current state (chain id, iteration, signing key) must come back identical so the chain
        // continues exactly where it left off.
        Assert.Equal(original.State.ChainId, restored.State.ChainId);
        Assert.Equal(original.State.ChainKey.Iteration, restored.State.ChainKey.Iteration);
        Assert.Equal(original.State.ChainKey.Seed, restored.State.ChainKey.Seed);
        Assert.Equal(original.State.SigningKeyPublic, restored.State.SigningKeyPublic);
        Assert.Equal(original.State.SigningKeyPrivate, restored.State.SigningKeyPrivate);
    }

    [Fact]
    public void SqliteStore_PersistsGroupChain_AcrossInstances_IncludingSkippedKeys()
    {
        string dir = Path.Combine(Path.GetTempPath(), "wingnal-sk-" + Guid.NewGuid().ToString("N"));
        try
        {
            Guid distId = Guid.NewGuid();

            // Sender side (in-memory is fine) emits four ordered messages.
            var senderStore = new InMemorySenderKeyStore();
            SenderKeyDistributionMessage skdm = new GroupSessionBuilder(senderStore).Create(Sender, distId);
            var senderCipher = new GroupSessionCipher(senderStore);
            SenderKeyMessage m0 = senderCipher.Encrypt(Sender, distId, Utf8("zero"));
            SenderKeyMessage m1 = senderCipher.Encrypt(Sender, distId, Utf8("one"));
            SenderKeyMessage m2 = senderCipher.Encrypt(Sender, distId, Utf8("two"));
            SenderKeyMessage m3 = senderCipher.Encrypt(Sender, distId, Utf8("three"));

            // Receiver installs the SKDM + decrypts m0 in the FIRST store instance.
            var store1 = new SqliteSenderKeyStore("senderkeys.db", directory: dir);
            new GroupSessionBuilder(store1).Process(Sender, skdm);
            Assert.Equal("zero", Str(new GroupSessionCipher(store1).Decrypt(Sender, m0)));

            // Reopen the store (simulated app restart) and keep decrypting. m2 arrives before m1, so
            // iteration 1's key is skipped → cached; that cache must have persisted for m1 to decrypt.
            var store2 = new SqliteSenderKeyStore("senderkeys.db", directory: dir);
            var cipher2 = new GroupSessionCipher(store2);
            Assert.Equal("two", Str(cipher2.Decrypt(Sender, m2)));    // skips + caches iteration 1
            Assert.Equal("one", Str(cipher2.Decrypt(Sender, m1)));    // from the persisted cache
            Assert.Equal("three", Str(cipher2.Decrypt(Sender, m3)));

            // A replay of a consumed iteration is still rejected after the restart.
            Assert.Throws<DuplicateMessageException>(() => new GroupSessionCipher(
                new SqliteSenderKeyStore("senderkeys.db", directory: dir)).Decrypt(Sender, m0));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best-effort cleanup */ }
        }
    }
}
