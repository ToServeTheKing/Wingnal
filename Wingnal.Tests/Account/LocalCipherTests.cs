using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Wingnal.Service.Account;
using Wingnal.Service.Messaging;
using Xunit;

namespace Wingnal.Tests.Account;

/// <summary>
/// Validates at-rest encryption: LocalCipher round-trips + leaves legacy plaintext readable, and a
/// MessageStore actually writes ciphertext to disk (not the plaintext body) while reads decrypt.
/// </summary>
public class LocalCipherTests
{
    private static LocalCipher TestCipher() => new(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void RoundTrips_AndIsNonDeterministic()
    {
        var cipher = TestCipher();
        string a = cipher.Protect("hello 🐦");
        string b = cipher.Protect("hello 🐦");
        Assert.NotEqual(a, b);                       // random nonce per call
        Assert.Equal("hello 🐦", cipher.Unprotect(a));
        Assert.Equal("hello 🐦", cipher.Unprotect(b));
    }

    [Fact]
    public void Unprotect_LeavesLegacyPlaintextUnchanged()
    {
        var cipher = TestCipher();
        // A pre-encryption plaintext row decrypts-through unchanged (graceful migration).
        Assert.Equal("legacy message", cipher.Unprotect("legacy message"));
    }

    [Fact]
    public void Mac_IsDeterministic()
    {
        var cipher = TestCipher();
        Assert.Equal(cipher.Mac("x"), cipher.Mac("x"));
        Assert.NotEqual(cipher.Mac("x"), cipher.Mac("y"));
    }

    [Fact]
    public void MessageStore_WritesCiphertext_ReadsPlaintext()
    {
        string path = Path.Combine(Path.GetTempPath(), "wingnal-enc-" + Guid.NewGuid().ToString("N") + ".db");
        var store = new MessageStore(path, TestCipher());
        store.Add(new StoredMessage("alice", "secret words", 1000, Outgoing: false));

        // The raw body column must NOT contain the plaintext.
        using (var conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT body FROM messages LIMIT 1;";
            string raw = (string)cmd.ExecuteScalar()!;
            Assert.DoesNotContain("secret words", raw);
        }

        // But reading through the store decrypts it.
        Assert.Equal("secret words", store.Recent("alice")[0].Body);
    }
}
