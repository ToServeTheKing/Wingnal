using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Wingnal.Service.Account;
using Wingnal.Service.Crypto;
using Xunit;

namespace Wingnal.Tests.Account;

/// <summary>Offline-validatable pieces of sealed sending: the unidentified-access-key derivation and the
/// encrypted profile-key store. (The live cert-fetch + unauthenticated send can't be tested headless.)</summary>
public class SealedSendPiecesTests
{
    [Fact]
    public void AccessKey_Is16Bytes_Deterministic_DistinctPerProfileKey()
    {
        byte[] pk1 = RandomNumberGenerator.GetBytes(32);
        byte[] pk2 = RandomNumberGenerator.GetBytes(32);

        byte[] a1 = UnidentifiedAccess.DeriveAccessKey(pk1);
        Assert.Equal(16, a1.Length);
        Assert.Equal(a1, UnidentifiedAccess.DeriveAccessKey(pk1));            // deterministic
        Assert.NotEqual(a1, UnidentifiedAccess.DeriveAccessKey(pk2));         // key-dependent
    }

    [Fact]
    public void ProfileKeyStore_RoundTrips_AndEncryptsAtRest()
    {
        string path = Path.Combine(Path.GetTempPath(), "wingnal-pk-" + Guid.NewGuid().ToString("N") + ".db");
        var cipher = new LocalCipher(RandomNumberGenerator.GetBytes(32));
        var store = new ProfileKeyStore(path, cipher);

        byte[] pk = RandomNumberGenerator.GetBytes(32);
        const string aci = "a65ec3d8-3e8c-4018-9349-f8c837f8631e";
        store.Store(aci, pk);

        Assert.Equal(pk, store.Get(aci));
        Assert.Null(store.Get("00000000-0000-0000-0000-000000000000"));

        // Raw column must not contain the base64 of the profile key.
        using (var conn = new SqliteConnection($"Data Source={path};Mode=ReadOnly"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT key FROM profile_keys LIMIT 1;";
            string raw = (string)cmd.ExecuteScalar()!;
            Assert.DoesNotContain(Convert.ToBase64String(pk), raw);
        }

        store.Clear();
        Assert.Null(store.Get(aci));
    }
}
