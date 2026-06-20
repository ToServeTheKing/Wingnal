using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace Wingnal.Service.Account;

/// <summary>
/// Stores peers' profile keys (learned from the <c>profileKey</c> field of their inbound DataMessages),
/// so we can derive their unidentified-access key and send them sealed-sender (metadata-minimized)
/// messages. Profile keys are encrypted at rest with <see cref="LocalCipher"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProfileKeyStore
{
    private readonly string _connectionString;
    private readonly LocalCipher _cipher;

    public ProfileKeyStore(string? path = null, LocalCipher? cipher = null)
    {
        if (path is null)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "profilekeys.db");
        }
        _cipher = cipher ?? LocalCipher.Default();
        _connectionString = $"Data Source={path}";
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS profile_keys (aci TEXT PRIMARY KEY, key TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public void Store(string aci, byte[] profileKey)
    {
        if (profileKey.Length != 32) return;
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO profile_keys (aci, key) VALUES ($a, $k) ON CONFLICT(aci) DO UPDATE SET key = $k;";
        cmd.Parameters.AddWithValue("$a", aci);
        cmd.Parameters.AddWithValue("$k", _cipher.Protect(Convert.ToBase64String(profileKey)));
        cmd.ExecuteNonQuery();
    }

    public byte[]? Get(string aci)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key FROM profile_keys WHERE aci = $a;";
        cmd.Parameters.AddWithValue("$a", aci);
        if (cmd.ExecuteScalar() is not string enc) return null;
        try { return Convert.FromBase64String(_cipher.Unprotect(enc)); } catch { return null; }
    }

    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM profile_keys;";
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}
