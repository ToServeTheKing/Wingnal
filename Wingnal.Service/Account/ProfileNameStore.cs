using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace Wingnal.Service.Account;

/// <summary>
/// SQLite store of profile display names we've fetched and decrypted per ACI (via <c>ProfileCipher</c>),
/// so the conversation list can name contacts who aren't in the primary's system address book. This is
/// distinct from <see cref="ContactsStore"/> (which holds names synced from the primary): profile names
/// are resolved on demand from each peer's profile key. Names are encrypted at rest with
/// <see cref="LocalCipher"/> (%LOCALAPPDATA%\Wingnal\profile_names.db). Keyed by ACI.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProfileNameStore
{
    private readonly string _connectionString;
    private readonly LocalCipher _cipher;

    public ProfileNameStore(string? path = null, LocalCipher? cipher = null)
    {
        if (path is null)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "profile_names.db");
        }
        _cipher = cipher ?? LocalCipher.Default();
        _connectionString = $"Data Source={path}";
        Initialize();
    }

    private void Initialize()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE IF NOT EXISTS profile_names (aci TEXT PRIMARY KEY, name TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
    }

    public void Store(string aci, string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO profile_names (aci, name) VALUES ($a, $n) ON CONFLICT(aci) DO UPDATE SET name = $n;";
        cmd.Parameters.AddWithValue("$a", aci);
        cmd.Parameters.AddWithValue("$n", _cipher.Protect(name));
        cmd.ExecuteNonQuery();
    }

    public string? Get(string aci)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM profile_names WHERE aci = $a;";
        cmd.Parameters.AddWithValue("$a", aci);
        return cmd.ExecuteScalar() is string s ? _cipher.Unprotect(s) : null;
    }

    /// <summary>Removes all resolved profile names (used when unlinking).</summary>
    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM profile_names;";
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}
