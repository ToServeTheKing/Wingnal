using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Wingnal.Service.Account;

namespace Wingnal.Service.Groups;

/// <summary>
/// Persists the decrypted state of groups the user is in (%LOCALAPPDATA%\Wingnal\groups.db), keyed by the
/// lowercase-hex group id. Stores the 32-byte master key (so the group can be re-fetched / re-derived) plus
/// the current revision, title, and roster. The master key, title, and roster JSON are encrypted at rest
/// with <see cref="LocalCipher"/> (the group id stays plaintext so it can key/route conversations).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GroupStore
{
    private readonly string _connectionString;
    private readonly LocalCipher _cipher;

    public GroupStore(string? path = null, LocalCipher? cipher = null)
    {
        if (path is null)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "groups.db");
        }
        _cipher = cipher ?? LocalCipher.Default();
        _connectionString = $"Data Source={path}";
        Initialize();
    }

    private void Initialize()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS groups (
                group_id   TEXT PRIMARY KEY,
                master_key TEXT NOT NULL,
                revision   INTEGER NOT NULL,
                title      TEXT NOT NULL,
                roster     TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Inserts or updates the stored state for a group.</summary>
    public void Save(string groupId, byte[] masterKey, DecryptedGroup group)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO groups (group_id, master_key, revision, title, roster)
            VALUES ($id, $mk, $rev, $title, $roster)
            ON CONFLICT(group_id) DO UPDATE SET master_key = $mk, revision = $rev, title = $title, roster = $roster;
            """;
        cmd.Parameters.AddWithValue("$id", groupId);
        cmd.Parameters.AddWithValue("$mk", _cipher.Protect(Convert.ToHexString(masterKey)));
        cmd.Parameters.AddWithValue("$rev", group.Revision);
        cmd.Parameters.AddWithValue("$title", _cipher.Protect(group.Title));
        cmd.Parameters.AddWithValue("$roster", _cipher.Protect(JsonSerializer.Serialize(group.Members)));
        cmd.ExecuteNonQuery();
    }

    /// <summary>Loads a group's state, or null if not present.</summary>
    public StoredGroup? Load(string groupId)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT master_key, revision, title, roster FROM groups WHERE group_id = $id;";
        cmd.Parameters.AddWithValue("$id", groupId);
        using SqliteDataReader r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        byte[] masterKey = Convert.FromHexString(_cipher.Unprotect(r.GetString(0)));
        uint revision = (uint)r.GetInt64(1);
        string title = _cipher.Unprotect(r.GetString(2));
        var members = JsonSerializer.Deserialize<List<DecryptedGroupMember>>(_cipher.Unprotect(r.GetString(3)))
                      ?? new List<DecryptedGroupMember>();
        return new StoredGroup(groupId, masterKey, new DecryptedGroup(title, null, revision, members));
    }

    public IReadOnlyList<string> AllGroupIds()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT group_id FROM groups;";
        var ids = new List<string>();
        using SqliteDataReader r = cmd.ExecuteReader();
        while (r.Read()) ids.Add(r.GetString(0));
        return ids;
    }

    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM groups;";
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}

/// <summary>A group's persisted state: id, master key, and decrypted roster/title/revision.</summary>
public sealed record StoredGroup(string GroupId, byte[] MasterKey, DecryptedGroup Group);
