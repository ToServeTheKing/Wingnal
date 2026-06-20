using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Wingnal.Service.Account;

namespace Wingnal.Service.Messaging;

/// <summary>A stored 1:1 message. <see cref="MediaPath"/> is the local file of a downloaded attachment
/// (null for plain text).</summary>
public sealed record StoredMessage(string Peer, string Body, long Timestamp, bool Outgoing)
{
    public string? MediaPath { get; init; }
}

/// <summary>One conversation thread, keyed by peer service id, with its most recent message.</summary>
public sealed record Conversation(string Peer, string LastBody, long LastTimestamp, bool LastOutgoing);

/// <summary>
/// SQLite store for received/sent 1:1 texts (%LOCALAPPDATA%\Wingnal\messages.db). Message BODIES are
/// encrypted at rest with <see cref="LocalCipher"/> (peer/timestamp metadata stays plaintext so the
/// list/threads can still be queried + sorted). Legacy plaintext rows decrypt-through unchanged.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MessageStore
{
    private readonly string _connectionString;
    private readonly LocalCipher _cipher;

    public MessageStore(string? path = null, LocalCipher? cipher = null)
    {
        if (path is null)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "messages.db");
        }
        _cipher = cipher ?? LocalCipher.Default();
        _connectionString = $"Data Source={path}";
        Initialize();
    }

    private void Initialize()
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                peer      TEXT    NOT NULL,
                body      TEXT    NOT NULL,
                timestamp INTEGER NOT NULL,
                outgoing  INTEGER NOT NULL,
                media     TEXT
            );
            """;
        cmd.ExecuteNonQuery();
        // Idempotent migration for DBs created before the media column existed.
        try
        {
            using SqliteCommand alter = conn.CreateCommand();
            alter.CommandText = "ALTER TABLE messages ADD COLUMN media TEXT;";
            alter.ExecuteNonQuery();
        }
        catch (SqliteException) { /* column already exists */ }
    }

    public void Add(StoredMessage message)
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT INTO messages (peer, body, timestamp, outgoing, media) VALUES ($peer, $body, $ts, $out, $media);";
        cmd.Parameters.AddWithValue("$peer", message.Peer);
        cmd.Parameters.AddWithValue("$body", _cipher.Protect(message.Body));   // encrypted at rest
        cmd.Parameters.AddWithValue("$ts", message.Timestamp);
        cmd.Parameters.AddWithValue("$out", message.Outgoing ? 1 : 0);
        cmd.Parameters.AddWithValue("$media", message.MediaPath is null ? DBNull.Value : _cipher.Protect(message.MediaPath));
        cmd.ExecuteNonQuery();
    }

    /// <summary>The most recent <paramref name="limit"/> messages for one peer's thread, returned
    /// oldest-first for display. (Selects the NEWEST N by timestamp DESC then reverses — selecting ASC
    /// would return the OLDEST N and hide recent history in a long thread.)</summary>
    public IReadOnlyList<StoredMessage> Recent(string peer, int limit = 500)
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT peer, body, timestamp, outgoing, media FROM messages WHERE peer = $peer ORDER BY timestamp DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$peer", peer);
        cmd.Parameters.AddWithValue("$limit", limit);

        var result = new List<StoredMessage>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
            result.Add(new StoredMessage(reader.GetString(0), _cipher.Unprotect(reader.GetString(1)),
                reader.GetInt64(2), reader.GetInt64(3) != 0)
            {
                MediaPath = reader.IsDBNull(4) ? null : _cipher.Unprotect(reader.GetString(4)),
            });
        result.Reverse();   // chronological (oldest → newest) for the thread view
        return result;
    }

    /// <summary>One row per peer (the conversation list), most-recently-active first.</summary>
    public IReadOnlyList<Conversation> Conversations()
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        // Pick each peer's CHRONOLOGICALLY newest message (max TIMESTAMP, not max id — rows are inserted
        // in import order, not time order). SQLite fills the bare columns from the MAX(timestamp) row.
        cmd.CommandText =
            """
            SELECT peer, body, MAX(timestamp) AS timestamp, outgoing
            FROM messages
            GROUP BY peer
            ORDER BY timestamp DESC;
            """;

        var result = new List<Conversation>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
            result.Add(new Conversation(reader.GetString(0), _cipher.Unprotect(reader.GetString(1)),
                reader.GetInt64(2), reader.GetInt64(3) != 0));
        return result;
    }

    /// <summary>A set of identity keys for the messages already stored (peer‖ts‖outgoing‖body), so a
    /// bulk import can skip ones it already added (idempotent re-import).</summary>
    public HashSet<string> ExistingKeys()
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT peer, timestamp, outgoing, body FROM messages;";
        var set = new HashSet<string>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
            set.Add(KeyOf(reader.GetString(0), reader.GetInt64(1), reader.GetInt64(2) != 0,
                _cipher.Unprotect(reader.GetString(3))));
        return set;
    }

    /// <summary>The de-dup identity of a message.</summary>
    public static string KeyOf(string peer, long timestamp, bool outgoing, string body) =>
        string.Join('|', peer, timestamp, outgoing ? 1 : 0, body);

    /// <summary>Removes exact-duplicate rows (same peer+timestamp+outgoing+body), keeping the earliest.
    /// Done in code because the body column is now encrypted (non-deterministic), so SQL GROUP BY can't
    /// see content equality. Returns rows deleted.</summary>
    public int Deduplicate()
    {
        using var conn = Open();
        var seen = new HashSet<string>();
        var toDelete = new List<long>();
        using (SqliteCommand read = conn.CreateCommand())
        {
            read.CommandText = "SELECT id, peer, timestamp, outgoing, body FROM messages ORDER BY id;";
            using SqliteDataReader reader = read.ExecuteReader();
            while (reader.Read())
            {
                string key = KeyOf(reader.GetString(1), reader.GetInt64(2), reader.GetInt64(3) != 0,
                    _cipher.Unprotect(reader.GetString(4)));
                if (!seen.Add(key)) toDelete.Add(reader.GetInt64(0));
            }
        }
        foreach (long id in toDelete)
        {
            using SqliteCommand del = conn.CreateCommand();
            del.CommandText = "DELETE FROM messages WHERE id = $id;";
            del.Parameters.AddWithValue("$id", id);
            del.ExecuteNonQuery();
        }
        return toDelete.Count;
    }

    /// <summary>Removes all stored messages (used when unlinking).</summary>
    public void Clear()
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM messages;";
        cmd.ExecuteNonQuery();
    }

    /// <summary>Deletes every message in one peer's thread (peer is stored in the clear).</summary>
    public void DeleteConversation(string peer)
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM messages WHERE peer = $peer;";
        cmd.Parameters.AddWithValue("$peer", peer);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Deletes one message identified by (peer, timestamp, direction). Body isn't used since it's
    /// encrypted; the timestamp is effectively unique within a peer + direction.</summary>
    public void DeleteMessage(string peer, long timestamp, bool outgoing)
    {
        using var conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM messages WHERE peer = $peer AND timestamp = $ts AND outgoing = $out;";
        cmd.Parameters.AddWithValue("$peer", peer);
        cmd.Parameters.AddWithValue("$ts", timestamp);
        cmd.Parameters.AddWithValue("$out", outgoing ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}
