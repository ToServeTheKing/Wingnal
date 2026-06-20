using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Wingnal.Protocol.Groups;
using Wingnal.Protocol.State;

namespace Wingnal.Service.Account;

/// <summary>
/// Durable <see cref="ISenderKeyStore"/>: persists group sender-key records to SQLite, keyed by
/// (sender address, distribution id), so an established group chain survives an app restart — mirroring
/// how <see cref="SqliteSignalProtocolStore"/> persists 1:1 sessions. Each record blob is DPAPI-protected
/// at rest. State serialization is local-only (never sent to a peer).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SqliteSenderKeyStore : ISenderKeyStore
{
    private static readonly byte[] Entropy = "Wingnal.SenderKeyStore.v1"u8.ToArray();

    private readonly string _connectionString;

    public SqliteSenderKeyStore(string dbFileName = "senderkeys.db", string? directory = null)
    {
        directory ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
        Directory.CreateDirectory(directory);
        _connectionString = $"Data Source={Path.Combine(directory, dbFileName)}";
        Initialize();
    }

    private void Initialize()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS sender_keys (
                name         TEXT    NOT NULL,
                device       INTEGER NOT NULL,
                distribution TEXT    NOT NULL,
                data         BLOB    NOT NULL,
                PRIMARY KEY (name, device, distribution));
            """;
        cmd.ExecuteNonQuery();
    }

    public void StoreSenderKey(SignalProtocolAddress sender, Guid distributionId, SenderKeyRecord record)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "INSERT OR REPLACE INTO sender_keys (name, device, distribution, data) VALUES ($n, $d, $g, $data);";
        cmd.Parameters.AddWithValue("$n", sender.Name);
        cmd.Parameters.AddWithValue("$d", sender.DeviceId);
        cmd.Parameters.AddWithValue("$g", distributionId.ToString("D"));
        cmd.Parameters.AddWithValue("$data", Protect(record.Serialize()));
        cmd.ExecuteNonQuery();
    }

    public SenderKeyRecord? LoadSenderKey(SignalProtocolAddress sender, Guid distributionId)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            "SELECT data FROM sender_keys WHERE name = $n AND device = $d AND distribution = $g;";
        cmd.Parameters.AddWithValue("$n", sender.Name);
        cmd.Parameters.AddWithValue("$d", sender.DeviceId);
        cmd.Parameters.AddWithValue("$g", distributionId.ToString("D"));
        return cmd.ExecuteScalar() is byte[] data ? SenderKeyRecord.Deserialize(Unprotect(data)) : null;
    }

    /// <summary>Wipes all sender keys (used when unlinking, alongside the session/message wipe).</summary>
    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sender_keys;";
        cmd.ExecuteNonQuery();
    }

    private static byte[] Protect(byte[] plain) => ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
    private static byte[] Unprotect(byte[] enc) => ProtectedData.Unprotect(enc, Entropy, DataProtectionScope.CurrentUser);

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}
