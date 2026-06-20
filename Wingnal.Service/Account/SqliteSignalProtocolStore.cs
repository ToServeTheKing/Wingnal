using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Service.Account;

/// <summary>
/// Durable Signal protocol store: identity + signed/kyber/one-time prekeys are seeded from the
/// persisted <see cref="SignalAccount"/> (same as <see cref="AccountProtocolStore"/>), while sessions
/// and learned remote identities persist to a SQLite DB so conversations survive app restarts. Each
/// stored blob is DPAPI-protected at rest. One-time prekey consumption re-persists the account via the
/// <c>onChanged</c> callback.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SqliteSignalProtocolStore : ISignalProtocolStore
{
    private static readonly byte[] Entropy = "Wingnal.ProtocolStore.v1"u8.ToArray();

    private readonly SignalAccount _account;
    private readonly Action? _onChanged;
    private readonly IdentityKeyPair _identityKeyPair;
    private readonly uint _registrationId;
    private readonly Dictionary<uint, PreKeyRecord> _preKeys = new();
    private readonly Dictionary<uint, SignedPreKeyRecord> _signedPreKeys = new();
    private readonly Dictionary<uint, KyberPreKeyRecord> _kyberPreKeys = new();
    private readonly string _connectionString;

    /// <param name="dbFileName">Distinct file lets send/receive keep separate session spaces.</param>
    public SqliteSignalProtocolStore(SignalAccount account, string dbFileName = "protocol.db",
        Action? onChanged = null, string? directory = null)
    {
        _account = account;
        _onChanged = onChanged;
        _identityKeyPair = account.AciIdentityKeyPair;
        _registrationId = account.AciRegistrationId;

        RegisteredPreKeys pk = account.AciPreKeys;
        _signedPreKeys[pk.SignedPreKeyId] = new SignedPreKeyRecord(
            pk.SignedPreKeyId, new ECKeyPair(pk.SignedPreKeyPrivate, pk.SignedPreKeyPublic), pk.SignedPreKeySignature, 0);
        _kyberPreKeys[pk.KyberPreKeyId] = new KyberPreKeyRecord(
            pk.KyberPreKeyId, new KyberKeyPair(pk.KyberPreKeyPublic, pk.KyberPreKeyPrivate), pk.KyberPreKeySignature, 0);
        foreach (OneTimePreKey otp in account.AciOneTimePreKeys)
            _preKeys[otp.Id] = new PreKeyRecord(otp.Id, new ECKeyPair(otp.Private, otp.Public));

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
            CREATE TABLE IF NOT EXISTS sessions   (name TEXT NOT NULL, device INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (name, device));
            CREATE TABLE IF NOT EXISTS identities (name TEXT NOT NULL, device INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (name, device));
            """;
        cmd.ExecuteNonQuery();
    }

    // ── identities ──
    public IdentityKeyPair GetIdentityKeyPair() => _identityKeyPair;
    public uint GetLocalRegistrationId() => _registrationId;

    public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identity)
    {
        IdentityKey? existing = GetIdentity(address);
        bool changed = existing is not null && !existing.PublicKey.AsSpan().SequenceEqual(identity.PublicKey);
        Upsert("identities", address, Protect(identity.PublicKey));
        return changed;
    }

    public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identity)
    {
        IdentityKey? existing = GetIdentity(address);
        return existing is null || existing.PublicKey.AsSpan().SequenceEqual(identity.PublicKey);
    }

    public IdentityKey? GetIdentity(SignalProtocolAddress address)
    {
        byte[]? data = Load("identities", address);
        return data is null ? null : new IdentityKey(Unprotect(data));
    }

    // ── prekeys (from account; consumption re-persists the account) ──
    public PreKeyRecord LoadPreKey(uint preKeyId) => _preKeys[preKeyId];
    public void StorePreKey(uint preKeyId, PreKeyRecord record) => _preKeys[preKeyId] = record;
    public bool ContainsPreKey(uint preKeyId) => _preKeys.ContainsKey(preKeyId);
    public void RemovePreKey(uint preKeyId)
    {
        _preKeys.Remove(preKeyId);
        if (_account.AciOneTimePreKeys.RemoveAll(k => k.Id == preKeyId) > 0) _onChanged?.Invoke();
    }

    public SignedPreKeyRecord LoadSignedPreKey(uint id) => _signedPreKeys[id];
    public void StoreSignedPreKey(uint id, SignedPreKeyRecord record) => _signedPreKeys[id] = record;
    public bool ContainsSignedPreKey(uint id) => _signedPreKeys.ContainsKey(id);

    public KyberPreKeyRecord LoadKyberPreKey(uint id) => _kyberPreKeys[id];
    public void StoreKyberPreKey(uint id, KyberPreKeyRecord record) => _kyberPreKeys[id] = record;
    public bool ContainsKyberPreKey(uint id) => _kyberPreKeys.ContainsKey(id);
    public void MarkKyberPreKeyUsed(uint id) { /* last-resort key: kept */ }

    // ── sessions (durable) ──
    public SessionRecord LoadSession(SignalProtocolAddress address)
    {
        byte[]? data = Load("sessions", address);
        return data is null ? new SessionRecord() : SessionRecord.Deserialize(Unprotect(data));
    }

    public bool ContainsSession(SignalProtocolAddress address) => Load("sessions", address) is not null;
    public void StoreSession(SignalProtocolAddress address, SessionRecord record) =>
        Upsert("sessions", address, Protect(record.Serialize()));

    public void DeleteSession(SignalProtocolAddress address)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sessions WHERE name = $n AND device = $d;";
        cmd.Parameters.AddWithValue("$n", address.Name);
        cmd.Parameters.AddWithValue("$d", address.DeviceId);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<uint> GetSubDeviceSessions(string name)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT device FROM sessions WHERE name = $n;";
        cmd.Parameters.AddWithValue("$n", name);
        var result = new List<uint>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read()) result.Add((uint)reader.GetInt64(0));
        return result;
    }

    /// <summary>Forgets a peer's learned identities + sessions across all their devices. Used to APPROVE
    /// a changed identity: after this, the next session re-establishes trust-on-first-use with the new
    /// key (and the dead sessions tied to the old key are dropped).</summary>
    public void ResetPeer(string name)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM identities WHERE name = $n; DELETE FROM sessions WHERE name = $n;";
        cmd.Parameters.AddWithValue("$n", name);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Wipes all sessions + learned identities (used when unlinking, so a re-link starts fresh
    /// and never reuses sessions tied to the old identity keys).</summary>
    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sessions; DELETE FROM identities;";
        cmd.ExecuteNonQuery();
    }

    // ── helpers ──
    private void Upsert(string table, SignalProtocolAddress address, byte[] data)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = $"INSERT OR REPLACE INTO {table} (name, device, data) VALUES ($n, $d, $data);";
        cmd.Parameters.AddWithValue("$n", address.Name);
        cmd.Parameters.AddWithValue("$d", address.DeviceId);
        cmd.Parameters.AddWithValue("$data", data);
        cmd.ExecuteNonQuery();
    }

    private byte[]? Load(string table, SignalProtocolAddress address)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT data FROM {table} WHERE name = $n AND device = $d;";
        cmd.Parameters.AddWithValue("$n", address.Name);
        cmd.Parameters.AddWithValue("$d", address.DeviceId);
        return cmd.ExecuteScalar() as byte[];
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
