using System.Linq;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace Wingnal.Service.Account;

/// <summary>A synced contact: ACI + display info, used to name conversations.</summary>
public sealed record Contact(string Aci, string? Number, string? Name, int InboxPosition);

/// <summary>
/// SQLite store of contacts learned from a SyncMessage.Contacts blob, so the conversation list can show
/// names instead of raw ACIs (%LOCALAPPDATA%\Wingnal\contacts.db). Keyed by ACI. Names + numbers are
/// encrypted at rest with <see cref="LocalCipher"/> (so the file can't be read to map an ACI → a real
/// person); legacy plaintext rows decrypt-through unchanged.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ContactsStore
{
    private readonly string _connectionString;
    private readonly LocalCipher _cipher;

    public ContactsStore(string? path = null, LocalCipher? cipher = null)
    {
        if (path is null)
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
            Directory.CreateDirectory(dir);
            path = Path.Combine(dir, "contacts.db");
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
            CREATE TABLE IF NOT EXISTS contacts (
                aci           TEXT PRIMARY KEY,
                number        TEXT,
                name          TEXT,
                inboxPosition INTEGER NOT NULL DEFAULT 0
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public void Upsert(Contact contact)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO contacts (aci, number, name, inboxPosition) VALUES ($aci, $number, $name, $pos)
            ON CONFLICT(aci) DO UPDATE SET number = $number, name = $name, inboxPosition = $pos;
            """;
        cmd.Parameters.AddWithValue("$aci", contact.Aci);
        cmd.Parameters.AddWithValue("$number", Enc(contact.Number));
        cmd.Parameters.AddWithValue("$name", Enc(contact.Name));
        cmd.Parameters.AddWithValue("$pos", contact.InboxPosition);
        cmd.ExecuteNonQuery();
    }

    public string? NameFor(string aci)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM contacts WHERE aci = $aci;";
        cmd.Parameters.AddWithValue("$aci", aci);
        return cmd.ExecuteScalar() is string s ? _cipher.Unprotect(s) : null;
    }

    /// <summary>The contact's phone number (E.164), if we synced/imported one — a friendlier last-resort
    /// label than a raw ACI when no name is available.</summary>
    public string? NumberFor(string aci)
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT number FROM contacts WHERE aci = $aci;";
        cmd.Parameters.AddWithValue("$aci", aci);
        return cmd.ExecuteScalar() is string s ? _cipher.Unprotect(s) : null;
    }

    /// <summary>Contacts whose name or number contains <paramref name="query"/> (empty = all named),
    /// ordered by inbox position then name. Filtered in memory because the columns are encrypted.</summary>
    public IReadOnlyList<Contact> Search(string? query, int limit = 25)
    {
        string q = (query ?? string.Empty).Trim();
        IEnumerable<Contact> contacts = All();
        contacts = q.Length == 0
            ? contacts.Where(c => !string.IsNullOrEmpty(c.Name))
            : contacts.Where(c =>
                (c.Name?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (c.Number?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false));
        return contacts.OrderBy(c => c.InboxPosition).ThenBy(c => c.Name).Take(limit).ToList();
    }

    public IReadOnlyList<Contact> All()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT aci, number, name, inboxPosition FROM contacts ORDER BY inboxPosition;";
        var result = new List<Contact>();
        using SqliteDataReader reader = cmd.ExecuteReader();
        while (reader.Read())
            result.Add(new Contact(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : _cipher.Unprotect(reader.GetString(1)),
                reader.IsDBNull(2) ? null : _cipher.Unprotect(reader.GetString(2)),
                reader.GetInt32(3)));
        return result;
    }

    private object Enc(string? value) => value is null ? DBNull.Value : _cipher.Protect(value);

    /// <summary>Removes all synced contacts (used when unlinking).</summary>
    public void Clear()
    {
        using SqliteConnection conn = Open();
        using SqliteCommand cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM contacts;";
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }
}
