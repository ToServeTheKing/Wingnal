using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace Wingnal.Service.Account;

/// <summary>
/// Persists the linked <see cref="SignalAccount"/> to disk, encrypted at rest with Windows DPAPI
/// (per-user). Stored under %LOCALAPPDATA%\Wingnal\account.bin.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AccountStore
{
    private static readonly byte[] Entropy = "Wingnal.Account.v1"u8.ToArray();
    private readonly string _path;

    public AccountStore(string? directory = null)
    {
        directory ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "account.bin");
    }

    public bool Exists => File.Exists(_path);

    public void Save(SignalAccount account)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(account);
        byte[] encrypted = ProtectedData.Protect(json, Entropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(_path, encrypted);
    }

    public SignalAccount? Load()
    {
        if (!Exists)
            return null;
        byte[] encrypted = File.ReadAllBytes(_path);
        byte[] json = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
        return JsonSerializer.Deserialize<SignalAccount>(json);
    }

    public void Delete()
    {
        if (Exists)
            File.Delete(_path);
    }
}
