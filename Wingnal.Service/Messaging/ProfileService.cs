using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Wingnal.Service.Account;
using Wingnal.Service.Crypto;
using Wingnal.Service.Diagnostics;
using Wingnal.Service.Net;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Resolves display names for peers we can't name from synced contacts, by fetching their Signal profile
/// (<c>GET /v1/profile</c>) and decrypting the name with the profile key learned from their inbound
/// messages (see <see cref="MessageDecryptor"/> → <see cref="ProfileKeyStore"/>). Resolved names are
/// cached in <see cref="ProfileNameStore"/> so a name is fetched at most once per peer.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProfileService
{
    private readonly SignalRestClient _rest;
    private readonly ProfileKeyStore _profileKeys;
    private readonly ProfileNameStore _names;
    private readonly string _authToken;

    public ProfileService(SignalRestClient rest, ProfileKeyStore profileKeys, ProfileNameStore names, string authToken)
    {
        _rest = rest;
        _profileKeys = profileKeys;
        _names = names;
        _authToken = authToken;
    }

    /// <summary>The cached profile name for a peer, if one has been resolved; otherwise null.</summary>
    public string? NameFor(string aci) => _names.Get(aci);

    /// <summary>Fetches, decrypts and caches the profile name for a peer. Returns the resolved name, or
    /// null when we have no profile key for them, their profile isn't accessible, or decryption fails.
    /// Best-effort and idempotent — a cached name short-circuits the network call.</summary>
    public async Task<string?> ResolveAsync(string aci, CancellationToken ct)
    {
        string? cached = _names.Get(aci);
        if (!string.IsNullOrEmpty(cached)) return cached;

        byte[]? profileKey = _profileKeys.Get(aci);
        if (profileKey is null) { FileLog.Write($"profile: {aci} skip — no profile key"); return null; }

        ProfileResponse? profile = await _rest.GetProfileAsync(aci, _authToken, ct).ConfigureAwait(false);
        if (profile is null) { FileLog.Write($"profile: {aci} — fetch returned null (inaccessible/HTTP error)"); return null; }

        string? name = ProfileCipher.DecryptName(profileKey, profile.Name);
        if (name is null)
        {
            FileLog.Write($"profile: {aci} — decrypt/empty (name field len={profile.Name?.Length ?? 0})");
            return null;
        }
        _names.Store(aci, name);
        FileLog.Write($"profile: {aci} resolved (len={name.Length})");   // length only — no PII in the log
        return name;
    }
}
