namespace Wingnal.Service.Net;

/// <summary>The subset of <c>GET /v1/profile/{id}</c> we consume: the encrypted display <c>name</c>
/// (base64 of <c>nonce || ciphertext || tag</c>, decryptable with the recipient's profile key). Other
/// fields (about, avatar, capabilities, …) are ignored.</summary>
public sealed record ProfileResponse
{
    public string? Name { get; init; }
    public string? About { get; init; }
}
