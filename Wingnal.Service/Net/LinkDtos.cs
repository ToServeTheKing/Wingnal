using System.Text.Json.Serialization;

namespace Wingnal.Service.Net;

// JSON DTOs for PUT /v1/devices/link. Field names match the Signal service contract.

public sealed record SignedPreKeyEntity(
    [property: JsonPropertyName("keyId")] uint KeyId,
    [property: JsonPropertyName("publicKey")] string PublicKey,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record KyberPreKeyEntity(
    [property: JsonPropertyName("keyId")] uint KeyId,
    [property: JsonPropertyName("publicKey")] string PublicKey,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record AccountAttributes(
    [property: JsonPropertyName("fetchesMessages")] bool FetchesMessages,
    [property: JsonPropertyName("registrationId")] uint RegistrationId,
    [property: JsonPropertyName("pniRegistrationId")] uint PniRegistrationId,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("capabilities")] AccountCapabilities Capabilities);

/// <summary>
/// Linked-device capability flags, serialized as a {name: bool} map. The server keeps the true
/// entries with known names. New devices must declare <c>spqr</c> (required for new devices) and must
/// not drop downgrade-protected capabilities the account already has (e.g. usernameChangeSyncMessage).
/// </summary>
public sealed record AccountCapabilities(
    [property: JsonPropertyName("storage")] bool Storage = true,
    [property: JsonPropertyName("spqr")] bool Spqr = true,
    [property: JsonPropertyName("usernameChangeSyncMessage")] bool UsernameChangeSyncMessage = true);

public sealed record LinkDeviceRequest(
    [property: JsonPropertyName("verificationCode")] string VerificationCode,
    [property: JsonPropertyName("accountAttributes")] AccountAttributes AccountAttributes,
    [property: JsonPropertyName("aciSignedPreKey")] SignedPreKeyEntity AciSignedPreKey,
    [property: JsonPropertyName("pniSignedPreKey")] SignedPreKeyEntity PniSignedPreKey,
    [property: JsonPropertyName("aciPqLastResortPreKey")] KyberPreKeyEntity AciPqLastResortPreKey,
    [property: JsonPropertyName("pniPqLastResortPreKey")] KyberPreKeyEntity PniPqLastResortPreKey);

public sealed record LinkDeviceResponse(
    [property: JsonPropertyName("uuid")] string Uuid,
    [property: JsonPropertyName("pni")] string Pni,
    [property: JsonPropertyName("deviceId")] int DeviceId);
