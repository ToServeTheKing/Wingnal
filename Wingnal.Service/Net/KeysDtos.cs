namespace Wingnal.Service.Net;

// ── GET /v2/keys/{identifier}/{deviceId} response ──

public sealed class PreKeyResponse
{
    public string IdentityKey { get; set; } = "";          // base64, 33-byte (0x05‖32)
    public PreKeyResponseDevice[] Devices { get; set; } = Array.Empty<PreKeyResponseDevice>();
}

public sealed class PreKeyResponseDevice
{
    public uint DeviceId { get; set; }
    public uint RegistrationId { get; set; }
    public PreKeyDto? PreKey { get; set; }                  // optional one-time EC prekey
    public SignedPreKeyDto SignedPreKey { get; set; } = new();
    public SignedPreKeyDto? PqPreKey { get; set; }          // ML-KEM (Kyber) signed prekey
}

public sealed class PreKeyDto
{
    public uint KeyId { get; set; }
    public string PublicKey { get; set; } = "";            // base64, 33-byte (0x05‖32)
}

public sealed class SignedPreKeyDto
{
    public uint KeyId { get; set; }
    public string PublicKey { get; set; } = "";            // base64 (EC: 0x05‖32; Kyber: 0x08‖1568)
    public string Signature { get; set; } = "";            // base64
}

// ── PUT /v1/messages/{destination} request ──

public sealed class OutgoingMessageList
{
    public OutgoingMessage[] Messages { get; set; } = Array.Empty<OutgoingMessage>();
    public long Timestamp { get; set; }
    public bool Online { get; set; }
    public bool Urgent { get; set; }
}

// ── PUT /v2/keys?identity={aci|pni} request (upload one-time prekeys) ──

public sealed class SetKeysRequest
{
    public PreKeyEntity[]? PreKeys { get; set; }   // one-time EC prekeys
}

public sealed class PreKeyEntity
{
    public uint KeyId { get; set; }
    public string PublicKey { get; set; } = "";   // base64, 33-byte (0x05‖32)
}

public sealed class OutgoingMessage
{
    public int Type { get; set; }                          // envelope type: 3=PREKEY_MESSAGE, 1=DOUBLE_RATCHET
    public uint DestinationDeviceId { get; set; }
    public uint DestinationRegistrationId { get; set; }
    public string Content { get; set; } = "";              // base64 of the serialized ciphertext
}
