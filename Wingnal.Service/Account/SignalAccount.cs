using System.Text;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;

namespace Wingnal.Service.Account;

/// <summary>
/// Everything this linked secondary device needs to authenticate to Signal and run the protocol:
/// account identifiers, the device id/password assigned at link time, registration ids, and the ACI
/// and PNI identity key pairs (received from the primary during provisioning).
/// </summary>
public sealed class SignalAccount
{
    public required string Aci { get; init; }
    public required string Pni { get; init; }
    public required string Number { get; init; }
    public required int DeviceId { get; set; }
    public required string Password { get; init; }
    public required uint AciRegistrationId { get; init; }
    public required uint PniRegistrationId { get; init; }

    /// <summary>33-byte serialized DjbECPublicKey.</summary>
    public required byte[] AciIdentityPublic { get; init; }
    public required byte[] AciIdentityPrivate { get; init; }
    public required byte[] PniIdentityPublic { get; init; }
    public required byte[] PniIdentityPrivate { get; init; }
    public required byte[] ProfileKey { get; init; }

    /// <summary>Signed + last-resort kyber prekeys registered at link time (ACI identity).</summary>
    public required RegisteredPreKeys AciPreKeys { get; init; }

    /// <summary>Signed + last-resort kyber prekeys registered at link time (PNI identity).</summary>
    public required RegisteredPreKeys PniPreKeys { get; init; }

    /// <summary>Unused one-time EC prekeys uploaded for the ACI identity (consumed as inbound sessions
    /// use them; removed on consumption and re-persisted). Not <c>required</c> so older account.bin
    /// files (without this field) still deserialize as empty.</summary>
    public List<OneTimePreKey> AciOneTimePreKeys { get; set; } = new();

    /// <summary>The one-time 32-byte link'n'sync backup key the primary sent in the ProvisionMessage,
    /// used to decrypt the message-history transfer archive once. Cleared after a successful import (or
    /// null when the primary didn't offer link+sync). Not <c>required</c> for back-compat.</summary>
    public byte[]? EphemeralBackupKey { get; set; }

    public IdentityKeyPair AciIdentityKeyPair =>
        new(IdentityKey.Decode(AciIdentityPublic), AciIdentityPrivate);

    public IdentityKeyPair PniIdentityKeyPair =>
        new(IdentityKey.Decode(PniIdentityPublic), PniIdentityPrivate);

    /// <summary>HTTP Basic auth value (without the "Basic " prefix) for the authenticated chat API.</summary>
    public string BasicAuthToken()
    {
        string user = DeviceId == 1 ? Aci : $"{Aci}.{DeviceId}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{Password}"));
    }
}

/// <summary>The durable private material for the prekeys this device registered for one identity.</summary>
public sealed class RegisteredPreKeys
{
    public required uint SignedPreKeyId { get; init; }
    public required byte[] SignedPreKeyPublic { get; init; }   // raw 32
    public required byte[] SignedPreKeyPrivate { get; init; }  // raw 32
    public required byte[] SignedPreKeySignature { get; init; }
    public required uint KyberPreKeyId { get; init; }
    public required byte[] KyberPreKeyPublic { get; init; }    // ML-KEM encoded
    public required byte[] KyberPreKeyPrivate { get; init; }
    public required byte[] KyberPreKeySignature { get; init; }
}

/// <summary>One unused one-time prekey's durable material (id + raw 32-byte EC key pair).</summary>
public sealed class OneTimePreKey
{
    public uint Id { get; set; }
    public byte[] Public { get; set; } = Array.Empty<byte>();   // raw 32
    public byte[] Private { get; set; } = Array.Empty<byte>();  // raw 32
}
