using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.State;
using Wingnal.Service.Account;
using Wingnal.Service.Crypto;
using Wingnal.Service.Keys;
using Wingnal.Service.Net;
using Wingnal.Service.Protos;
using Wingnal.Service.Provisioning;

namespace Wingnal.Service.Linking;

/// <summary>
/// Orchestrates the full secondary-device link: drive the provisioning handshake, generate this
/// device's credentials + prekeys, register with the service, and persist the resulting account.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LinkingManager
{
    private const uint SignedPreKeyId = 1;
    private const uint KyberPreKeyId = 1;

    private readonly AccountStore _accountStore;
    private readonly SignalRestClient _restClient;
    private readonly string _deviceName;

    public LinkingManager(AccountStore accountStore, SignalRestClient restClient, string deviceName = "Wingnal")
    {
        _accountStore = accountStore;
        _restClient = restClient;
        _deviceName = deviceName;
    }

    /// <summary>
    /// Runs the link flow. <paramref name="onQrReady"/> is invoked with the QR URI to display; the
    /// returned account is also persisted to the <see cref="AccountStore"/>.
    /// </summary>
    public async Task<SignalAccount> LinkAsync(Func<string, Task> onQrReady, CancellationToken ct)
    {
        var provisioning = new ProvisioningManager();
        // Advertise link+sync so the primary offers a message-history transfer archive (docs/SYNC.md).
        ProvisionMessage message = await provisioning
            .LinkAsync(onQrReady, ct, new[] { ProvisioningManager.LinkAndSyncCapability })
            .ConfigureAwait(false);

        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        uint aciRegistrationId = PreKeyHelper.GenerateRegistrationId();
        uint pniRegistrationId = PreKeyHelper.GenerateRegistrationId();

        byte[] aciIdentityPrivate = message.AciIdentityKeyPrivate.ToByteArray();
        byte[] aciIdentityPublic = message.AciIdentityKeyPublic.ToByteArray();
        byte[] pniIdentityPrivate = message.PniIdentityKeyPrivate.ToByteArray();
        byte[] pniIdentityPublic = message.PniIdentityKeyPublic.ToByteArray();

        SignedPreKeyRecord aciSigned = PreKeyHelper.GenerateSignedPreKey(aciIdentityPrivate, SignedPreKeyId);
        KyberPreKeyRecord aciKyber = PreKeyHelper.GenerateKyberPreKey(aciIdentityPrivate, KyberPreKeyId);
        SignedPreKeyRecord pniSigned = PreKeyHelper.GenerateSignedPreKey(pniIdentityPrivate, SignedPreKeyId);
        KyberPreKeyRecord pniKyber = PreKeyHelper.GenerateKyberPreKey(pniIdentityPrivate, KyberPreKeyId);

        byte[] encryptedName = DeviceNameCipher.EncryptDeviceName(
            _deviceName, new IdentityKeyPair(IdentityKey.Decode(aciIdentityPublic), aciIdentityPrivate));

        var request = new LinkDeviceRequest(
            VerificationCode: message.ProvisioningCode,
            AccountAttributes: new AccountAttributes(
                FetchesMessages: true,
                RegistrationId: aciRegistrationId,
                PniRegistrationId: pniRegistrationId,
                Name: Convert.ToBase64String(encryptedName),
                Capabilities: new AccountCapabilities()),
            AciSignedPreKey: ToSignedEntity(aciSigned),
            PniSignedPreKey: ToSignedEntity(pniSigned),
            AciPqLastResortPreKey: ToKyberEntity(aciKyber),
            PniPqLastResortPreKey: ToKyberEntity(pniKyber));

        LinkDeviceResponse response = await _restClient
            .LinkDeviceAsync(message.Number, password, request, ct)
            .ConfigureAwait(false);

        var account = new SignalAccount
        {
            Aci = response.Uuid,
            Pni = response.Pni,
            Number = message.Number,
            DeviceId = response.DeviceId,
            Password = password,
            AciRegistrationId = aciRegistrationId,
            PniRegistrationId = pniRegistrationId,
            AciIdentityPublic = aciIdentityPublic,
            AciIdentityPrivate = aciIdentityPrivate,
            PniIdentityPublic = pniIdentityPublic,
            PniIdentityPrivate = pniIdentityPrivate,
            ProfileKey = message.ProfileKey.ToByteArray(),
            AciPreKeys = ToMaterial(aciSigned, aciKyber),
            PniPreKeys = ToMaterial(pniSigned, pniKyber),
            // Present only if the primary accepted link+sync; used once to import message history.
            EphemeralBackupKey = message.HasEphemeralBackupKey && message.EphemeralBackupKey.Length == 32
                ? message.EphemeralBackupKey.ToByteArray()
                : null,
        };

        // Register a batch of one-time prekeys so inbound sessions get per-message forward secrecy
        // instead of always falling back to the signed prekey. Best-effort: the link already succeeded,
        // so a failure here just leaves us on the last-resort prekeys (prior behavior).
        try
        {
            List<PreKeyRecord> oneTime = PreKeyHelper.GenerateOneTimePreKeys(startId: 1, count: 100);
            await _restClient.UploadPreKeysAsync("aci", new SetKeysRequest
            {
                PreKeys = oneTime.Select(p => new PreKeyEntity
                {
                    KeyId = p.Id,
                    PublicKey = Convert.ToBase64String(Curve25519.EncodePoint(p.KeyPair.PublicKey)),
                }).ToArray(),
            }, account.BasicAuthToken(), ct).ConfigureAwait(false);

            account.AciOneTimePreKeys = oneTime
                .Select(p => new OneTimePreKey { Id = p.Id, Public = p.KeyPair.PublicKey, Private = p.KeyPair.PrivateKey })
                .ToList();
        }
        catch
        {
            // Non-fatal — fall back to last-resort signed/kyber prekeys.
        }

        _accountStore.Save(account);
        return account;
    }

    private static SignedPreKeyEntity ToSignedEntity(SignedPreKeyRecord record) => new(
        record.Id,
        Convert.ToBase64String(Curve25519.EncodePoint(record.KeyPair.PublicKey)),
        Convert.ToBase64String(record.Signature));

    private static KyberPreKeyEntity ToKyberEntity(KyberPreKeyRecord record) => new(
        record.Id,
        Convert.ToBase64String(KemKeySerialization.Serialize(record.KeyPair.PublicKey)),
        Convert.ToBase64String(record.Signature));

    private static RegisteredPreKeys ToMaterial(SignedPreKeyRecord signed, KyberPreKeyRecord kyber) => new()
    {
        SignedPreKeyId = signed.Id,
        SignedPreKeyPublic = signed.KeyPair.PublicKey,
        SignedPreKeyPrivate = signed.KeyPair.PrivateKey,
        SignedPreKeySignature = signed.Signature,
        KyberPreKeyId = kyber.Id,
        KyberPreKeyPublic = kyber.KeyPair.PublicKey,
        KyberPreKeyPrivate = kyber.KeyPair.PrivateKey,
        KyberPreKeySignature = kyber.Signature,
    };
}
