using System.Text;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Service.Sync;

/// <summary>The AES + HMAC keys a Signal Backup (and the link'n'sync transfer archive) is encrypted
/// under, derived from a backup key + backup id. Layout matches libsignal MessageBackupKey: 64 bytes =
/// hmacKey[32] || aesKey[32].</summary>
public sealed record MessageBackupKey(byte[] HmacKey, byte[] AesKey);

/// <summary>
/// Key derivation for Signal Backups, byte-exact with libsignal v0.96.1 (account-keys/src/backup.rs,
/// message-backup/src/key.rs). For link'n'sync the 32-byte <c>ephemeralBackupKey</c> from the
/// ProvisionMessage IS the BackupKey; combine it with our ACI to get the message backup key.
/// </summary>
public static class BackupKey
{
    // HKDF domain-separation strings (libsignal). expand_multi_info([info, suffix]) == HKDF info = info‖suffix.
    private static readonly byte[] BackupKeyInfo = Encoding.ASCII.GetBytes("20240801_SIGNAL_BACKUP_KEY");
    private static readonly byte[] BackupIdInfo = Encoding.ASCII.GetBytes("20241024_SIGNAL_BACKUP_ID:");
    // OLD_DST — used when there is no backup forward-secrecy token, which is the link'n'sync case.
    private static readonly byte[] EncryptMessageBackupInfo =
        Encoding.ASCII.GetBytes("20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:");

    /// <summary>BackupKey from an AccountEntropyPool string (the remote-backup path; also used to
    /// validate the chain against libsignal's test vector). Returns 32 bytes.</summary>
    public static byte[] FromAccountEntropyPool(string accountEntropyPool) =>
        CryptoPrimitives.Hkdf(Encoding.ASCII.GetBytes(accountEntropyPool), salt: null, BackupKeyInfo, 32);

    /// <summary>Derives the 16-byte backup id from a 32-byte backup key and the 16-byte ACI (service-id
    /// binary form = the raw RFC-4122 UUID bytes).</summary>
    public static byte[] DeriveBackupId(byte[] backupKey, byte[] aciServiceIdBinary)
    {
        if (backupKey.Length != 32) throw new ArgumentException("backup key must be 32 bytes", nameof(backupKey));
        if (aciServiceIdBinary.Length != 16) throw new ArgumentException("aci must be 16 bytes", nameof(aciServiceIdBinary));
        return CryptoPrimitives.Hkdf(backupKey, salt: null, Concat(BackupIdInfo, aciServiceIdBinary), 16);
    }

    /// <summary>Derives the message backup key (hmac[32] || aes[32]) from a backup key + backup id.</summary>
    public static MessageBackupKey DeriveMessageBackupKey(byte[] backupKey, byte[] backupId)
    {
        if (backupId.Length != 16) throw new ArgumentException("backup id must be 16 bytes", nameof(backupId));
        byte[] material = CryptoPrimitives.Hkdf(backupKey, salt: null, Concat(EncryptMessageBackupInfo, backupId), 64);
        return new MessageBackupKey(material.AsSpan(0, 32).ToArray(), material.AsSpan(32, 32).ToArray());
    }

    /// <summary>Convenience for link'n'sync: ephemeralBackupKey + our ACI → message backup key.</summary>
    public static MessageBackupKey ForLinkAndSync(byte[] ephemeralBackupKey, Guid aci)
    {
        byte[] aciBinary = UuidToRfc4122(aci);
        byte[] backupId = DeriveBackupId(ephemeralBackupKey, aciBinary);
        return DeriveMessageBackupKey(ephemeralBackupKey, backupId);
    }

    /// <summary>A UUID's 16 bytes in RFC 4122 / big-endian order (service-id binary form for an ACI).</summary>
    public static byte[] UuidToRfc4122(Guid id) => id.ToByteArray(bigEndian: true);

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
