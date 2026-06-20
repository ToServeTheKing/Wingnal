using Wingnal.Service.Sync;
using Xunit;

namespace Wingnal.Tests.Sync;

/// <summary>
/// Validates the Signal Backup key-derivation chain byte-exact against libsignal v0.96.1's own test
/// vector (message-backup/src/key.rs): AccountEntropyPool → BackupKey → BackupId → MessageBackupKey.
/// The link'n'sync path uses the same derivation with the 32-byte ephemeralBackupKey as the BackupKey.
/// </summary>
public class BackupKeyTests
{
    // From libsignal key.rs test constants.
    private const string FakeAep = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l";
    private const string FakeAciHex = "659aa5f4a28dfcc11ea1b997537a3d95";
    private const string ExpectedHmacLegacy = "f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649";
    private const string ExpectedAesLegacy = "e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df";

    [Fact]
    public void DerivesMessageBackupKey_MatchesLibsignalVector()
    {
        byte[] backupKey = BackupKey.FromAccountEntropyPool(FakeAep);
        byte[] aci = Convert.FromHexString(FakeAciHex); // service-id binary = raw 16-byte UUID
        byte[] backupId = BackupKey.DeriveBackupId(backupKey, aci);

        // libsignal: derive(key, id, None) -> OLD_DST -> the "legacy" vector (the link'n'sync case).
        MessageBackupKey key = BackupKey.DeriveMessageBackupKey(backupKey, backupId);

        Assert.Equal(ExpectedHmacLegacy, Convert.ToHexString(key.HmacKey).ToLowerInvariant());
        Assert.Equal(ExpectedAesLegacy, Convert.ToHexString(key.AesKey).ToLowerInvariant());
    }
}
