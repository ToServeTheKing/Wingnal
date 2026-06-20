using System.Security.Cryptography;
using Wingnal.Service.Protos.Backup;
using Wingnal.Service.Sync;
using Xunit;

namespace Wingnal.Tests.Sync;

/// <summary>
/// Validates the backup frame reader against libsignal's own canonical decrypted backup
/// (message-backup/tests/res/canonical-backup.binproto), and the encrypted-container pipeline
/// (HMAC + AES-256-CBC + gzip) via a round-trip.
/// </summary>
public class BackupReaderTests
{
    // libsignal v0.96.1 canonical-backup.binproto (the decrypted, decompressed varint-delimited frame
    // stream: a BackupInfo header + 4 Recipient frames + AccountData).
    private const string CanonicalBackupB64 =
        "KwgBENj6oJ/3MRogq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6vfAQrcAQogYQKRq+3DQklInaOaMcmlz" +
        "ZnN0m/1hzLiaONX7gB12dgSDGJvYmFfZmV0dC42Nho2CiBlZ1xz0A6wEAXju3xKR/KWy2VU94mBI4gV6RXYJP0ukx" +
        "IQYcEBogDVQheJwgUY2El68BgEIgRCb2JhKgRGZXR0OikKIOy7aMc0MxouozPNp0fJjEVTZSJhWCtPzlrg3qhNzmU" +
        "ZEgNVU0QYAUozCAEQARgBKAEwATiQHEIH8J+Pju+4j0gBUAFYAWABaAFwAXgBgAEBiAECuAEB4AEB6AECYgYIARAB" +
        "GAEGEgQIASoABhIECAIyACgSJggDIiIKEAAAAAAAAAAAAAAAAAAAAAAaDgoITXkgU3RvcnkQARgDURJPCAQ6SwoQL" +
        "K/OA8QKkAScD3Pylf/TQBIgtHL8wOy+nxrU20u/AwPVlzQZPrvUAb8Gi0JYepG5h7kaDFRlYW0gTWVldGluZyACKI" +
        "DA68mdMg==";

    [Fact]
    public void ParsesLibsignalCanonicalBackup()
    {
        byte[] frameStream = Convert.FromBase64String(CanonicalBackupB64);

        BackupContents backup = BackupReader.ReadFrames(frameStream);

        Assert.Equal(1u, backup.Info.Version);
        // The canonical backup has 4 recipients (Self, ReleaseNotes, DistributionList, CallLink) +
        // one AccountData frame.
        Assert.Equal(4, backup.Frames.Count(f => f.ItemCase == Frame.ItemOneofCase.Recipient));
        Assert.Contains(backup.Frames, f => f.ItemCase == Frame.ItemOneofCase.Account);
        Assert.Contains(backup.Frames, f =>
            f.ItemCase == Frame.ItemOneofCase.Recipient &&
            f.Recipient.DestinationCase == Recipient.DestinationOneofCase.Self);
    }

    [Fact]
    public void EncryptedContainer_RoundTrips()
    {
        var key = new MessageBackupKey(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));

        var info = new BackupInfo { Version = 1, BackupTimeMs = 1700000000000 };
        var frames = new[]
        {
            new Frame { Recipient = new Recipient { Id = 1, Self = new Self() } },
            new Frame { Chat = new Chat { Id = 10, RecipientId = 1 } },
        };
        byte[] frameStream = BackupReader.WriteFrames(info, frames);

        byte[] file = BackupReader.WriteContainer(frameStream, key, RandomNumberGenerator.GetBytes(16));
        BackupContents read = BackupReader.Read(file, key);

        Assert.Equal(1u, read.Info.Version);
        Assert.Equal(2, read.Frames.Count);
        Assert.Equal(10u, read.Frames[1].Chat.Id);
    }

    [Fact]
    public void EncryptedContainer_RejectsTamper()
    {
        var key = new MessageBackupKey(RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32));
        byte[] frameStream = BackupReader.WriteFrames(new BackupInfo { Version = 1 }, Array.Empty<Frame>());
        byte[] file = BackupReader.WriteContainer(frameStream, key, RandomNumberGenerator.GetBytes(16));

        file[20] ^= 0x01;
        Assert.Throws<InvalidBackupException>(() => BackupReader.Read(file, key));
    }
}
