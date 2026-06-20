using System.IO.Compression;
using System.Security.Cryptography;
using Google.Protobuf;
using Wingnal.Protocol.Crypto;
using Wingnal.Service.Protos.Backup;

namespace Wingnal.Service.Sync;

/// <summary>Thrown when a backup file is malformed or fails its HMAC.</summary>
public sealed class InvalidBackupException : Exception
{
    public InvalidBackupException(string message) : base(message) { }
}

/// <summary>The parsed contents of a decrypted backup: the header plus every frame.</summary>
public sealed record BackupContents(BackupInfo Info, IReadOnlyList<Frame> Frames);

/// <summary>
/// Reads a Signal Backup / link'n'sync transfer archive. The container is
/// <c>IV[16] || AES-256-CBC(aesKey, IV, gzip(frames)) || HMAC-SHA256(hmacKey, IV||ciphertext)[32]</c>;
/// after MAC-verify + decrypt + PKCS7-unpad + gunzip the plaintext is a varint-delimited stream of a
/// <see cref="BackupInfo"/> header followed by <see cref="Frame"/>s. Byte-exact with libsignal v0.96.1
/// (message-backup/src/frame: mac_read, aes_read, unpad; gzip).
/// </summary>
public static class BackupReader
{
    private const int IvLen = 16;
    private const int MacLen = 32;

    /// <summary>Full read: verify + decrypt + decompress + parse frames.</summary>
    public static BackupContents Read(byte[] file, MessageBackupKey key) =>
        ReadFrames(Decompress(DecryptContainer(file, key)));

    /// <summary>Verifies the HMAC and AES-256-CBC-decrypts (PKCS7) to the gzip-compressed frame stream.</summary>
    public static byte[] DecryptContainer(byte[] file, MessageBackupKey key)
    {
        if (file.Length < IvLen + MacLen)
            throw new InvalidBackupException("backup file too short");

        int macOffset = file.Length - MacLen;
        byte[] theirMac = file.AsSpan(macOffset, MacLen).ToArray();
        byte[] ourMac = CryptoPrimitives.HmacSha256(key.HmacKey, file.AsSpan(0, macOffset));
        if (!CryptographicOperations.FixedTimeEquals(theirMac, ourMac))
            throw new InvalidBackupException("backup HMAC mismatch");

        byte[] iv = file.AsSpan(0, IvLen).ToArray();
        byte[] ciphertext = file.AsSpan(IvLen, macOffset - IvLen).ToArray();
        return CryptoPrimitives.AesCbcDecrypt(key.AesKey, iv, ciphertext);
    }

    /// <summary>gzip-inflates the decrypted backup payload.</summary>
    public static byte[] Decompress(byte[] gzipped)
    {
        using var input = new MemoryStream(gzipped, writable: false);
        using var gz = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gz.CopyTo(output);
        return output.ToArray();
    }

    /// <summary>Parses the decompressed varint-delimited stream: a BackupInfo header then Frames.</summary>
    public static BackupContents ReadFrames(byte[] frameStream)
    {
        using var stream = new MemoryStream(frameStream, writable: false);

        BackupInfo info = BackupInfo.Parser.ParseDelimitedFrom(stream)
            ?? throw new InvalidBackupException("missing BackupInfo header");

        var frames = new List<Frame>();
        while (stream.Position < stream.Length)
            frames.Add(Frame.Parser.ParseDelimitedFrom(stream));

        return new BackupContents(info, frames);
    }

    /// <summary>
    /// Builds an encrypted backup container from a decompressed frame stream (for tests / round-trip
    /// validation): gzip → AES-256-CBC → prepend IV → append HMAC.
    /// </summary>
    public static byte[] WriteContainer(byte[] frameStream, MessageBackupKey key, byte[] iv)
    {
        if (iv.Length != IvLen) throw new ArgumentException("iv must be 16 bytes", nameof(iv));

        using var compressed = new MemoryStream();
        using (var gz = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
            gz.Write(frameStream, 0, frameStream.Length);
        byte[] ciphertext = CryptoPrimitives.AesCbcEncrypt(key.AesKey, iv, compressed.ToArray());

        var withoutMac = new byte[IvLen + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, withoutMac, 0, IvLen);
        Buffer.BlockCopy(ciphertext, 0, withoutMac, IvLen, ciphertext.Length);
        byte[] mac = CryptoPrimitives.HmacSha256(key.HmacKey, withoutMac);

        var file = new byte[withoutMac.Length + MacLen];
        Buffer.BlockCopy(withoutMac, 0, file, 0, withoutMac.Length);
        Buffer.BlockCopy(mac, 0, file, withoutMac.Length, MacLen);
        return file;
    }

    /// <summary>Serializes a BackupInfo + frames into the varint-delimited stream (test helper).</summary>
    public static byte[] WriteFrames(BackupInfo info, IEnumerable<Frame> frames)
    {
        using var ms = new MemoryStream();
        info.WriteDelimitedTo(ms);
        foreach (Frame f in frames) f.WriteDelimitedTo(ms);
        return ms.ToArray();
    }
}
