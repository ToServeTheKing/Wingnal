using System.Security.Cryptography;
using System.Text;
using Wingnal.Service.Attachments;
using Xunit;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Offline validation of the attachment-download crypto primitive: a synthetic encrypted attachment
/// (built the way Signal encodes one — iv ‖ AES-256-CBC ‖ HMAC) decrypts back to plaintext, bucket
/// padding is truncated to the declared size, and digest / MAC tampering is rejected.
/// </summary>
public class AttachmentCipherTests
{
    private static byte[] Key() => RandomNumberGenerator.GetBytes(64);
    private static byte[] Iv() => RandomNumberGenerator.GetBytes(16);

    [Fact]
    public void RoundTrip_DecryptsToPlaintext()
    {
        byte[] key = Key();
        byte[] plaintext = Encoding.UTF8.GetBytes("the quick brown fox attachment payload");

        (byte[] blob, byte[] digest) = AttachmentCipher.Encrypt(plaintext, key, Iv());
        byte[] decrypted = AttachmentCipher.Decrypt(blob, key, digest, plaintext.Length);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_TruncatesBucketPaddingToDeclaredSize()
    {
        byte[] key = Key();
        byte[] plaintext = Encoding.UTF8.GetBytes("real content");
        // Signal pads the plaintext to a bucket before encrypting; the pointer's `size` is the real length.
        var padded = new byte[512];
        Array.Copy(plaintext, padded, plaintext.Length);

        (byte[] blob, byte[] digest) = AttachmentCipher.Encrypt(padded, key, Iv());
        byte[] decrypted = AttachmentCipher.Decrypt(blob, key, digest, plaintext.Length);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_RejectsDigestMismatch()
    {
        byte[] key = Key();
        (byte[] blob, byte[] digest) = AttachmentCipher.Encrypt(Encoding.UTF8.GetBytes("x"), key, Iv());
        digest[0] ^= 0x01;
        Assert.Throws<InvalidAttachmentException>(() => AttachmentCipher.Decrypt(blob, key, digest));
    }

    [Fact]
    public void Decrypt_RejectsMacMismatch()
    {
        byte[] key = Key();
        (byte[] blob, _) = AttachmentCipher.Encrypt(Encoding.UTF8.GetBytes("payload"), key, Iv());
        blob[20] ^= 0x01;   // flip a ciphertext byte; no digest given, so the MAC must catch it
        Assert.Throws<InvalidAttachmentException>(() => AttachmentCipher.Decrypt(blob, key, digest: null));
    }

    [Fact]
    public void Decrypt_RejectsWrongKeyLength()
    {
        (byte[] blob, _) = AttachmentCipher.Encrypt(Encoding.UTF8.GetBytes("payload"), Key(), Iv());
        Assert.Throws<InvalidAttachmentException>(() => AttachmentCipher.Decrypt(blob, new byte[32]));
    }
}
