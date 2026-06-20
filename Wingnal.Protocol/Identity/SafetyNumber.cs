using System.Security.Cryptography;
using System.Text;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Identity;

/// <summary>
/// Computes Signal's numeric "safety number" (a.k.a. fingerprint) for two identity keys, so a user can
/// verify out-of-band that they have the right keys for a contact — and detect a man-in-the-middle.
/// Byte-exact with libsignal v0.96.1 (rust/protocol/src/fingerprint.rs): per party, iterate
/// <c>SHA-512(prevHash ‖ key)</c> 5200× starting from <c>SHA-512(0x0000 ‖ key ‖ stableId ‖ key)</c>,
/// take 30 bytes as six 5-byte big-endian chunks mod 100000 (→ 30 digits), then concatenate the two
/// parties' halves in sorted order (so both sides see the same 60-digit number).
///
/// The modern (ACI-based) safety number uses version 2 and each party's 16-byte ACI UUID as the stable
/// identifier — matching what the official Signal app shows for the same contact.
/// </summary>
public static class SafetyNumber
{
    public const int DefaultIterations = 5200;

    /// <summary>The 60-digit safety number for the two parties (order-independent).</summary>
    public static string Generate(byte[] localStableId, IdentityKey localKey,
        byte[] remoteStableId, IdentityKey remoteKey, int iterations = DefaultIterations)
    {
        string local = Encode(GetFingerprint(iterations, localStableId, localKey));
        string remote = Encode(GetFingerprint(iterations, remoteStableId, remoteKey));
        // Sorted concatenation makes both participants compute the identical string.
        return string.CompareOrdinal(local, remote) <= 0 ? local + remote : remote + local;
    }

    /// <summary>Convenience for the ACI-based safety number: pass each party's ACI UUID.</summary>
    public static string GenerateForAci(Guid localAci, IdentityKey localKey, Guid remoteAci, IdentityKey remoteKey) =>
        Generate(UuidBytes(localAci), localKey, UuidBytes(remoteAci), remoteKey);

    /// <summary>Groups the 60 digits into the usual 12 blocks of 5 for display.</summary>
    public static string FormatForDisplay(string digits)
    {
        var sb = new StringBuilder(digits.Length + digits.Length / 5);
        for (int i = 0; i < digits.Length; i += 5)
        {
            if (i > 0) sb.Append(i % 25 == 0 ? '\n' : ' ');
            sb.Append(digits.AsSpan(i, Math.Min(5, digits.Length - i)));
        }
        return sb.ToString();
    }

    private static byte[] GetFingerprint(int iterations, byte[] stableId, IdentityKey key)
    {
        if (iterations <= 1) throw new ArgumentOutOfRangeException(nameof(iterations));
        byte[] keyBytes = key.Serialize();                 // 33-byte DjbECPublicKey

        // Iteration 0: SHA-512( 0x0000 ‖ key ‖ stableId ‖ key ).
        byte[] buf = SHA512.HashData(Concat(new byte[] { 0, 0 }, keyBytes, stableId, keyBytes));
        for (int i = 1; i < iterations; i++)
            buf = SHA512.HashData(Concat(buf, keyBytes));
        return buf;                                         // 64 bytes
    }

    private static string Encode(byte[] fingerprint)
    {
        var sb = new StringBuilder(30);
        for (int chunk = 0; chunk < 6; chunk++)
        {
            ulong x = 0;
            for (int i = 0; i < 5; i++)
                x = (x << 8) | fingerprint[chunk * 5 + i];
            sb.Append((x % 100000).ToString("D5"));
        }
        return sb.ToString();
    }

    /// <summary>A UUID's 16 bytes in RFC 4122 / big-endian order (the ACI service-id bytes).</summary>
    public static byte[] UuidBytes(Guid id) => id.ToByteArray(bigEndian: true);

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        int o = 0;
        foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, result, o, p.Length); o += p.Length; }
        return result;
    }
}
