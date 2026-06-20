using System.Security.Cryptography;

namespace Wingnal.Protocol.ZkGroup.Curve;

/// <summary>
/// The "Lizard" encoding from the curve25519-dalek-<b>signal</b> fork (NOT RFC 9496, NOT upstream dalek):
/// reversibly maps 16 bytes (a raw UUID) to a Ristretto255 point and back. zkgroup uses it to put a
/// member's ACI/PNI inside a homomorphically-encryptable group element (see <c>UidStruct.M2</c>).
///
/// Encode: <c>fe = SHA-256(data) with bytes[8..24] overwritten by data, low bit and top two bits cleared;
/// point = ElligatorRistrettoFlavor(fe)</c>. Decode inverts Elligator (up to 8 candidate field elements via
/// the Jacobi quartic) and keeps the unique one whose embedded bytes re-hash to itself.
///
/// Validated against the dalek-signal lizard test vectors (encode) + round-trip (decode).
/// NOT constant-time (data-dependent branching in decode) — acceptable for client-side group decryption.
/// </summary>
public static class Lizard
{
    /// <summary>Encodes 16 bytes to a Ristretto255 point.</summary>
    public static Ristretto255 Encode(ReadOnlySpan<byte> data16)
    {
        if (data16.Length != 16) throw new ArgumentException("Lizard.Encode expects 16 bytes");
        Span<byte> feBytes = stackalloc byte[32];
        SHA256.HashData(data16, feBytes);
        data16.CopyTo(feBytes[8..24]);
        feBytes[0] &= 254;    // make positive — Elligator on r and -r is the same
        feBytes[31] &= 63;    // < 2²⁵⁴
        return Ristretto255.FromSingleElligatorBytes(feBytes);
    }

    /// <summary>Recovers the 16 bytes from a Lizard-encoded point, or null if it isn't a valid encoding.</summary>
    public static byte[]? Decode(Ristretto255 p)
    {
        (byte mask, Fe[] fes) = p.ElligatorInverse();
        byte[]? result = null;
        int found = 0;
        Span<byte> recomputed = stackalloc byte[32];
        for (int j = 0; j < 8; j++)
        {
            if (((mask >> j) & 1) == 0) continue;
            byte[] buf = fes[j].Encode();                 // 32-byte canonical encoding
            SHA256.HashData(buf.AsSpan(8, 16), recomputed);
            buf.AsSpan(8, 16).CopyTo(recomputed[8..24]);
            recomputed[0] &= 254;
            recomputed[31] &= 63;
            if (!recomputed.SequenceEqual(buf)) continue;
            result = buf[8..24];
            found++;
        }
        return found == 1 ? result : null;
    }
}
