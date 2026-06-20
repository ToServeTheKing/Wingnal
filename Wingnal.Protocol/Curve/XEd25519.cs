using System.Numerics;
using System.Security.Cryptography;

namespace Wingnal.Protocol.Curve;

/// <summary>
/// XEdDSA over Curve25519 / Ed25519 (Trevor Perrin's spec, as used by Signal).
/// Signs/verifies Ed25519-style signatures using a Montgomery (X25519) key pair, so the same
/// identity key can be used for both ECDH (X25519) and signatures.
///
/// Implemented on top of a compact, auditable BigInteger reference of the Ed25519 group
/// (<see cref="Ed25519Math"/>). Correctness of the underlying group/field/scalar arithmetic is
/// validated against RFC 8032 known-answer vectors; XEdDSA verify is validated against libsignal's
/// own curve25519 known-answer vector (XEd25519VectorTests).
///
/// Signal-specific detail: the Edwards public key's sign bit is NOT forced to 0. The signer stashes
/// A's natural sign bit in the high bit of s (s &lt; L leaves it free), and the verifier reads it from
/// signature[63] to reconstruct A with the correct sign before clearing the bit to parse s. (Our
/// signer happens to always produce sign-bit-0 keys, which is the special case libsignal accepts.)
/// </summary>
public static class XEd25519
{
    // hash_1 prefix per XEdDSA spec: little-endian encoding of (2^256 - 1 - 1) = 2^256 - 2.
    private static readonly byte[] Hash1Prefix = BuildHash1Prefix();

    // (L-1) as a 32-byte little-endian scalar, used to negate a scalar mod L (constant-time).
    private static readonly byte[] ScalarMinusOne = Ed25519Math.ToLe32(Ed25519Math.Mod(BigInteger.MinusOne, Ed25519Math.L));
    private static readonly byte[] Zero32 = new byte[32];

    private static byte[] BuildHash1Prefix()
    {
        var p = new byte[32];
        p[0] = 0xFE;
        for (int i = 1; i < 32; i++) p[i] = 0xFF;
        return p;
    }

    /// <summary>
    /// XEdDSA sign. <paramref name="privateKey"/> is the 32-byte (clamped) Montgomery/X25519
    /// private scalar, little-endian. <paramref name="random"/> must be 64 fresh random bytes.
    /// Returns a 64-byte signature (R || s).
    /// </summary>
    public static byte[] CalculateSignature(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> random)
    {
        if (privateKey.Length != 32) throw new ArgumentException("private key must be 32 bytes", nameof(privateKey));
        if (random.Length != 64) throw new ArgumentException("random must be 64 bytes", nameof(random));

        // Constant-time signing: the operations that touch the private key (the two fixed-base scalar
        // multiplies on the secret k and nonce r, and the scalar arithmetic mod L) run through Ed25519Ct
        // (BouncyCastle's constant-time field). The hash-to-scalar h is over public data (R, A, M) only,
        // so it stays on the BigInteger reference. Validated byte-identical to the reference (Ed25519CtTests).
        byte[] sk = privateKey.ToArray();

        // calculate_key_pair(k): A has sign bit 0; a is adjusted so that a·B == A.
        byte[] enc = Ed25519Ct.ScalarMultBaseEncode(sk);     // k·B
        int xOdd = (enc[31] >> 7) & 1;
        byte[] aEnc = (byte[])enc.Clone();
        aEnc[31] &= 0x7F;                                     // A's x is forced even (sign bit 0)

        var k64 = new byte[64];
        Array.Copy(sk, k64, 32);
        byte[] kModL = Ed25519Ct.ScReduce(k64);              // k mod L
        byte[] aBytes = xOdd == 1 ? Ed25519Ct.ScMulAdd(ScalarMinusOne, kModL, Zero32) : kModL;  // a = ±k mod L

        // r = hash_1(a || M || Z) mod L
        byte[] r;
        using (var sha = SHA512.Create())
        {
            sha.TransformBlock(Hash1Prefix, 0, Hash1Prefix.Length, null, 0);
            sha.TransformBlock(aBytes, 0, aBytes.Length, null, 0);
            TransformSpan(sha, message);
            TransformSpan(sha, random, final: true);
            r = Ed25519Ct.ScReduce(sha.Hash!);
        }

        byte[] rEnc = Ed25519Ct.ScalarMultBaseEncode(r);     // R = r·B

        // h = hash(R || A || M) mod L  (public inputs only)
        byte[] hBytes = Ed25519Math.ToLe32(HashToScalar(rEnc, aEnc, message));

        byte[] s = Ed25519Ct.ScMulAdd(hBytes, aBytes, r);    // s = h·a + r (mod L)

        var sig = new byte[64];
        Array.Copy(rEnc, 0, sig, 0, 32);
        Array.Copy(s, 0, sig, 32, 32);
        return sig;
    }

    /// <summary>
    /// XEdDSA verify. <paramref name="montgomeryPublicKey"/> is the 32-byte X25519 public key
    /// (Montgomery u-coordinate, little-endian). <paramref name="signature"/> is 64 bytes (R || s).
    /// </summary>
    public static bool VerifySignature(ReadOnlySpan<byte> montgomeryPublicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (montgomeryPublicKey.Length != 32 || signature.Length != 64) return false;

        // Mask the high bit per RFC 7748, then reject u >= p.
        Span<byte> u32 = stackalloc byte[32];
        montgomeryPublicKey.CopyTo(u32);
        u32[31] &= 0x7F;
        BigInteger u = Ed25519Math.FromLe(u32);
        if (u >= Ed25519Math.P) return false;

        // Montgomery u -> Edwards y = (u - 1) / (u + 1)
        BigInteger denom = Ed25519Math.Mod(u + 1, Ed25519Math.P);
        if (denom.IsZero) return false;
        BigInteger y = Ed25519Math.Mod((u - 1) * Ed25519Math.Inverse(denom), Ed25519Math.P);

        // Signal's curve25519 XEdDSA stashes the Edwards public key's sign bit in the high bit of s
        // (signature[63]); the verifier reads it back to reconstruct A with the correct sign, then
        // clears it before parsing s. Matches libsignal rust/core curve25519 verify_signature.
        int sign = (signature[63] & 0x80) >> 7;

        Span<byte> s32 = stackalloc byte[32];
        signature.Slice(32, 32).CopyTo(s32);
        s32[31] &= 0x7F;
        if ((s32[31] & 0xE0) != 0) return false;  // scalar out of range
        BigInteger s = Ed25519Math.FromLe(s32);

        // A = decode(y, sign-from-signature); its encoding carries that sign bit and is what's hashed.
        if (!Ed25519Math.TryDecode(y, sign, out Ed25519Math.Point a)) return false;
        byte[] aEnc = Ed25519Math.Encode(a);

        byte[] rEnc = signature.Slice(0, 32).ToArray();
        BigInteger h = HashToScalar(rEnc, aEnc, message);

        // R_check = s*B - h*A
        Ed25519Math.Point sB = Ed25519Math.ScalarMultBase(s);
        Ed25519Math.Point hA = Ed25519Math.ScalarMult(a, h);
        Ed25519Math.Point rCheck = Ed25519Math.Add(sB, hA.Negate());

        return CryptographicOperations.FixedTimeEquals(Ed25519Math.Encode(rCheck), rEnc);
    }

    private static BigInteger HashToScalar(byte[] rEnc, byte[] aEnc, ReadOnlySpan<byte> message)
    {
        using var sha = SHA512.Create();
        sha.TransformBlock(rEnc, 0, rEnc.Length, null, 0);
        sha.TransformBlock(aEnc, 0, aEnc.Length, null, 0);
        TransformSpan(sha, message, final: true);
        return Ed25519Math.ScReduce(sha.Hash!);
    }

    private static void TransformSpan(SHA512 sha, ReadOnlySpan<byte> data, bool final = false)
    {
        byte[] buf = data.ToArray();
        if (final)
            sha.TransformFinalBlock(buf, 0, buf.Length);
        else
            sha.TransformBlock(buf, 0, buf.Length, null, 0);
    }
}
