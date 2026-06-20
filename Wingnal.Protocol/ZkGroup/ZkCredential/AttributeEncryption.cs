using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;

namespace Wingnal.Protocol.ZkGroup.ZkCredential;

/// <summary>
/// Port of libsignal's <c>zkcredential::attributes</c> verifiable-encryption layer (Chase-Perrin-Zaverucha
/// §4.1). An attribute is a pair of Ristretto points (M1, M2). A <see cref="AttributeKeyPair"/> holds two
/// scalars (a1, a2); encryption is <c>E_A1 = a1·M1; E_A2 = a2·E_A1 + M2</c>. The verifying server can match
/// the ciphertext without learning the plaintext, which is how a group hides its members' ACIs/profile keys.
/// </summary>
public readonly struct AttributeCiphertext
{
    public readonly Ristretto255 EA1;
    public readonly Ristretto255 EA2;

    public AttributeCiphertext(Ristretto255 ea1, Ristretto255 ea2) { EA1 = ea1; EA2 = ea2; }

    /// <summary>The ciphertext as its own attribute (for chaining), per zkcredential.</summary>
    public Ristretto255[] AsPoints() => new[] { EA1, EA2 };

    /// <summary>64-byte serialization: E_A1‖E_A2 (each a 32-byte compressed Ristretto point).</summary>
    public byte[] Serialize()
    {
        var b = new byte[64];
        Array.Copy(EA1.Encode(), 0, b, 0, 32);
        Array.Copy(EA2.Encode(), 0, b, 32, 32);
        return b;
    }

    public static AttributeCiphertext Deserialize(ReadOnlySpan<byte> bytes64)
    {
        if (bytes64.Length != 64) throw new ArgumentException("ciphertext must be 64 bytes");
        Ristretto255 ea1 = Ristretto255.Decode(bytes64[..32]) ?? throw new ArgumentException("bad E_A1");
        Ristretto255 ea2 = Ristretto255.Decode(bytes64[32..64]) ?? throw new ArgumentException("bad E_A2");
        return new AttributeCiphertext(ea1, ea2);
    }
}

/// <summary>
/// A key for encrypting one kind of attribute (a domain). The private key is (a1, a2); the public key is
/// A = a1·G_a1 + a2·G_a2. Different domains use different generator points so ciphertexts can't be confused.
/// </summary>
public sealed class AttributeKeyPair
{
    public Scalar25519 A1 { get; }
    public Scalar25519 A2 { get; }
    public Ristretto255 PublicKey { get; }   // A

    private AttributeKeyPair(Scalar25519 a1, Scalar25519 a2, Ristretto255 publicKey)
    {
        A1 = a1; A2 = a2; PublicKey = publicKey;
    }

    /// <summary>Derives a deterministic key pair from the SHO state and the domain's generator points.</summary>
    public static AttributeKeyPair DeriveFrom(ShoHmacSha256 sho, Ristretto255 ga1, Ristretto255 ga2)
    {
        Scalar25519 a1 = Scalar25519.FromBytesModOrderWide(sho.SqueezeAndRatchet(64));
        Scalar25519 a2 = Scalar25519.FromBytesModOrderWide(sho.SqueezeAndRatchet(64));
        Ristretto255 a = Ristretto255.Add(ga1.Multiply(a1), ga2.Multiply(a2));
        return new AttributeKeyPair(a1, a2, a);
    }

    public static AttributeKeyPair FromScalars(Scalar25519 a1, Scalar25519 a2, Ristretto255 ga1, Ristretto255 ga2)
        => new(a1, a2, Ristretto255.Add(ga1.Multiply(a1), ga2.Multiply(a2)));

    /// <summary>Encrypts an attribute (M1, M2): E_A1 = a1·M1; E_A2 = a2·E_A1 + M2.</summary>
    public AttributeCiphertext Encrypt(Ristretto255 m1, Ristretto255 m2)
    {
        Ristretto255 ea1 = m1.Multiply(A1);
        Ristretto255 ea2 = Ristretto255.Add(ea1.Multiply(A2), m2);
        return new AttributeCiphertext(ea1, ea2);
    }

    /// <summary>Recovers M2 = E_A2 − a2·E_A1. Throws if E_A1 is the basepoint (a1 not actually encrypting).
    /// The caller MUST verify the decoded value re-encrypts to E_A1 (decode is otherwise garbage-in/out).</summary>
    public Ristretto255 DecryptToSecondPoint(AttributeCiphertext ct)
    {
        if (ct.EA1.ConstantTimeEquals(Ristretto255.BasePoint))
            throw new ZkGroupVerificationException("E_A1 is the basepoint");
        Ristretto255 a2EA1 = ct.EA1.Multiply(A2);
        return Ristretto255.Add(ct.EA2, Ristretto255.Negate(a2EA1));
    }
}

/// <summary>A zkgroup verification failure (a wrong key, forged ciphertext, or invalid proof).</summary>
public sealed class ZkGroupVerificationException : Exception
{
    public ZkGroupVerificationException(string message) : base(message) { }
}
