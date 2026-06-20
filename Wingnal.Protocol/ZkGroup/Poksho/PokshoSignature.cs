using System.Collections.Generic;
using Wingnal.Protocol.ZkGroup.Curve;

namespace Wingnal.Protocol.ZkGroup.Poksho;

/// <summary>
/// poksho's Schnorr signature (<c>poksho::sign</c>/<c>verify_signature</c>): a one-equation proof of
/// knowledge of the discrete log of a public key (<c>public_key = private_key·G</c>) bound to a message.
/// zkgroup signs each <c>GroupChange</c> with this (the server's sig key); the client verifies it before
/// applying a change. Reuses the byte-exact <see cref="Statement"/> engine, so signatures are interoperable
/// with libsignal. Validated against poksho's own signature vector.
/// </summary>
public static class PokshoSignature
{
    /// <summary>Verifies a 64-byte signature over <paramref name="message"/> by <paramref name="publicKey"/>.</summary>
    public static bool Verify(byte[] signature, Ristretto255 publicKey, byte[] message)
    {
        Statement st = SignatureStatement();
        var points = new Dictionary<string, Ristretto255> { ["public_key"] = publicKey };
        return st.VerifyProof(signature, points, message);
    }

    /// <summary>Produces a signature (needs the private scalar; mainly for offline testing).</summary>
    public static byte[] Sign(Scalar25519 privateKey, Ristretto255 publicKey, byte[] message, byte[] randomness)
    {
        Statement st = SignatureStatement();
        var scalars = new Dictionary<string, Scalar25519> { ["private_key"] = privateKey };
        var points = new Dictionary<string, Ristretto255> { ["public_key"] = publicKey };
        return st.Prove(scalars, points, message, randomness);
    }

    private static Statement SignatureStatement()
    {
        var st = new Statement();
        st.Add("public_key", ("private_key", "G"));   // G = the Ristretto basepoint (statement index 0)
        return st;
    }
}
