using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;

namespace Wingnal.Protocol.ZkGroup.ZkCredential;

/// <summary>
/// Issuance + presentation proofs for the zkcredential MAC system (Chase-Perrin-Zaverucha §3.2 / §4.1),
/// expressed as poksho <see cref="Statement"/>s (reusing the byte-exact Schnorr engine). The client uses
/// <see cref="IssuanceProofBuilder"/> to verify a server-issued credential and
/// <see cref="PresentationProofBuilder"/> to build the anonymous presentation it sends to the verifying
/// (storage) server. <see cref="PresentationProofVerifier"/> is included for offline round-trip testing.
/// </summary>
public sealed class EncryptionKeyContext
{
    public string Id = "";
    public Ristretto255 Ga1 = Ristretto255.Identity;
    public Ristretto255 Ga2 = Ristretto255.Identity;
    public Scalar25519 A1, A2;          // present for the prover (KeyPair)
    public Ristretto255? PublicKeyA;    // the encryption public key A (present when key is "verified")
}

public sealed class IssuanceProof
{
    public Credential Credential = null!;
    public byte[] PokshoProof = System.Array.Empty<byte>();

    /// <summary>bincode: Credential(96) ‖ Vec&lt;u8&gt;(u64le len ‖ proof bytes).</summary>
    public byte[] Serialize()
    {
        var b = new List<byte>(Credential.Serialize());
        Span<byte> len = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(len, (ulong)PokshoProof.Length);
        b.AddRange(len.ToArray());
        b.AddRange(PokshoProof);
        return b.ToArray();
    }

    public static IssuanceProof Deserialize(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 96 + 8) throw new ArgumentException("IssuanceProof too short");
        var credential = Credential.Deserialize(bytes[..96]);
        ulong len = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(96, 8));
        if (96 + 8 + (int)len != bytes.Length) throw new ArgumentException("IssuanceProof length mismatch");
        return new IssuanceProof { Credential = credential, PokshoProof = bytes.Slice(104, (int)len).ToArray() };
    }
}

public sealed class IssuanceProofBuilder
{
    private readonly ShoHmacSha256 _publicAttrs;
    private readonly byte[] _message;
    private readonly List<Ristretto255> _attrPoints = new() { Ristretto255.Identity };  // [0] reserved for public

    public IssuanceProofBuilder(byte[] label, byte[]? message = null)
    {
        _publicAttrs = new ShoHmacSha256(label);
        _message = message ?? System.Array.Empty<byte>();
    }

    public IssuanceProofBuilder AddPublicAttributeU64(ulong value)
    {
        Span<byte> be = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(be, value);
        _publicAttrs.AbsorbAndRatchet(be);   // ratchet() after is a no-op (already ratcheted)
        return this;
    }

    public IssuanceProofBuilder AddAttribute(Ristretto255[] points)
    {
        _attrPoints.AddRange(points);
        if (_attrPoints.Count > CredentialSystem.NumSupportedAttrs)
            throw new ArgumentException("too many attribute points");
        return this;
    }

    private void FinalizePublicAttrs() => _attrPoints[0] = _publicAttrs.GetPoint();

    private Statement BuildStatement()
    {
        var st = new Statement();
        st.Add("C_W", ("w", "G_w"), ("wprime", "G_wprime"));

        var gvi = new (string, string)[]
        {
            ("x0", "G_x0"), ("x1", "G_x1"),
            ("y0", "G_y0"), ("y1", "G_y1"), ("y2", "G_y2"), ("y3", "G_y3"),
            ("y4", "G_y4"), ("y5", "G_y5"), ("y6", "G_y6"),
        };
        st.Add("G_V-I", gvi[..(2 + _attrPoints.Count)]);

        var vt = new (string, string)[]
        {
            ("w", "G_w"), ("x0", "U"), ("x1", "tU"),
            ("y0", "M0"), ("y1", "M1"), ("y2", "M2"), ("y3", "M3"),
            ("y4", "M4"), ("y5", "M5"), ("y6", "M6"),
        };
        st.Add("V", vt[..(3 + _attrPoints.Count)]);
        return st;
    }

    private Dictionary<string, Ristretto255> PointArgs(CredentialPublicKey key, Credential credential)
    {
        var s = CredentialSystem.SystemParams.Hardcoded;
        var p = new Dictionary<string, Ristretto255>
        {
            ["C_W"] = key.CW,
            ["G_w"] = s.GW,
            ["G_wprime"] = s.GWprime,
            ["G_V-I"] = Ristretto255.Add(s.GV, Ristretto255.Negate(key.IFor(_attrPoints.Count))),
            ["G_x0"] = s.GX0,
            ["G_x1"] = s.GX1,
            ["V"] = credential.V,
            ["U"] = credential.U,
            ["tU"] = credential.U.Multiply(credential.T),
        };
        string[] gy = { "G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6" };
        for (int i = 0; i < _attrPoints.Count; i++) p[gy[i]] = s.GY[i];
        string[] mn = { "M0", "M1", "M2", "M3", "M4", "M5", "M6" };
        for (int i = 0; i < _attrPoints.Count; i++) p[mn[i]] = _attrPoints[i];
        return p;
    }

    /// <summary>Verifies a server-issued credential, returning it on success.</summary>
    public Credential Verify(CredentialPublicKey publicKey, IssuanceProof proof)
    {
        FinalizePublicAttrs();
        Dictionary<string, Ristretto255> points = PointArgs(publicKey, proof.Credential);
        if (!BuildStatement().VerifyProof(proof.PokshoProof, points, _message))
            throw new ZkGroupVerificationException("issuance proof did not verify");
        return proof.Credential;
    }

    /// <summary>Issues a credential (server side; used for offline tests).</summary>
    public IssuanceProof Issue(CredentialKeyPair keyPair, byte[] randomness)
    {
        FinalizePublicAttrs();
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Signal_ZKCredential_Issuance_20230410"));
        sho.AbsorbAndRatchet(randomness);
        Credential credential = keyPair.Private.CredentialCore(_attrPoints.ToArray(), sho);

        var scalars = new Dictionary<string, Scalar25519>
        {
            ["w"] = keyPair.Private.W,
            ["wprime"] = keyPair.Private.Wprime,
            ["x0"] = keyPair.Private.X0,
            ["x1"] = keyPair.Private.X1,
        };
        string[] yn = { "y0", "y1", "y2", "y3", "y4", "y5", "y6" };
        for (int i = 0; i < _attrPoints.Count; i++) scalars[yn[i]] = keyPair.Private.Y[i];

        Dictionary<string, Ristretto255> points = PointArgs(keyPair.Public, credential);
        byte[] poksho = BuildStatement().Prove(scalars, points, _message, sho.SqueezeAndRatchet(32));
        return new IssuanceProof { Credential = credential, PokshoProof = poksho };
    }
}
