using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;

namespace Wingnal.Protocol.ZkGroup.ZkCredential;

/// <summary>A credential presentation proof (Chase-Perrin-Zaverucha §3.2/§4.1): the commitments plus the
/// poksho proof. Serialized with bincode (fixint, little-endian; Vec = u64 length prefix + elements).</summary>
public sealed class PresentationProof
{
    public Ristretto255 Cx0 = null!, Cx1 = null!, Cv = null!;
    public Ristretto255[] Cy = System.Array.Empty<Ristretto255>();
    public byte[] PokshoProof = System.Array.Empty<byte>();

    public byte[] Serialize()
    {
        var ms = new List<byte>();
        ms.AddRange(Cx0.Encode());
        ms.AddRange(Cx1.Encode());
        ms.AddRange(Cv.Encode());
        AddU64Le(ms, (ulong)Cy.Length);
        foreach (Ristretto255 p in Cy) ms.AddRange(p.Encode());
        AddU64Le(ms, (ulong)PokshoProof.Length);
        ms.AddRange(PokshoProof);
        return ms.ToArray();
    }

    private static void AddU64Le(List<byte> dst, ulong v)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        dst.AddRange(b.ToArray());
    }
}

internal struct AttrRef { public int? KeyIndex; public int First; public int Second; }

/// <summary>Builds a credential presentation (the anonymous proof sent to the verifying/storage server).</summary>
public sealed class PresentationProofBuilder
{
    private readonly byte[] _message;
    private readonly List<EncryptionKeyContext> _keys = new();
    private readonly List<AttrRef> _attrs = new();
    private readonly List<Ristretto255> _attrPoints = new() { Ristretto255.Identity };

    public PresentationProofBuilder(byte[] label, byte[]? message = null)
    {
        _ = label;   // label is ignored on the prover side (public attrs are server-provided)
        _message = message ?? System.Array.Empty<byte>();
    }

    public PresentationProofBuilder AddAttribute(Ristretto255[] points, EncryptionKeyContext key)
    {
        int first = _attrPoints.Count;
        _attrPoints.AddRange(points);
        if (_attrPoints.Count > CredentialSystem.NumSupportedAttrs)
            throw new ArgumentException("too many attribute points");
        int keyIndex = _keys.FindIndex(k => k.Id == key.Id);
        if (keyIndex < 0) { keyIndex = _keys.Count; _keys.Add(key); }
        _attrs.Add(new AttrRef { KeyIndex = keyIndex, First = first, Second = first + points.Length - 1 });
        return this;
    }

    public PresentationProof Present(CredentialPublicKey publicKey, Credential credential, byte[] randomness)
    {
        var s = CredentialSystem.SystemParams.Hardcoded;
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes("Signal_ZKCredential_Presentation_20230410"));
        sho.AbsorbAndRatchet(randomness);
        Scalar25519 z = sho.GetScalar();

        var cy = new Ristretto255[_attrPoints.Count];
        for (int i = 0; i < _attrPoints.Count; i++)
            cy[i] = Ristretto255.Add(s.GY[i].Multiply(z), _attrPoints[i]);
        Ristretto255 cx0 = Ristretto255.Add(s.GX0.Multiply(z), credential.U);
        Ristretto255 cv = Ristretto255.Add(s.GV.Multiply(z), credential.V);
        Ristretto255 cx1 = Ristretto255.Add(s.GX1.Multiply(z), credential.U.Multiply(credential.T));

        Scalar25519 z0 = Scalar25519.Negate(Scalar25519.Mul(z, credential.T));
        Ristretto255 ii = publicKey.IFor(_attrPoints.Count);
        Ristretto255 bigZ = ii.Multiply(z);

        var scalars = new Dictionary<string, Scalar25519> { ["z"] = z, ["t"] = credential.T, ["z0"] = z0 };
        foreach (EncryptionKeyContext k in _keys)
        {
            scalars[$"a1_{k.Id}"] = k.A1;
            scalars[$"a2_{k.Id}"] = k.A2;
            scalars[$"z1_{k.Id}"] = Scalar25519.Negate(Scalar25519.Mul(z, k.A1));
        }

        Dictionary<string, Ristretto255> points = PrepareNonAttrPoints(ii, cx0, cx1, cy);
        points["Z"] = bigZ;
        foreach (AttrRef attr in _attrs)
        {
            points[$"C_y{attr.First}"] = cy[attr.First];
            if (attr.KeyIndex is { } ki)
            {
                EncryptionKeyContext k = _keys[ki];
                Ristretto255 eA1 = _attrPoints[attr.First].Multiply(k.A1);
                Ristretto255 eA2 = Ristretto255.Add(eA1.Multiply(k.A2), _attrPoints[attr.Second]);
                points[$"E_A{attr.First}"] = eA1;
                points[$"-E_A{attr.First}"] = Ristretto255.Negate(eA1);
                points[$"C_y{attr.Second}-E_A{attr.Second}"] = Ristretto255.Add(cy[attr.Second], Ristretto255.Negate(eA2));
            }
        }

        byte[] poksho = BuildStatement(_keys, _attrs).Prove(scalars, points, _message, sho.SqueezeAndRatchet(32));
        return new PresentationProof { Cx0 = cx0, Cx1 = cx1, Cv = cv, Cy = cy, PokshoProof = poksho };
    }

    private Dictionary<string, Ristretto255> PrepareNonAttrPoints(
        Ristretto255 ii, Ristretto255 cx0, Ristretto255 cx1, Ristretto255[] cy)
    {
        var s = CredentialSystem.SystemParams.Hardcoded;
        var p = new Dictionary<string, Ristretto255>
        {
            ["I"] = ii, ["C_x0"] = cx0, ["C_x1"] = cx1, ["G_x0"] = s.GX0, ["G_x1"] = s.GX1,
        };
        if (_keys.Count > 0)
        {
            p["0"] = Ristretto255.Identity;
            Ristretto255 sumA = Ristretto255.Identity;
            bool any = false;
            foreach (EncryptionKeyContext k in _keys)
            {
                if (k.PublicKeyA is { } a)
                {
                    p[$"G_a1_{k.Id}"] = k.Ga1;
                    p[$"G_a2_{k.Id}"] = k.Ga2;
                    sumA = Ristretto255.Add(sumA, a);
                    any = true;
                }
            }
            if (any) p["sum(A)"] = sumA;
        }
        string[] gy = { "G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6" };
        for (int i = 0; i < _attrPoints.Count; i++) p[gy[i]] = s.GY[i];
        p["C_y0"] = cy[0];
        return p;
    }

    internal static Statement BuildStatement(List<EncryptionKeyContext> keys, List<AttrRef> attrs)
    {
        var st = new Statement();
        st.Add("Z", ("z", "I"));
        st.Add("C_x1", ("t", "C_x0"), ("z0", "G_x0"), ("z", "G_x1"));

        var sumTerms = new List<(string, string)>();
        foreach (EncryptionKeyContext k in keys)
        {
            st.Add("0", ($"z1_{k.Id}", "I"), ($"a1_{k.Id}", "Z"));
            if (k.PublicKeyA is not null)
            {
                sumTerms.Add(($"a1_{k.Id}", $"G_a1_{k.Id}"));
                sumTerms.Add(($"a2_{k.Id}", $"G_a2_{k.Id}"));
            }
        }
        if (sumTerms.Count > 0) st.Add("sum(A)", sumTerms.ToArray());

        foreach (AttrRef attr in attrs)
        {
            if (attr.KeyIndex is { } ki)
            {
                string id = keys[ki].Id;
                st.Add($"E_A{attr.First}", ($"a1_{id}", $"C_y{attr.First}"), ($"z1_{id}", $"G_y{attr.First}"));
                st.Add($"C_y{attr.Second}-E_A{attr.Second}",
                    ("z", $"G_y{attr.Second}"), ($"a2_{id}", $"-E_A{attr.First}"));
            }
            else
            {
                st.Add($"C_y{attr.First}", ("z", $"G_y{attr.First}"));
            }
        }
        st.Add("C_y0", ("z", "G_y0"));
        return st;
    }
}

/// <summary>Verifies a presentation (the verifying-server side; used here for offline round-trip testing).</summary>
public sealed class PresentationProofVerifier
{
    private readonly ShoHmacSha256 _publicAttrs;
    private readonly byte[] _message;
    private readonly List<EncryptionKeyContext> _keys = new();
    private readonly List<AttrRef> _attrs = new();
    private readonly List<Ristretto255> _attrPoints = new() { Ristretto255.Identity };

    public PresentationProofVerifier(byte[] label, byte[]? message = null)
    {
        _publicAttrs = new ShoHmacSha256(label);
        _message = message ?? System.Array.Empty<byte>();
    }

    public PresentationProofVerifier AddPublicAttributeU64(ulong value)
    {
        Span<byte> be = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(be, value);
        _publicAttrs.AbsorbAndRatchet(be);
        return this;
    }

    /// <summary>Adds an encrypted attribute (the ciphertext points) + the public encryption key context.</summary>
    public PresentationProofVerifier AddAttribute(Ristretto255[] ciphertextPoints, EncryptionKeyContext key)
    {
        int first = _attrPoints.Count;
        _attrPoints.AddRange(ciphertextPoints);
        int keyIndex = _keys.FindIndex(k => k.Id == key.Id);
        if (keyIndex < 0) { keyIndex = _keys.Count; _keys.Add(key); }
        _attrs.Add(new AttrRef { KeyIndex = keyIndex, First = first, Second = first + ciphertextPoints.Length - 1 });
        return this;
    }

    public bool Verify(CredentialKeyPair keyPair, PresentationProof proof)
    {
        _attrPoints[0] = _publicAttrs.GetPoint();
        if (proof.Cy.Length != _attrPoints.Count) return false;

        CredentialPrivateKey priv = keyPair.Private;
        // Z = C_V - W - x0·C_x0 - x1·C_x1 - Σ y_i·C_y_i - y0·M0
        Ristretto255 z = proof.Cv;
        z = Ristretto255.Add(z, Ristretto255.Negate(priv.BigW));
        z = Ristretto255.Add(z, Ristretto255.Negate(proof.Cx0.Multiply(priv.X0)));
        z = Ristretto255.Add(z, Ristretto255.Negate(proof.Cx1.Multiply(priv.X1)));
        for (int i = 0; i < proof.Cy.Length; i++)
            z = Ristretto255.Add(z, Ristretto255.Negate(proof.Cy[i].Multiply(priv.Y[i])));
        z = Ristretto255.Add(z, Ristretto255.Negate(_attrPoints[0].Multiply(priv.Y[0])));

        Ristretto255 ii = keyPair.Public.IFor(_attrPoints.Count);
        Dictionary<string, Ristretto255> points = PrepareNonAttrPoints(ii, proof.Cx0, proof.Cx1, proof.Cy);
        foreach (AttrRef attr in _attrs)
        {
            points[$"C_y{attr.First}"] = proof.Cy[attr.First];
            if (attr.KeyIndex is not null)
            {
                points[$"E_A{attr.First}"] = _attrPoints[attr.First];
                points[$"-E_A{attr.First}"] = Ristretto255.Negate(_attrPoints[attr.First]);
                points[$"C_y{attr.Second}-E_A{attr.Second}"] =
                    Ristretto255.Add(proof.Cy[attr.Second], Ristretto255.Negate(_attrPoints[attr.Second]));
            }
            else
            {
                z = Ristretto255.Add(z, Ristretto255.Negate(_attrPoints[attr.First].Multiply(priv.Y[attr.First])));
            }
        }
        points["Z"] = z;
        return PresentationProofBuilder.BuildStatement(_keys, _attrs).VerifyProof(proof.PokshoProof, points, _message);
    }

    private Dictionary<string, Ristretto255> PrepareNonAttrPoints(
        Ristretto255 ii, Ristretto255 cx0, Ristretto255 cx1, Ristretto255[] cy)
    {
        var s = CredentialSystem.SystemParams.Hardcoded;
        var p = new Dictionary<string, Ristretto255>
        {
            ["I"] = ii, ["C_x0"] = cx0, ["C_x1"] = cx1, ["G_x0"] = s.GX0, ["G_x1"] = s.GX1,
        };
        if (_keys.Count > 0)
        {
            p["0"] = Ristretto255.Identity;
            Ristretto255 sumA = Ristretto255.Identity;
            bool any = false;
            foreach (EncryptionKeyContext k in _keys)
            {
                if (k.PublicKeyA is { } a)
                {
                    p[$"G_a1_{k.Id}"] = k.Ga1; p[$"G_a2_{k.Id}"] = k.Ga2;
                    sumA = Ristretto255.Add(sumA, a); any = true;
                }
            }
            if (any) p["sum(A)"] = sumA;
        }
        string[] gy = { "G_y0", "G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6" };
        for (int i = 0; i < _attrPoints.Count; i++) p[gy[i]] = s.GY[i];
        p["C_y0"] = cy[0];
        return p;
    }
}
