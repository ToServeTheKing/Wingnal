using System.Collections.Generic;
using System.Linq;
using Wingnal.Protocol.ZkGroup.Curve;

namespace Wingnal.Protocol.ZkGroup.Poksho;

/// <summary>
/// Byte-exact port of libsignal poksho's Sigma/Schnorr proof system for arbitrary linear relations
/// (Boneh-Shoup §19.5.3) over Ristretto255. A <see cref="Statement"/> is a set of equations
/// "P = Σ scalarᵢ·pointᵢ"; <see cref="Statement.Prove"/> produces a Fiat-Shamir proof of knowledge of the
/// witness scalars, and <see cref="Statement.VerifyProof"/> checks it. The Fiat-Shamir transcript uses
/// <see cref="ShoHmacSha256"/> with label "POKSHO_Ristretto_SHOHMACSHA256". zkgroup credentials are all
/// expressed as poksho statements. Validated against poksho's own prove/verify test vector.
/// </summary>
public sealed class Statement
{
    private static readonly byte[] Label =
        System.Text.Encoding.ASCII.GetBytes("POKSHO_Ristretto_SHOHMACSHA256");

    private readonly record struct Term(byte Scalar, byte Point);
    private readonly record struct Equation(byte Lhs, List<Term> Rhs);

    private readonly List<Equation> _equations = new();
    private readonly Dictionary<string, byte> _scalarMap = new();
    private readonly List<string> _scalarVec = new();
    private readonly Dictionary<string, byte> _pointMap = new() { ["G"] = 0 };
    private readonly List<string> _pointVec = new() { "G" };   // index 0 = Ristretto base point

    /// <summary>Adds the equation lhs = Σ (scalar·point) over the given (scalarName, pointName) terms.</summary>
    public void Add(string lhs, params (string scalar, string point)[] rhs)
    {
        if (string.IsNullOrEmpty(lhs) || rhs.Length == 0 || rhs.Length > 255 || _equations.Count >= 255)
            throw new ArgumentException("poksho: bad statement sizes");
        byte lhsIdx = AddPoint(lhs);
        var terms = new List<Term>(rhs.Length);
        foreach ((string s, string p) in rhs)
        {
            if (string.IsNullOrEmpty(s) || string.IsNullOrEmpty(p)) throw new ArgumentException("poksho: empty name");
            terms.Add(new Term(AddScalar(s), AddPoint(p)));
        }
        _equations.Add(new Equation(lhsIdx, terms));
    }

    private byte AddScalar(string name)
    {
        if (_scalarMap.TryGetValue(name, out byte i)) return i;
        byte idx = checked((byte)_scalarMap.Count);
        _scalarMap[name] = idx; _scalarVec.Add(name);
        return idx;
    }

    private byte AddPoint(string name)
    {
        if (_pointMap.TryGetValue(name, out byte i)) return i;
        byte idx = checked((byte)_pointMap.Count);
        _pointMap[name] = idx; _pointVec.Add(name);
        return idx;
    }

    internal byte[] ToBytes()
    {
        var v = new List<byte> { (byte)_equations.Count };
        foreach (Equation e in _equations)
        {
            v.Add(e.Lhs);
            v.Add((byte)e.Rhs.Count);
            foreach (Term t in e.Rhs) { v.Add(t.Scalar); v.Add(t.Point); }
        }
        return v.ToArray();
    }

    private Scalar25519[] SortScalars(IReadOnlyDictionary<string, Scalar25519> args)
    {
        if (args.Count != _scalarVec.Count) throw new ArgumentException("poksho: wrong number of scalar args");
        return _scalarVec.Select(n => args.TryGetValue(n, out Scalar25519 s)
            ? s : throw new ArgumentException($"poksho: missing scalar {n}")).ToArray();
    }

    private Ristretto255[] SortPoints(IReadOnlyDictionary<string, Ristretto255> args)
    {
        if (args.Count != _pointVec.Count - 1) throw new ArgumentException("poksho: wrong number of point args");
        var pts = new Ristretto255[_pointVec.Count];
        pts[0] = Ristretto255.BasePoint;
        for (int i = 1; i < _pointVec.Count; i++)
            pts[i] = args.TryGetValue(_pointVec[i], out Ristretto255? p)
                ? p! : throw new ArgumentException($"poksho: missing point {_pointVec[i]}");
        return pts;
    }

    // commitment[eq] = Σ g1[scalar]·points[point]  (+ (-challenge)·points[lhs] when verifying)
    private Ristretto255[] Homomorphism(Scalar25519[] g1, Ristretto255[] points, Scalar25519? challenge)
    {
        var result = new Ristretto255[_equations.Count];
        for (int k = 0; k < _equations.Count; k++)
        {
            Equation e = _equations[k];
            Ristretto255 acc = Ristretto255.Identity;
            foreach (Term t in e.Rhs)
                acc = Ristretto255.Add(acc, points[t.Point].Multiply(g1[t.Scalar]));
            if (challenge is { } h)
                acc = Ristretto255.Add(acc, points[e.Lhs].Multiply(Scalar25519.Negate(h)));
            result[k] = acc;
        }
        return result;
    }

    public byte[] Prove(IReadOnlyDictionary<string, Scalar25519> scalarArgs,
        IReadOnlyDictionary<string, Ristretto255> pointArgs, byte[] message, byte[] randomness)
    {
        if (randomness.Length != 32) throw new ArgumentException("poksho: randomness must be 32 bytes");
        Scalar25519[] g1 = SortScalars(scalarArgs);
        Ristretto255[] allPoints = SortPoints(pointArgs);

        var sho = new ShoHmacSha256(Label);
        sho.Absorb(ToBytes());                                   // D
        foreach (Ristretto255 p in allPoints) sho.Absorb(p.Encode());   // A
        sho.Ratchet();

        // Synthetic nonce: hash randomness ‖ witness ‖ message in a forked transcript.
        ShoHmacSha256 sho2 = sho.Clone();
        sho2.Absorb(randomness);                                 // Z
        foreach (Scalar25519 s in g1) sho2.Absorb(s.ToBytes());  // a
        sho2.Ratchet();
        sho2.AbsorbAndRatchet(message);                          // M
        byte[] nonceBytes = sho2.SqueezeAndRatchet(g1.Length * 64);
        var nonce = new Scalar25519[g1.Length];
        for (int i = 0; i < g1.Length; i++)
            nonce[i] = Scalar25519.FromBytesModOrderWide(nonceBytes.AsSpan(i * 64, 64));

        Ristretto255[] commitment = Homomorphism(nonce, allPoints, null);
        foreach (Ristretto255 r in commitment) sho.Absorb(r.Encode());   // R
        sho.AbsorbAndRatchet(message);                          // M
        Scalar25519 challenge = Scalar25519.FromBytesModOrderWide(sho.SqueezeAndRatchet(64));

        var response = new Scalar25519[g1.Length];
        for (int i = 0; i < g1.Length; i++)
            response[i] = Scalar25519.Add(nonce[i], Scalar25519.Mul(g1[i], challenge));

        byte[] proof = SerializeProof(challenge, response);
        if (!VerifyProof(proof, pointArgs, message))            // self-check before returning
            throw new InvalidOperationException("poksho: proof failed self-verification");
        return proof;
    }

    public bool VerifyProof(byte[] proofBytes, IReadOnlyDictionary<string, Ristretto255> pointArgs, byte[] message)
    {
        if (!TryParseProof(proofBytes, out Scalar25519 challenge, out Scalar25519[] response)) return false;
        if (response.Length != _scalarVec.Count) return false;

        Ristretto255[] allPoints;
        try { allPoints = SortPoints(pointArgs); }
        catch (ArgumentException) { throw; }   // wrong number of point args is a usage error, not a failure

        var sho = new ShoHmacSha256(Label);
        sho.Absorb(ToBytes());
        foreach (Ristretto255 p in allPoints) sho.Absorb(p.Encode());
        sho.Ratchet();

        Ristretto255[] commitment = Homomorphism(response, allPoints, challenge);
        foreach (Ristretto255 r in commitment) sho.Absorb(r.Encode());
        sho.AbsorbAndRatchet(message);
        Scalar25519 expected = Scalar25519.FromBytesModOrderWide(sho.SqueezeAndRatchet(64));
        return expected.Equals(challenge);
    }

    private static byte[] SerializeProof(Scalar25519 challenge, Scalar25519[] response)
    {
        var v = new List<byte>(challenge.ToBytes());
        foreach (Scalar25519 s in response) v.AddRange(s.ToBytes());
        return v.ToArray();
    }

    private static bool TryParseProof(byte[] bytes, out Scalar25519 challenge, out Scalar25519[] response)
    {
        challenge = default; response = System.Array.Empty<Scalar25519>();
        if (bytes.Length == 0 || bytes.Length % 32 != 0) return false;
        int count = bytes.Length / 32;
        if (count < 2 || count > 257) return false;   // challenge + 1..256 responses
        Scalar25519? ch = Scalar25519.FromCanonicalBytes(bytes.AsSpan(0, 32));
        if (ch is null) return false;
        challenge = ch.Value;
        var resp = new Scalar25519[count - 1];
        for (int i = 1; i < count; i++)
        {
            Scalar25519? s = Scalar25519.FromCanonicalBytes(bytes.AsSpan(i * 32, 32));
            if (s is null) return false;
            resp[i - 1] = s.Value;
        }
        response = resp;
        return true;
    }
}
