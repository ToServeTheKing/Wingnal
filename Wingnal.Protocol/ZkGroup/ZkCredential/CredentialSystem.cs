using System.Text;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;

namespace Wingnal.Protocol.ZkGroup.ZkCredential;

/// <summary>
/// Port of libsignal's <c>zkcredential::credentials</c> — the algebraic-MAC credential system
/// (Chase-Perrin-Zaverucha §3.1) that AuthCredential/ProfileKeyCredential are built on. Supports up to
/// <see cref="NumSupportedAttrs"/> attribute points. The shared <see cref="SystemParams"/> generators are
/// derived via <see cref="ShoSha256"/> and gated against libsignal's hardcoded serialization.
/// </summary>
public static class CredentialSystem
{
    public const int NumSupportedAttrs = 7;   // 1 aggregate public + 3 two-point private attributes

    public sealed class SystemParams
    {
        // Always populated by Generate()'s object initializer (null! silences the constructor-exit check).
        public Ristretto255 GW = null!, GWprime = null!, GX0 = null!, GX1 = null!, GV = null!, GZ = null!;
        public Ristretto255[] GY = new Ristretto255[NumSupportedAttrs];

        public static readonly SystemParams Hardcoded = Generate();

        public static SystemParams Generate()
        {
            var sho = new ShoSha256(Encoding.ASCII.GetBytes(
                "Signal_ZKCredential_ConstantSystemParams_generate_20230410"));
            var p = new SystemParams
            {
                GW = sho.GetPoint(),
                GWprime = sho.GetPoint(),
                GX0 = sho.GetPoint(),
                GX1 = sho.GetPoint(),
                GV = sho.GetPoint(),
                GZ = sho.GetPoint(),
            };
            for (int i = 0; i < NumSupportedAttrs; i++) p.GY[i] = sho.GetPoint();
            return p;
        }

        /// <summary>bincode serialization: G_w‖G_wprime‖G_x0‖G_x1‖G_V‖G_z‖G_y[0..7] (13 × 32 = 416 bytes).</summary>
        public byte[] Serialize()
        {
            var b = new byte[13 * 32];
            int o = 0;
            foreach (Ristretto255 p in new[] { GW, GWprime, GX0, GX1, GV, GZ })
            { Array.Copy(p.Encode(), 0, b, o, 32); o += 32; }
            foreach (Ristretto255 p in GY) { Array.Copy(p.Encode(), 0, b, o, 32); o += 32; }
            return b;
        }
    }
}

/// <summary>A credential: the MAC (t, U, V) issued by the server over a set of attributes.</summary>
public sealed class Credential
{
    public Scalar25519 T;
    public Ristretto255 U;
    public Ristretto255 V;

    public Credential(Scalar25519 t, Ristretto255 u, Ristretto255 v) { T = t; U = u; V = v; }

    /// <summary>bincode: t(32)‖U(32)‖V(32) = 96 bytes.</summary>
    public byte[] Serialize()
    {
        var b = new byte[96];
        Array.Copy(T.ToBytes(), 0, b, 0, 32);
        Array.Copy(U.Encode(), 0, b, 32, 32);
        Array.Copy(V.Encode(), 0, b, 64, 32);
        return b;
    }

    public static Credential Deserialize(ReadOnlySpan<byte> b)
    {
        if (b.Length != 96) throw new ArgumentException("credential must be 96 bytes");
        Scalar25519 t = Scalar25519.FromCanonicalBytes(b[..32]) ?? throw new ArgumentException("bad t");
        Ristretto255 u = Ristretto255.Decode(b[32..64]) ?? throw new ArgumentException("bad U");
        Ristretto255 v = Ristretto255.Decode(b[64..96]) ?? throw new ArgumentException("bad V");
        return new Credential(t, u, v);
    }
}

/// <summary>The server's private credential key (only needed locally for tests / a verifying server).</summary>
public sealed class CredentialPrivateKey
{
    public Scalar25519 W, Wprime, X0, X1;
    public Ristretto255 BigW = null!;   // set by Generate()/FromPrivate() before use
    public Scalar25519[] Y = new Scalar25519[CredentialSystem.NumSupportedAttrs];

    public static CredentialPrivateKey Generate(byte[] randomness)
    {
        var sho = new ShoHmacSha256(Encoding.ASCII.GetBytes(
            "Signal_ZKCredential_CredentialPrivateKey_generate_20230410"));
        sho.AbsorbAndRatchet(randomness);
        var system = CredentialSystem.SystemParams.Hardcoded;
        var k = new CredentialPrivateKey();
        k.W = sho.GetScalar();
        k.BigW = system.GW.Multiply(k.W);
        k.Wprime = sho.GetScalar();
        k.X0 = sho.GetScalar();
        k.X1 = sho.GetScalar();
        for (int i = 0; i < CredentialSystem.NumSupportedAttrs; i++) k.Y[i] = sho.GetScalar();
        return k;
    }

    /// <summary>Produces the MAC over the attribute points (Chase-Perrin-Zaverucha §3.1).</summary>
    public Credential CredentialCore(Ristretto255[] m, ShoHmacSha256 sho)
    {
        if (m.Length > CredentialSystem.NumSupportedAttrs) throw new ArgumentException("too many attributes");
        Scalar25519 t = sho.GetScalar();
        Ristretto255 u = sho.GetPoint();
        // V = W + (x0 + x1·t)·U + Σ y_i·M_i
        Scalar25519 coeff = Scalar25519.Add(X0, Scalar25519.Mul(X1, t));
        Ristretto255 v = Ristretto255.Add(BigW, u.Multiply(coeff));
        for (int i = 0; i < m.Length; i++) v = Ristretto255.Add(v, m[i].Multiply(Y[i]));
        return new Credential(t, u, v);
    }
}

/// <summary>The server's public credential key the client uses to receive + present credentials.</summary>
public sealed class CredentialPublicKey
{
    public Ristretto255 CW = null!;   // set by FromPrivate() before use
    public Ristretto255[] I = new Ristretto255[CredentialSystem.NumSupportedAttrs - 1];   // I_2 .. I_7

    /// <summary>I for a credential with <paramref name="numAttrs"/> attribute points (≥2).</summary>
    public Ristretto255 IFor(int numAttrs) => I[numAttrs - 2];

    public static CredentialPublicKey FromPrivate(CredentialPrivateKey priv)
    {
        var system = CredentialSystem.SystemParams.Hardcoded;
        var pub = new CredentialPublicKey
        {
            CW = Ristretto255.Add(priv.BigW, system.GWprime.Multiply(priv.Wprime)),
        };
        // I_i = G_V - x0·G_x0 - x1·G_x1 - Σ_{j≤i} y_j·G_y_j
        Ristretto255 ii = system.GV;
        ii = Ristretto255.Add(ii, Ristretto255.Negate(system.GX0.Multiply(priv.X0)));
        ii = Ristretto255.Add(ii, Ristretto255.Negate(system.GX1.Multiply(priv.X1)));
        ii = Ristretto255.Add(ii, Ristretto255.Negate(system.GY[0].Multiply(priv.Y[0])));
        for (int n = 1; n < CredentialSystem.NumSupportedAttrs; n++)
        {
            ii = Ristretto255.Add(ii, Ristretto255.Negate(system.GY[n].Multiply(priv.Y[n])));
            pub.I[n - 1] = ii;
        }
        return pub;
    }

    /// <summary>bincode: C_W(32)‖I[6]·32 = 224 bytes.</summary>
    public byte[] Serialize()
    {
        var b = new byte[32 + 32 * (CredentialSystem.NumSupportedAttrs - 1)];
        Array.Copy(CW.Encode(), 0, b, 0, 32);
        for (int i = 0; i < I.Length; i++) Array.Copy(I[i].Encode(), 0, b, 32 + 32 * i, 32);
        return b;
    }

    public static CredentialPublicKey Deserialize(ReadOnlySpan<byte> b)
    {
        int expected = 32 + 32 * (CredentialSystem.NumSupportedAttrs - 1);
        if (b.Length != expected) throw new ArgumentException("bad CredentialPublicKey length");
        var pub = new CredentialPublicKey
        {
            CW = Ristretto255.Decode(b[..32]) ?? throw new ArgumentException("bad C_W"),
        };
        for (int i = 0; i < pub.I.Length; i++)
            pub.I[i] = Ristretto255.Decode(b.Slice(32 + 32 * i, 32)) ?? throw new ArgumentException("bad I");
        return pub;
    }
}

/// <summary>The server's credential key pair (private + derived public).</summary>
public sealed class CredentialKeyPair
{
    public CredentialPrivateKey Private { get; }
    public CredentialPublicKey Public { get; }

    private CredentialKeyPair(CredentialPrivateKey priv, CredentialPublicKey pub) { Private = priv; Public = pub; }

    public static CredentialKeyPair Generate(byte[] randomness)
    {
        var priv = CredentialPrivateKey.Generate(randomness);
        return new CredentialKeyPair(priv, CredentialPublicKey.FromPrivate(priv));
    }
}
