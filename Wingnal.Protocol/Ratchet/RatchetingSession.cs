using System.Text;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Spqr;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Ratchet;

/// <summary>Initiator (Alice) X3DH/PQXDH inputs.</summary>
public sealed class AliceParameters
{
    public required IdentityKeyPair OurIdentityKey { get; init; }
    public required ECKeyPair OurBaseKey { get; init; }
    public required IdentityKey TheirIdentityKey { get; init; }
    public required byte[] TheirSignedPreKey { get; init; }   // raw 32
    public required byte[] TheirRatchetKey { get; init; }     // raw 32 (== signed prekey)
    public byte[]? TheirOneTimePreKey { get; init; }          // raw 32
    public byte[]? KyberSharedSecret { get; init; }           // from encapsulation (PQXDH)
}

/// <summary>Responder (Bob) X3DH/PQXDH inputs.</summary>
public sealed class BobParameters
{
    public required IdentityKeyPair OurIdentityKey { get; init; }
    public required ECKeyPair OurSignedPreKey { get; init; }
    public required ECKeyPair OurRatchetKey { get; init; }    // == signed prekey
    public ECKeyPair? OurOneTimePreKey { get; init; }
    public required IdentityKey TheirIdentityKey { get; init; }
    public required byte[] TheirBaseKey { get; init; }        // raw 32
    public byte[]? KyberSharedSecret { get; init; }           // from decapsulation (PQXDH)
}

/// <summary>
/// Builds the initial Double Ratchet state from X3DH/PQXDH agreements. The DH and (for PQXDH) Kyber
/// secrets are concatenated after 32 discontinuity bytes (0xFF), then HKDF "WhisperText" yields the
/// root and initial chain key. Initiator then performs one DH ratchet step to open its sending chain.
/// </summary>
public static class RatchetingSession
{
    private static readonly byte[] DiscontinuityBytes = BuildDiscontinuity();
    private static readonly byte[] DeriveInfo = Encoding.UTF8.GetBytes("WhisperText");
    // PQXDH uses a distinct HKDF label and derives an extra 32-byte slice (the SPQR auth_key) beyond
    // the root and chain keys. Matches libsignal pqxdh.rs HandshakeKeys::derive.
    private static readonly byte[] PqxdhDeriveInfo =
        Encoding.UTF8.GetBytes("WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024");

    public static void InitializeAlice(SessionState state, AliceParameters p)
    {
        state.SessionVersion = p.KyberSharedSecret is not null ? 4 : 3;
        state.LocalIdentity = p.OurIdentityKey.PublicKey;
        state.RemoteIdentity = p.TheirIdentityKey;

        ECKeyPair sendingRatchetKey = Curve25519.GenerateKeyPair();

        using var secrets = new MemoryStream();
        secrets.Write(DiscontinuityBytes);
        secrets.Write(Curve25519.CalculateAgreement(p.TheirSignedPreKey, p.OurIdentityKey.PrivateKey));   // DH1
        secrets.Write(Curve25519.CalculateAgreement(p.TheirIdentityKey.PublicKey, p.OurBaseKey.PrivateKey)); // DH2
        secrets.Write(Curve25519.CalculateAgreement(p.TheirSignedPreKey, p.OurBaseKey.PrivateKey));        // DH3
        if (p.TheirOneTimePreKey is not null)
            secrets.Write(Curve25519.CalculateAgreement(p.TheirOneTimePreKey, p.OurBaseKey.PrivateKey));   // DH4
        if (p.KyberSharedSecret is not null)
            secrets.Write(p.KyberSharedSecret);

        (RootKey rootKey, ChainKey chainKey, byte[]? authKey) = DeriveKeys(secrets.ToArray(), p.KyberSharedSecret is not null);
        state.SpqrAuthKey = authKey;
        state.Spqr = CreateSpqr(authKey, Direction.A2B);
        (RootKey sendingRoot, ChainKey sendingChain) = rootKey.CreateChain(p.TheirRatchetKey, sendingRatchetKey);

        state.AddReceiverChain(p.TheirRatchetKey, chainKey);
        state.SenderRatchetKeyPair = sendingRatchetKey;
        state.SenderChainKey = sendingChain;
        state.RootKey = sendingRoot;
        state.PreviousCounter = 0;
    }

    public static void InitializeBob(SessionState state, BobParameters p)
    {
        state.SessionVersion = p.KyberSharedSecret is not null ? 4 : 3;
        state.LocalIdentity = p.OurIdentityKey.PublicKey;
        state.RemoteIdentity = p.TheirIdentityKey;

        using var secrets = new MemoryStream();
        secrets.Write(DiscontinuityBytes);
        secrets.Write(Curve25519.CalculateAgreement(p.TheirIdentityKey.PublicKey, p.OurSignedPreKey.PrivateKey)); // DH1
        secrets.Write(Curve25519.CalculateAgreement(p.TheirBaseKey, p.OurIdentityKey.PrivateKey));               // DH2
        secrets.Write(Curve25519.CalculateAgreement(p.TheirBaseKey, p.OurSignedPreKey.PrivateKey));             // DH3
        if (p.OurOneTimePreKey is not null)
            secrets.Write(Curve25519.CalculateAgreement(p.TheirBaseKey, p.OurOneTimePreKey.PrivateKey));        // DH4
        if (p.KyberSharedSecret is not null)
            secrets.Write(p.KyberSharedSecret);

        (RootKey rootKey, ChainKey chainKey, byte[]? authKey) = DeriveKeys(secrets.ToArray(), p.KyberSharedSecret is not null);
        state.SpqrAuthKey = authKey;
        state.Spqr = CreateSpqr(authKey, Direction.B2A);

        state.SenderRatchetKeyPair = p.OurRatchetKey;
        state.SenderChainKey = chainKey;
        state.RootKey = rootKey;
        state.PreviousCounter = 0;
    }

    private static (RootKey, ChainKey, byte[]? AuthKey) DeriveKeys(byte[] masterSecret, bool pqxdh)
    {
        if (!pqxdh)
        {
            byte[] derived = CryptoPrimitives.Hkdf(masterSecret, salt: null, DeriveInfo, 64);
            return (new RootKey(derived.AsSpan(0, 32).ToArray()), new ChainKey(derived.AsSpan(32, 32).ToArray(), 0), null);
        }

        // PQXDH: HKDF expands to root[32] || chain[32] || pqr_key[32]; the last slice seeds SPQR.
        byte[] pq = CryptoPrimitives.Hkdf(masterSecret, salt: null, PqxdhDeriveInfo, 96);
        return (new RootKey(pq.AsSpan(0, 32).ToArray()), new ChainKey(pq.AsSpan(32, 32).ToArray(), 0),
            pq.AsSpan(64, 32).ToArray());
    }

    // Initialize the Sparse Post-Quantum Ratchet for a PQXDH (v4) session. Both ends mandate V1.
    // chain_params default to libsignal's non-self-session values (max_jump=25000, max_ooo=2000).
    private static SpqrRatchet? CreateSpqr(byte[]? authKey, Direction direction)
    {
        if (authKey is null) return null;
        return SpqrRatchet.InitialState(new SpqrParams
        {
            Direction = direction,
            Version = SpqrVersion.V1,
            MinVersion = SpqrVersion.V1,
            AuthKey = authKey,
            ChainParams = new ChainParams(),
        });
    }

    private static byte[] BuildDiscontinuity()
    {
        var bytes = new byte[32];
        Array.Fill(bytes, (byte)0xFF);
        return bytes;
    }
}
