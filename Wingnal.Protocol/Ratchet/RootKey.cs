using System.Text;
using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;

namespace Wingnal.Protocol.Ratchet;

/// <summary>
/// The Double Ratchet root key. A DH ratchet step derives a new root key and a fresh chain key from
/// the current root key (as HKDF salt) and a new DH output, with info "WhisperRatchet".
/// </summary>
public sealed class RootKey
{
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("WhisperRatchet");

    public byte[] Key { get; }

    public RootKey(byte[] key) => Key = key;

    public (RootKey RootKey, ChainKey ChainKey) CreateChain(byte[] theirRatchetKey, ECKeyPair ourRatchetKey)
    {
        byte[] dh = Curve25519.CalculateAgreement(theirRatchetKey, ourRatchetKey.PrivateKey);
        byte[] derived = CryptoPrimitives.Hkdf(dh, salt: Key, Info, 64);
        var newRootKey = new RootKey(derived.AsSpan(0, 32).ToArray());
        var newChainKey = new ChainKey(derived.AsSpan(32, 32).ToArray(), 0);
        return (newRootKey, newChainKey);
    }
}
