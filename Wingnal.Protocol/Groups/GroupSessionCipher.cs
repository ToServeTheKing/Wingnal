using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Groups;

/// <summary>
/// Encrypts/decrypts group messages with a sender key. Encrypt advances our own sending chain and
/// signs a SenderKeyMessage; decrypt selects the named chain, derives (and caches skipped) message
/// keys, verifies the signature, and AES-256-CBC decrypts. Mirrors libsignal's group_cipher.
/// </summary>
public sealed class GroupSessionCipher
{
    /// <summary>libsignal <c>consts::MAX_FORWARD_JUMPS</c> — reject messages too far in the future.</summary>
    private const int MaxForwardJumps = 25_000;

    private readonly ISenderKeyStore _store;

    public GroupSessionCipher(ISenderKeyStore store) => _store = store;

    /// <summary>Encrypts <paramref name="plaintext"/> under our sending chain for (sender,
    /// distributionId). Requires that <see cref="GroupSessionBuilder.Create"/> ran first.</summary>
    public SenderKeyMessage Encrypt(SignalProtocolAddress sender, Guid distributionId, byte[] plaintext)
    {
        SenderKeyRecord record = _store.LoadSenderKey(sender, distributionId)
            ?? throw new InvalidMessageException("no sender key to encrypt with");
        SenderKeyState state = record.State;
        if (state.SigningKeyPrivate is null)
            throw new InvalidMessageException("no private signing key (receive-only state)");

        SenderChainKey chainKey = state.ChainKey;
        SenderMessageKey messageKey = chainKey.MessageKey();

        byte[] ciphertext = CryptoPrimitives.AesCbcEncrypt(messageKey.CipherKey, messageKey.Iv, plaintext);

        var skm = new SenderKeyMessage(state.MessageVersion, distributionId, state.ChainId,
            messageKey.Iteration, ciphertext, state.SigningKeyPrivate);

        state.ChainKey = chainKey.Next();
        _store.StoreSenderKey(sender, distributionId, record);
        return skm;
    }

    /// <summary>Decrypts a received <paramref name="message"/> from <paramref name="sender"/>.</summary>
    public byte[] Decrypt(SignalProtocolAddress sender, SenderKeyMessage message)
    {
        SenderKeyRecord record = _store.LoadSenderKey(sender, message.DistributionId)
            ?? throw new InvalidMessageException("no sender key for this distribution");
        SenderKeyState state = record.StateForChainId(message.ChainId)
            ?? throw new InvalidMessageException($"no sender key state for chain id {message.ChainId}");

        if (!message.VerifySignature(state.SigningKeyPublic))
            throw new InvalidMessageException("invalid SenderKeyMessage signature");

        SenderMessageKey messageKey = GetMessageKey(state, message.Iteration);

        byte[] plaintext = CryptoPrimitives.AesCbcDecrypt(messageKey.CipherKey, messageKey.Iv, message.Ciphertext);
        _store.StoreSenderKey(sender, message.DistributionId, record);
        return plaintext;
    }

    // Mirrors libsignal get_sender_key: serve a cached past key, else advance (caching skipped keys)
    // up to the requested iteration. Bounded by MAX_FORWARD_JUMPS.
    private static SenderMessageKey GetMessageKey(SenderKeyState state, uint iteration)
    {
        SenderChainKey chainKey = state.ChainKey;
        uint current = chainKey.Iteration;

        if (current > iteration)
        {
            SenderMessageKey? cached = state.RemoveMessageKey(iteration);
            return cached ?? throw new DuplicateMessageException(
                $"message key for iteration {iteration} already used or skipped");
        }

        if (iteration - current > MaxForwardJumps)
            throw new InvalidMessageException("message from too far into the future");

        while (chainKey.Iteration < iteration)
        {
            state.AddMessageKey(chainKey.MessageKey());
            chainKey = chainKey.Next();
        }

        state.ChainKey = chainKey.Next();
        return chainKey.MessageKey();
    }
}
