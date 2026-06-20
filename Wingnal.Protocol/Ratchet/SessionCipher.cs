using Wingnal.Protocol.Crypto;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Protocol.Spqr;
using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Ratchet;

/// <summary>
/// Encrypts/decrypts messages for one peer using the Double Ratchet. Encrypt advances the sending
/// chain; decrypt performs DH ratchet steps on new ratchet keys and handles skipped (out-of-order)
/// message keys. Mirrors libsignal's SessionCipher.
/// </summary>
public sealed class SessionCipher
{
    private const int MaxSkip = 2000;

    private readonly ISessionStore _sessionStore;
    private readonly IPreKeyStore _preKeyStore;
    private readonly IIdentityKeyStore _identityStore;
    private readonly SignalProtocolAddress _remoteAddress;
    private readonly SessionBuilder _sessionBuilder;

    public SessionCipher(ISessionStore sessionStore, IPreKeyStore preKeyStore,
        ISignedPreKeyStore signedPreKeyStore, IKyberPreKeyStore kyberPreKeyStore,
        IIdentityKeyStore identityStore, SignalProtocolAddress remoteAddress)
    {
        _sessionStore = sessionStore;
        _preKeyStore = preKeyStore;
        _identityStore = identityStore;
        _remoteAddress = remoteAddress;
        _sessionBuilder = new SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
            kyberPreKeyStore, identityStore, remoteAddress);
    }

    public ICiphertextMessage Encrypt(byte[] plaintext)
    {
        SessionRecord record = _sessionStore.LoadSession(_remoteAddress);
        SessionState state = record.State;

        ChainKey chainKey = state.SenderChainKey ?? throw new InvalidOperationException("no sender chain");

        // Advance the Sparse Post-Quantum Ratchet (if enabled): the produced bytes ride in
        // SignalMessage.pq_ratchet, and the produced key salts the message-key derivation.
        byte[]? pqRatchet = null, pqrSalt = null;
        if (state.Spqr is not null)
        {
            SpqrRatchet.SendOutput sent = state.Spqr.Send();
            pqRatchet = sent.Message;
            pqrSalt = sent.Key;
        }

        MessageKeys messageKeys = chainKey.GetMessageKeys(pqrSalt);

        byte[] ciphertextBody = CryptoPrimitives.AesCbcEncrypt(messageKeys.CipherKey, messageKeys.Iv, plaintext);

        var signalMessage = new SignalMessage(state.SessionVersion, messageKeys.MacKey,
            state.SenderRatchetKeyPair!.PublicKey, chainKey.Index, state.PreviousCounter,
            ciphertextBody, state.LocalIdentity!, state.RemoteIdentity!, pqRatchet);

        ICiphertextMessage result = signalMessage;
        if (state.PendingPreKey is { } pending)
        {
            result = new PreKeySignalMessage(state.SessionVersion, state.LocalRegistrationId,
                pending.PreKeyId, pending.SignedPreKeyId, pending.KyberPreKeyId, pending.KyberCiphertext,
                pending.BaseKey, state.LocalIdentity!, signalMessage);
        }

        state.SenderChainKey = chainKey.Next();
        _sessionStore.StoreSession(_remoteAddress, record);
        return result;
    }

    public byte[] DecryptPreKeyMessage(PreKeySignalMessage message)
    {
        SessionRecord record = _sessionStore.ContainsSession(_remoteAddress)
            ? _sessionStore.LoadSession(_remoteAddress)
            : new SessionRecord();

        uint? unsignedPreKeyId = _sessionBuilder.Process(record, message);
        byte[] plaintext = Decrypt(record, message.Message);

        _sessionStore.StoreSession(_remoteAddress, record);
        if (unsignedPreKeyId.HasValue)
            _preKeyStore.RemovePreKey(unsignedPreKeyId.Value);

        return plaintext;
    }

    public byte[] DecryptSignalMessage(SignalMessage message)
    {
        SessionRecord record = _sessionStore.LoadSession(_remoteAddress);
        byte[] plaintext = Decrypt(record, message);
        _sessionStore.StoreSession(_remoteAddress, record);
        return plaintext;
    }

    private byte[] Decrypt(SessionRecord record, SignalMessage message)
    {
        try
        {
            return DecryptWithState(record.State, message);
        }
        catch (Exception ex) when (ex is InvalidMessageException or DuplicateMessageException)
        {
            foreach (SessionState previous in record.PreviousStates)
            {
                try { return DecryptWithState(previous, message); }
                catch (Exception inner) when (inner is InvalidMessageException or DuplicateMessageException) { }
            }
            throw;
        }
    }

    private byte[] DecryptWithState(SessionState state, SignalMessage message)
    {
        if (!state.HasSenderChain)
            throw new InvalidMessageException("uninitialized session");

        byte[] theirEphemeral = message.SenderRatchetKey;
        ChainKey chainKey = GetOrCreateChainKey(state, theirEphemeral);
        byte[] seed = GetOrCreateMessageSeed(state, theirEphemeral, chainKey, message.Counter);

        // Advance the SPQR receiving ratchet with this message's pq_ratchet bytes; the returned key
        // salts the message-key derivation (matching libsignal's per-message WhisperMessageKeys salt).
        byte[]? pqrSalt = state.Spqr?.Recv(message.PqRatchet ?? Array.Empty<byte>());
        MessageKeys messageKeys = ChainKey.DeriveMessageKeys(seed, pqrSalt, message.Counter);

        if (!message.VerifyMac(state.RemoteIdentity!, state.LocalIdentity!, messageKeys.MacKey))
            throw new InvalidMessageException("bad MAC");

        byte[] plaintext = CryptoPrimitives.AesCbcDecrypt(messageKeys.CipherKey, messageKeys.Iv, message.Body);
        state.PendingPreKey = null;
        return plaintext;
    }

    private static ChainKey GetOrCreateChainKey(SessionState state, byte[] theirEphemeral)
    {
        ReceiverChain? existing = state.FindReceiverChain(theirEphemeral);
        if (existing is not null)
            return existing.ChainKey;

        // New ratchet key from the peer: perform a DH ratchet step.
        RootKey rootKey = state.RootKey!;
        ECKeyPair ourEphemeral = state.SenderRatchetKeyPair!;
        (RootKey receiverRoot, ChainKey receiverChainKey) = rootKey.CreateChain(theirEphemeral, ourEphemeral);

        ECKeyPair ourNewEphemeral = Curve25519.GenerateKeyPair();
        (RootKey senderRoot, ChainKey senderChainKey) = receiverRoot.CreateChain(theirEphemeral, ourNewEphemeral);

        state.RootKey = senderRoot;
        state.AddReceiverChain(theirEphemeral, receiverChainKey);
        state.PreviousCounter = state.SenderChainKey!.Index == 0 ? 0 : state.SenderChainKey.Index - 1;
        state.SenderRatchetKeyPair = ourNewEphemeral;
        state.SenderChainKey = senderChainKey;

        return receiverChainKey;
    }

    // Returns the message-key SEED for the given counter (advancing/caching the DR chain as needed).
    // The SPQR salt is applied to the seed separately, so out-of-order messages each get their own salt.
    private static byte[] GetOrCreateMessageSeed(SessionState state, byte[] theirEphemeral, ChainKey chainKey, uint counter)
    {
        ReceiverChain chain = state.FindReceiverChain(theirEphemeral)!;

        if (chainKey.Index > counter)
        {
            if (chain.TryTakeMessageSeed(counter, out byte[] cached))
                return cached;
            throw new DuplicateMessageException($"message key for counter {counter} already used or skipped");
        }

        if (counter - chainKey.Index > MaxSkip)
            throw new InvalidMessageException("too many skipped messages");

        ChainKey current = chainKey;
        while (current.Index < counter)
        {
            chain.StoreMessageSeed(current.Index, current.MessageKeySeedBytes);
            current = current.Next();
        }

        chain.ChainKey = current.Next();
        return current.MessageKeySeedBytes;
    }
}
