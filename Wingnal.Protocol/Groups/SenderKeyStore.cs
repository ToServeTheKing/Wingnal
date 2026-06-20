using Wingnal.Protocol.State;

namespace Wingnal.Protocol.Groups;

/// <summary>Persists sender-key records, keyed by (sender address, distribution id). Mirrors
/// libsignal's SenderKeyStore.</summary>
public interface ISenderKeyStore
{
    void StoreSenderKey(SignalProtocolAddress sender, Guid distributionId, SenderKeyRecord record);
    SenderKeyRecord? LoadSenderKey(SignalProtocolAddress sender, Guid distributionId);
}

/// <summary>In-memory <see cref="ISenderKeyStore"/> for tests and the group crypto core.</summary>
public sealed class InMemorySenderKeyStore : ISenderKeyStore
{
    private readonly Dictionary<(SignalProtocolAddress, Guid), SenderKeyRecord> _store = new();

    public void StoreSenderKey(SignalProtocolAddress sender, Guid distributionId, SenderKeyRecord record) =>
        _store[(sender, distributionId)] = record;

    public SenderKeyRecord? LoadSenderKey(SignalProtocolAddress sender, Guid distributionId) =>
        _store.TryGetValue((sender, distributionId), out SenderKeyRecord? r) ? r : null;
}
