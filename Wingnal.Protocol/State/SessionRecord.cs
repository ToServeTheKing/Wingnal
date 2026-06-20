using System.IO;

namespace Wingnal.Protocol.State;

/// <summary>
/// Wraps the current <see cref="SessionState"/> plus a bounded list of archived previous states.
/// Archiving (on re-keying / new session setup) lets the decryptor still process in-flight messages
/// encrypted under the prior session.
/// </summary>
public sealed class SessionRecord
{
    private const int MaxArchivedStates = 40;
    private readonly LinkedList<SessionState> _previousStates = new();

    public SessionState State { get; private set; }

    public SessionRecord() => State = new SessionState();

    public SessionRecord(SessionState state) => State = state;

    public IEnumerable<SessionState> PreviousStates => _previousStates;

    /// <summary>Moves the current state into the archive and starts a fresh one.</summary>
    public void ArchiveCurrentState()
    {
        if (!State.IsInitialized) return;
        _previousStates.AddFirst(State);
        while (_previousStates.Count > MaxArchivedStates)
            _previousStates.RemoveLast();
        State = new SessionState();
    }

    /// <summary>Serializes the current + archived states (durable session persistence).</summary>
    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        State.Write(w);
        w.Write(_previousStates.Count);
        foreach (SessionState prev in _previousStates) prev.Write(w);
        w.Flush();
        return ms.ToArray();
    }

    public static SessionRecord Deserialize(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        using var r = new BinaryReader(ms);
        var record = new SessionRecord(SessionState.Read(r));
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++) record._previousStates.AddLast(SessionState.Read(r));
        return record;
    }
}
