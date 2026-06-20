using System.Linq;
using Wingnal.Service.Messaging;
using Xunit;

namespace Wingnal.Tests.Messaging;

public class MessageStoreTests
{
    private static MessageStore TempStore() =>
        new(Path.Combine(Path.GetTempPath(), "wingnal-msg-" + Guid.NewGuid().ToString("N") + ".db"));

    [Fact]
    public void Recent_IsScopedToOnePeer_OldestFirst()
    {
        MessageStore store = TempStore();
        store.Add(new StoredMessage("alice", "a1", 100, Outgoing: false));
        store.Add(new StoredMessage("bob", "b1", 150, Outgoing: true));
        store.Add(new StoredMessage("alice", "a2", 200, Outgoing: true));

        IReadOnlyList<StoredMessage> alice = store.Recent("alice");
        Assert.Equal(new[] { "a1", "a2" }, alice.Select(m => m.Body).ToArray());

        Assert.Equal(new[] { "b1" }, store.Recent("bob").Select(m => m.Body).ToArray());
    }

    [Fact]
    public void Recent_ReturnsNewestN_InChronologicalOrder()
    {
        MessageStore store = TempStore();
        for (int i = 0; i < 50; i++)
            store.Add(new StoredMessage("alice", $"m{i}", 1000 + i, Outgoing: false));

        // Ask for the most recent 10 — must be m40..m49 (NOT the oldest m0..m9), oldest-first for display.
        IReadOnlyList<StoredMessage> recent = store.Recent("alice", limit: 10);
        Assert.Equal(10, recent.Count);
        Assert.Equal("m40", recent[0].Body);
        Assert.Equal("m49", recent[^1].Body);
    }

    [Fact]
    public void Conversations_PicksNewestByTimestamp_NotInsertionOrder()
    {
        // Insert OUT of chronological order (as a bulk import does): the newest-timestamp message is NOT
        // the last inserted. The conversation must still report the newest by timestamp.
        MessageStore store = TempStore();
        store.Add(new StoredMessage("alice", "newest", 5000, Outgoing: false));   // inserted first
        store.Add(new StoredMessage("alice", "older", 1000, Outgoing: true));     // inserted last (higher id)

        IReadOnlyList<Conversation> convos = store.Conversations();
        Assert.Single(convos);
        Assert.Equal("newest", convos[0].LastBody);
        Assert.Equal(5000, convos[0].LastTimestamp);
    }

    [Fact]
    public void Deduplicate_RemovesExactDuplicates_KeepsOne()
    {
        MessageStore store = TempStore();
        store.Add(new StoredMessage("alice", "hi", 1000, Outgoing: true));
        store.Add(new StoredMessage("alice", "hi", 1000, Outgoing: true));   // exact dup (e.g. double-import)
        store.Add(new StoredMessage("alice", "different", 1000, Outgoing: true));

        int removed = store.Deduplicate();

        Assert.Equal(1, removed);
        Assert.Equal(new[] { "different", "hi" }, store.Recent("alice").Select(m => m.Body).OrderBy(b => b).ToArray());
    }

    [Fact]
    public void Conversations_OneRowPerPeer_LatestMessage_MostRecentFirst()
    {
        MessageStore store = TempStore();
        store.Add(new StoredMessage("alice", "a1", 100, Outgoing: false));
        store.Add(new StoredMessage("bob", "b1", 150, Outgoing: true));
        store.Add(new StoredMessage("alice", "a2 latest", 300, Outgoing: true));

        IReadOnlyList<Conversation> convos = store.Conversations();

        Assert.Equal(2, convos.Count);
        // alice's latest (ts 300) is most recent overall → first.
        Assert.Equal("alice", convos[0].Peer);
        Assert.Equal("a2 latest", convos[0].LastBody);
        Assert.True(convos[0].LastOutgoing);
        Assert.Equal("bob", convos[1].Peer);
        Assert.Equal("b1", convos[1].LastBody);
    }
}
