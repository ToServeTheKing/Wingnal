using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Builds the small "sideband" <see cref="Content"/> messages that ride alongside chat: delivery/read
/// receipts (the ✓✓ that tells the sender we got/read their message) and typing notifications. Pure
/// (no network), so the wire shape is offline-testable.
/// </summary>
public static class Receipts
{
    /// <summary>A DELIVERY receipt acknowledging the message(s) with these sent-timestamps arrived.</summary>
    public static Content Delivery(params long[] sentTimestamps) =>
        Build(ReceiptMessage.Types.Type.Delivery, sentTimestamps);

    /// <summary>A READ receipt for the message(s) the user has now seen.</summary>
    public static Content Read(params long[] sentTimestamps) =>
        Build(ReceiptMessage.Types.Type.Read, sentTimestamps);

    /// <summary>A typing START/STOP notification for a 1:1 thread.</summary>
    public static Content Typing(bool started, long timestamp) => new()
    {
        TypingMessage = new TypingMessage
        {
            Action = started ? TypingMessage.Types.Action.Started : TypingMessage.Types.Action.Stopped,
            Timestamp = (ulong)timestamp,
        },
    };

    private static Content Build(ReceiptMessage.Types.Type type, IEnumerable<long> timestamps)
    {
        var receipt = new ReceiptMessage { Type = type };
        foreach (long t in timestamps) receipt.Timestamp.Add((ulong)t);
        return new Content { ReceiptMessage = receipt };
    }
}
