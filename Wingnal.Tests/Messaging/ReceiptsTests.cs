using Google.Protobuf;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos;
using Xunit;

namespace Wingnal.Tests.Messaging;

public class ReceiptsTests
{
    [Fact]
    public void Delivery_BuildsDeliveryReceiptWithTimestamps()
    {
        Content c = Receipts.Delivery(100, 200, 300);

        Assert.NotNull(c.ReceiptMessage);
        Assert.Equal(ReceiptMessage.Types.Type.Delivery, c.ReceiptMessage.Type);
        Assert.Equal(new ulong[] { 100, 200, 300 }, c.ReceiptMessage.Timestamp);
    }

    [Fact]
    public void Read_BuildsReadReceipt()
    {
        Content c = Receipts.Read(42);

        Assert.Equal(ReceiptMessage.Types.Type.Read, c.ReceiptMessage.Type);
        Assert.Equal(new ulong[] { 42 }, c.ReceiptMessage.Timestamp);
    }

    [Theory]
    [InlineData(true, TypingMessage.Types.Action.Started)]
    [InlineData(false, TypingMessage.Types.Action.Stopped)]
    public void Typing_MapsStartedStopped(bool started, TypingMessage.Types.Action expected)
    {
        Content c = Receipts.Typing(started, 1700000000000);

        Assert.NotNull(c.TypingMessage);
        Assert.Equal(expected, c.TypingMessage.Action);
        Assert.Equal(1700000000000UL, c.TypingMessage.Timestamp);
    }

    [Fact]
    public void Receipt_RoundTripsThroughContentSerialization()
    {
        // The wire bytes must parse back to the same receipt (this is what the peer's client sees).
        byte[] wire = Receipts.Delivery(1, 2).ToByteArray();
        Content parsed = Content.Parser.ParseFrom(wire);

        Assert.Equal(ReceiptMessage.Types.Type.Delivery, parsed.ReceiptMessage.Type);
        Assert.Equal(new ulong[] { 1, 2 }, parsed.ReceiptMessage.Timestamp);
    }
}
