using Wingnal.Protocol.Messages;
using Xunit;

namespace Wingnal.Tests.Crypto;

public class ProtoReaderTests
{
    /// <summary>
    /// Regression: an unknown length-delimited field (wire type 2) must be skipped without losing the
    /// length-prefix byte, so following fields still parse. A buggy `_pos += (int)ReadVarint()` reads
    /// _pos before ReadVarint advances it, desyncing every later field (manifested as Signal's new
    /// pq_ratchet/addresses fields breaking decryption).
    /// </summary>
    [Fact]
    public void SkipField_UnknownLengthDelimited_DoesNotDesync()
    {
        var writer = new ProtoWriter();
        writer.WriteBytes(1, new byte[] { 0xAA, 0xBB, 0xCC });   // known field
        writer.WriteBytes(5, new byte[37]);                       // unknown (like pq_ratchet)
        writer.WriteBytes(6, new byte[36]);                       // unknown (like addresses)
        writer.WriteUInt32(2, 12345);                             // field after the unknowns
        byte[] bytes = writer.ToArray();

        var reader = new ProtoReader(bytes);
        byte[]? field1 = null;
        uint field2 = 0;
        while (reader.TryReadTag(out int field, out int wireType))
        {
            switch (field)
            {
                case 1: field1 = reader.ReadBytes(); break;
                case 2: field2 = reader.ReadUInt32(); break;
                default: reader.SkipField(wireType); break;
            }
        }

        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, field1);
        Assert.Equal(12345u, field2);
    }
}
