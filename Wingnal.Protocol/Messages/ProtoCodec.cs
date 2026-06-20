namespace Wingnal.Protocol.Messages;

/// <summary>
/// Minimal hand-written protobuf wire encoder/decoder. The Signal ciphertext messages are tiny and
/// live in the Protocol layer (which intentionally has no protobuf-compiler dependency — that is
/// reserved for the Service layer), so we encode them directly. Wire types: 0 = varint, 2 = length.
/// </summary>
internal sealed class ProtoWriter
{
    private readonly List<byte> _buf = new();

    public void WriteUInt32(int field, uint value)
    {
        WriteTag(field, 0);
        WriteVarint(value);
    }

    public void WriteBytes(int field, byte[] value)
    {
        WriteTag(field, 2);
        WriteVarint((ulong)value.Length);
        _buf.AddRange(value);
    }

    public byte[] ToArray() => _buf.ToArray();

    private void WriteTag(int field, int wireType) => WriteVarint(((ulong)field << 3) | (uint)wireType);

    private void WriteVarint(ulong v)
    {
        while (v >= 0x80)
        {
            _buf.Add((byte)(v | 0x80));
            v >>= 7;
        }
        _buf.Add((byte)v);
    }
}

internal ref struct ProtoReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;

    public ProtoReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
    }

    public bool TryReadTag(out int field, out int wireType)
    {
        if (_pos >= _data.Length)
        {
            field = 0;
            wireType = 0;
            return false;
        }
        ulong tag = ReadVarint();
        field = (int)(tag >> 3);
        wireType = (int)(tag & 0x7);
        return true;
    }

    public uint ReadUInt32() => (uint)ReadVarint();

    public byte[] ReadBytes()
    {
        int len = (int)ReadVarint();
        byte[] result = _data.Slice(_pos, len).ToArray();
        _pos += len;
        return result;
    }

    public void SkipField(int wireType)
    {
        switch (wireType)
        {
            case 0: ReadVarint(); break;
            // Read the length varint first (it advances _pos), then skip that many bytes. Writing
            // `_pos += (int)ReadVarint()` would add to the pre-ReadVarint _pos and lose the length bytes.
            case 2: { int len = (int)ReadVarint(); _pos += len; break; }
            case 5: _pos += 4; break;
            case 1: _pos += 8; break;
            default: throw new FormatException($"unsupported wire type {wireType}");
        }
    }

    private ulong ReadVarint()
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            byte b = _data[_pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }
}
