namespace Wingnal.Service.Messaging;

/// <summary>Signal's PushTransportDetails padding: append a 0x80 terminator, then zero-pad to a 160-byte
/// multiple. Applied to a serialized <c>Content</c> before encryption (1:1 and group) and removed after
/// decryption. Shared by the 1:1 send/receive path and the group (Sender Key) path.</summary>
public static class MessagePadding
{
    public static byte[] Add(byte[] message)
    {
        var padded = new byte[PaddedLength(message.Length + 1) - 1];
        Array.Copy(message, padded, message.Length);
        padded[message.Length] = 0x80;
        return padded;
    }

    public static byte[] Strip(byte[] message)
    {
        int paddingStart = 0;
        for (int i = message.Length - 1; i >= 0; i--)
        {
            if (message[i] == 0x80) { paddingStart = i; break; }
            if (message[i] != 0x00) { paddingStart = message.Length; break; }
        }
        return message[..paddingStart];
    }

    private static int PaddedLength(int messageLength)
    {
        int withTerminator = messageLength + 1;
        int parts = withTerminator / 160;
        if (withTerminator % 160 != 0) parts++;
        return parts * 160;
    }
}
