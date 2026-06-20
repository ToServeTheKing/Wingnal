namespace Wingnal.Protocol.Ratchet;

/// <summary>The per-message keys derived from a chain key: AES-256 key, HMAC-SHA256 key, and IV.</summary>
public sealed class MessageKeys
{
    public byte[] CipherKey { get; }   // 32
    public byte[] MacKey { get; }      // 32
    public byte[] Iv { get; }          // 16
    public uint Counter { get; }

    public MessageKeys(byte[] cipherKey, byte[] macKey, byte[] iv, uint counter)
    {
        CipherKey = cipherKey;
        MacKey = macKey;
        Iv = iv;
        Counter = counter;
    }
}
