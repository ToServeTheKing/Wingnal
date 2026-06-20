using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>A group member's service id, encrypted under the group's UID key. Wire form is a reserved 0x00
/// byte followed by the 64-byte <see cref="AttributeCiphertext"/> (65 bytes total), matching zkgroup.</summary>
public readonly struct UuidCiphertext
{
    public readonly AttributeCiphertext Ciphertext;
    public UuidCiphertext(AttributeCiphertext ct) => Ciphertext = ct;

    public byte[] Serialize()
    {
        var b = new byte[65];
        Array.Copy(Ciphertext.Serialize(), 0, b, 1, 64);   // b[0] = reserved 0x00
        return b;
    }

    public static UuidCiphertext Deserialize(ReadOnlySpan<byte> bytes65)
    {
        if (bytes65.Length != 65 || bytes65[0] != 0) throw new ArgumentException("bad UuidCiphertext");
        return new UuidCiphertext(AttributeCiphertext.Deserialize(bytes65[1..]));
    }
}

/// <summary>A group member's profile key, encrypted under the group's profile-key key (reserved 0x00 ‖ 64).</summary>
public readonly struct ProfileKeyCiphertext
{
    public readonly AttributeCiphertext Ciphertext;
    public ProfileKeyCiphertext(AttributeCiphertext ct) => Ciphertext = ct;

    public byte[] Serialize()
    {
        var b = new byte[65];
        Array.Copy(Ciphertext.Serialize(), 0, b, 1, 64);
        return b;
    }

    public static ProfileKeyCiphertext Deserialize(ReadOnlySpan<byte> bytes65)
    {
        if (bytes65.Length != 65 || bytes65[0] != 0) throw new ArgumentException("bad ProfileKeyCiphertext");
        return new ProfileKeyCiphertext(AttributeCiphertext.Deserialize(bytes65[1..]));
    }
}
