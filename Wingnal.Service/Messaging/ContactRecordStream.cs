using Wingnal.Service.Protos;

namespace Wingnal.Service.Messaging;

/// <summary>One parsed contact from a contacts-sync blob: the record plus its inline avatar bytes (if
/// any).</summary>
public sealed record ContactRecord(ContactDetails Details, byte[]? Avatar);

/// <summary>
/// Parses the decrypted contacts-sync blob. The blob is a flat stream of records, each:
/// <c>[varint length][ContactDetails protobuf]</c>, immediately followed by <c>[avatar.length bytes]</c>
/// when the record declares an avatar. Mirrors Signal's DeviceContactsInputStream.
/// </summary>
public static class ContactRecordStream
{
    public static IReadOnlyList<ContactRecord> Parse(byte[] blob)
    {
        var result = new List<ContactRecord>();
        using var stream = new MemoryStream(blob, writable: false);

        while (stream.Position < stream.Length)
        {
            ContactDetails details = ContactDetails.Parser.ParseDelimitedFrom(stream);

            byte[]? avatar = null;
            if (details.Avatar is { } a && a.Length > 0)
            {
                avatar = new byte[a.Length];
                int read = stream.Read(avatar, 0, avatar.Length);
                if (read != avatar.Length)
                    throw new InvalidDataException("truncated contact avatar in sync blob");
            }

            result.Add(new ContactRecord(details, avatar));
        }

        return result;
    }
}
