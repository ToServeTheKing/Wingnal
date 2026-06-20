namespace Wingnal.Service;

/// <summary>Shared service-id (ACI/PNI) byte helpers, so the binary→UUID conversion isn't reimplemented
/// in every store/decryptor. Uses the BCL's RFC-4122 big-endian Guid support.</summary>
public static class ServiceIds
{
    /// <summary>A service-id binary (16-byte ACI UUID, or 1-byte prefix + 16-byte PNI) → canonical
    /// lowercase UUID string, or null if malformed.</summary>
    public static string? StringFromBinary(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 17) bytes = bytes[1..];   // strip the service-id type prefix
        if (bytes.Length != 16) return null;
        return new Guid(bytes, bigEndian: true).ToString("D").ToLowerInvariant();
    }
}
