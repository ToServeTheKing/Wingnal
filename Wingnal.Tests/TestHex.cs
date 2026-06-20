namespace Wingnal.Tests;

internal static class TestHex
{
    public static byte[] Decode(string hex) => Convert.FromHexString(hex);

    public static string Encode(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
