using System.IO;

namespace Wingnal.Protocol.Spqr;

/// <summary>Length-prefixed binary helpers for the SPQR/session state serialization. The format is
/// local-only (never sent to a peer) — the ML-KEM Braid spec leaves state serialization
/// implementation-defined — so this compact custom encoding is sufficient.</summary>
internal static class Bin
{
    public static void WriteBlob(this BinaryWriter w, byte[] b)
    {
        w.Write(b.Length);
        w.Write(b);
    }

    public static byte[] ReadBlob(this BinaryReader r)
    {
        int n = r.ReadInt32();
        return r.ReadBytes(n);
    }
}
