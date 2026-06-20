using System.Text;
using Wingnal.Service.Protos;
using Xunit;
using Xunit.Abstractions;

namespace Wingnal.Tests.Messaging;

/// <summary>Offline analysis of a captured failed envelope: walks the protobuf wire format of the
/// PreKeySignalMessage and its inner SignalMessage to locate where our parser misaligns.</summary>
[Trait("Category", "Live")]
public class EnvelopeDumpTests
{
    private readonly ITestOutputHelper _o;
    private readonly StringBuilder _sb = new();
    public EnvelopeDumpTests(ITestOutputHelper o) => _o = o;

    private void Log(string s) { _o.WriteLine(s); _sb.Append(s).Append('\n'); }

    [Fact]
    public void DumpCapturedEnvelope()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Packages", "cdb9e5d5-57cc-4e6a-954d-85bc9da6892e_cnsc1k9bd01st",
            "LocalCache", "Local", "Wingnal", "failed-envelope-2.bin");
        if (!File.Exists(path)) { Log($"missing {path}"); return; }

        var env = Envelope.Parser.ParseFrom(File.ReadAllBytes(path));
        byte[] content = env.Content.ToByteArray();
        Log($"envelope type={env.Type} contentLen={content.Length}");
        Log($"prekey version byte=0x{content[0]:x2}");

        Log("--- PreKeySignalMessage fields ---");
        Walk(content.AsSpan(1), inner =>
        {
            Log($"  inner message len={inner.Length} version=0x{inner[0]:x2}");
            int macLen = 8;
            Log($"  --- inner SignalMessage proto (bytes 1..{inner.Length - macLen}) ---");
            Walk(inner.AsSpan(1, inner.Length - 1 - macLen), null, "    ");

            Log("  --- replica of SignalMessage.Parse switch (logs each tag) ---");
            ReplicaParse(inner.AsSpan(1, inner.Length - 1 - macLen));

            try
            {
                Wingnal.Protocol.Messages.SignalMessage.Parse(inner);
                Log("  REAL SignalMessage.Parse(inner): OK");
            }
            catch (Exception ex)
            {
                Log($"  REAL SignalMessage.Parse(inner): THREW {ex.GetType().Name}: {ex.Message}");
            }

            Log("  --- REAL ProtoReader step trace ---");
            try
            {
                var reader = new Wingnal.Protocol.Messages.ProtoReader(inner.AsSpan(1, inner.Length - 1 - macLen));
                while (reader.TryReadTag(out int f, out int w))
                {
                    Log($"    realreader field={f} wire={w}");
                    switch (f)
                    {
                        case 1: Log($"      bytes len={reader.ReadBytes().Length}"); break;
                        case 2: Log($"      uint={reader.ReadUInt32()}"); break;
                        case 3: Log($"      uint={reader.ReadUInt32()}"); break;
                        case 4: Log($"      bytes len={reader.ReadBytes().Length}"); break;
                        default:
                            if (w == 2) Log($"      (default) bytes len={reader.ReadBytes().Length}");
                            else reader.SkipField(w);
                            break;
                    }
                }
                Log("    realreader: clean end");
            }
            catch (Exception ex)
            {
                Log($"    realreader THREW: {ex.GetType().Name}: {ex.Message}");
            }
        });

        // Run the REAL parser on every captured envelope to reproduce the failure.
        string dir = Path.GetDirectoryName(path)!;
        foreach (string f in Directory.GetFiles(dir, "failed-envelope-*.bin").OrderBy(x => x))
        {
            try
            {
                var e = Envelope.Parser.ParseFrom(File.ReadAllBytes(f));
                var pk = Wingnal.Protocol.Messages.PreKeySignalMessage.Parse(e.Content.ToByteArray());
                Log($"REAL parse {Path.GetFileName(f)}: OK kyberCtLen={pk.KyberCiphertext?.Length}");
            }
            catch (Exception ex)
            {
                Log($"REAL parse {Path.GetFileName(f)}: THREW {ex.GetType().Name}: {ex.Message}");
            }
        }

        string outDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wingnal");
        Directory.CreateDirectory(outDir);
        File.WriteAllText(Path.Combine(outDir, "dump.txt"), _sb.ToString());
    }

    /// <summary>Walks one protobuf message, logging each field. If <paramref name="onField4"/> is set,
    /// the field-4 bytes are passed to it (the PreKeySignalMessage's inner message).</summary>
    private void Walk(ReadOnlySpan<byte> data, Action<byte[]>? onField4, string indent = "  ")
    {
        int pos = 0;
        while (pos < data.Length)
        {
            ulong tag = ReadVarint(data, ref pos, out bool ok);
            if (!ok) { Log($"{indent}<tag varint overran at pos {pos}>"); return; }
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            if (wire == 0)
            {
                ulong v = ReadVarint(data, ref pos, out ok);
                Log($"{indent}field {field} varint = {v}{(ok ? "" : " <overran>")}");
                if (!ok) return;
            }
            else if (wire == 2)
            {
                int len = (int)ReadVarint(data, ref pos, out ok);
                if (!ok || pos + len > data.Length)
                {
                    Log($"{indent}field {field} len-delim len={len} OVERRUNS (pos={pos}, remaining={data.Length - pos})");
                    return;
                }
                Log($"{indent}field {field} bytes len={len}");
                if (onField4 is not null && field == 4)
                    onField4(data.Slice(pos, len).ToArray());
                pos += len;
            }
            else
            {
                Log($"{indent}field {field} UNSUPPORTED wire type {wire} at pos {pos} — MISALIGNED HERE");
                return;
            }
        }
        Log($"{indent}<clean end at pos {pos}/{data.Length}>");
    }

    /// <summary>Mirrors ProtoReader + the SignalMessage.Parse switch, logging pos before each tag and
    /// the exact byte consumed, to find where it diverges from a clean walk.</summary>
    private void ReplicaParse(ReadOnlySpan<byte> data)
    {
        int pos = 0;
        while (pos < data.Length)
        {
            int tagPos = pos;
            ulong tag = ReadVarint(data, ref pos, out bool ok);
            if (!ok) { Log($"    [replica] tag overran at {tagPos}"); return; }
            int field = (int)(tag >> 3);
            int wire = (int)(tag & 7);
            Log($"    [replica] pos={tagPos} tagByte=0x{data[tagPos]:x2} field={field} wire={wire}");
            switch (field)
            {
                case 1: // ratchet_key
                case 4: // ciphertext
                    int len = (int)ReadVarint(data, ref pos, out _);
                    pos += len;
                    break;
                case 2:
                case 3:
                    ReadVarint(data, ref pos, out _);
                    break;
                default:
                    if (wire == 0) ReadVarint(data, ref pos, out _);
                    else if (wire == 2) { int l = (int)ReadVarint(data, ref pos, out _); pos += l; }
                    else { Log($"    [replica] *** would throw: unsupported wire type {wire} ***"); return; }
                    break;
            }
        }
        Log($"    [replica] clean end at {pos}/{data.Length}");
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> data, ref int pos, out bool ok)
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            if (pos >= data.Length) { ok = false; return result; }
            byte b = data[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift > 63) { ok = false; return result; }
        }
        ok = true;
        return result;
    }
}
