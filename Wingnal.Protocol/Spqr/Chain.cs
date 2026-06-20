using System.IO;
using Wingnal.Protocol.Crypto;

namespace Wingnal.Protocol.Spqr;

public enum Direction { A2B, B2A }

public static class DirectionExtensions
{
    public static Direction Switch(this Direction d) => d == Direction.A2B ? Direction.B2A : Direction.A2B;
}

/// <summary>A shared secret for a given ratchet epoch.</summary>
public sealed record EpochSecret(ulong Epoch, byte[] Secret);

/// <summary>Bounds for the symmetric chain (out-of-order tolerance / max forward jump).</summary>
public sealed class ChainParams
{
    public const uint DefaultMaxJump = 25_000;
    public const uint DefaultMaxOooKeys = 2_000;

    public uint MaxJump { get; init; } = DefaultMaxJump;
    public uint MaxOooKeys { get; init; } = DefaultMaxOooKeys;

    internal int TrimSize => (int)((long)MaxOooKeys * 11 / 10 + 1);
}

/// <summary>
/// SPQR symmetric key chain (ported from SparsePostQuantumRatchet v1.5.1 src/chain.rs). Per epoch and
/// direction it maintains a hash chain (HKDF) producing 32-byte keys; <see cref="SendKey"/> advances
/// it and <see cref="RecvKey"/> retrieves keys by index, tolerating out-of-order delivery via a
/// bounded key history. The A2B send chain matches the B2A receive chain (and vice versa).
/// </summary>
public sealed class Chain
{
    private static readonly byte[] ZeroSalt = new byte[32];
    private static readonly byte[] StartInfo = "Signal PQ Ratchet V1 Chain  Start"u8.ToArray(); // two spaces
    private static readonly byte[] NextInfo = "Signal PQ Ratchet V1 Chain Next"u8.ToArray();
    private static readonly byte[] AddEpochInfo = "Signal PQ Ratchet V1 Chain Add Epoch"u8.ToArray();
    private const int EpochsToKeepPriorToSendEpoch = 1;

    private sealed class KeyHistory
    {
        private const int KeySize = 4 + 32;
        private readonly List<byte> _data = new();

        /// <summary>Raw history bytes, for state serialization.</summary>
        public byte[] Data { get => _data.ToArray(); set { _data.Clear(); _data.AddRange(value); } }

        public void Add(uint idx, byte[] key)
        {
            _data.AddRange(Be32(idx));
            _data.AddRange(key);
        }

        public void Clear() => _data.Clear();

        public void Gc(uint currentKey, ChainParams p)
        {
            if (_data.Count < p.TrimSize * KeySize) return;
            uint horizon = currentKey - p.MaxOooKeys;
            int i = 0;
            while (i < _data.Count)
            {
                uint entryIdx = ReadBe32(i);
                if (horizon > entryIdx) RemoveAt(i);
                else i += KeySize;
            }
        }

        private void RemoveAt(int index)
        {
            int newEnd = _data.Count - KeySize;
            if (index + KeySize < _data.Count)
                for (int k = 0; k < KeySize; k++) _data[index + k] = _data[newEnd + k];
            _data.RemoveRange(newEnd, KeySize);
        }

        public byte[] Get(uint at, uint currentCtr, ChainParams p)
        {
            if (at + p.MaxOooKeys < currentCtr)
                throw new SpqrException($"key trimmed: {at}");
            for (int i = 0; i < _data.Count; i += KeySize)
                if (ReadBe32(i) == at)
                {
                    var outp = new byte[32];
                    for (int k = 0; k < 32; k++) outp[k] = _data[i + 4 + k];
                    RemoveAt(i);
                    return outp;
                }
            throw new SpqrException($"key already requested: {at}");
        }

        private uint ReadBe32(int i) =>
            (uint)((_data[i] << 24) | (_data[i + 1] << 16) | (_data[i + 2] << 8) | _data[i + 3]);
    }

    private sealed class ChainEpochDirection
    {
        public uint Ctr;
        public byte[] Next;
        public readonly KeyHistory Prev = new();

        public ChainEpochDirection(byte[] k) => Next = (byte[])k.Clone();

        public (uint Idx, byte[] Key) NextKey()
        {
            Ctr += 1;
            byte[] info = Concat(Be32(Ctr), NextInfo);
            byte[] gen = CryptoPrimitives.Hkdf(Next, ZeroSalt, info, 64);
            Next = gen[..32];
            return (Ctr, gen[32..64]);
        }

        public byte[] Key(uint at, ChainParams p)
        {
            if (at > Ctr)
            {
                if (at - Ctr > p.MaxJump) throw new SpqrException($"key jump {Ctr} -> {at}");
            }
            else if (at < Ctr)
            {
                return Prev.Get(at, Ctr, p);
            }
            else
            {
                throw new SpqrException($"key already requested: {at}");
            }

            if (at > Ctr + p.MaxOooKeys) Prev.Clear();
            while (at > Ctr + 1)
            {
                (uint idx, byte[] k) = NextKey();
                if (Ctr + p.MaxOooKeys >= at) Prev.Add(idx, k);
            }
            Prev.Gc(Ctr, p);
            return NextKey().Key;
        }

        public void ClearNext() => Next = Array.Empty<byte>();
    }

    private sealed class ChainEpoch
    {
        public required ChainEpochDirection Send;
        public required ChainEpochDirection Recv;
    }

    private readonly Direction _dir;
    private ulong _currentEpoch;
    private ulong _sendEpoch;
    private readonly LinkedList<ChainEpoch> _links = new();
    private byte[] _nextRoot;
    private readonly ChainParams _params;

    public Chain(byte[] initialKey, Direction dir, ChainParams parameters)
    {
        _dir = dir;
        _params = parameters;
        byte[] gen = CryptoPrimitives.Hkdf(initialKey, ZeroSalt, StartInfo, 96);
        _nextRoot = gen[0..32];
        _links.AddLast(new ChainEpoch
        {
            Send = CedForDirection(gen, dir),
            Recv = CedForDirection(gen, dir.Switch()),
        });
    }

    private static ChainEpochDirection CedForDirection(byte[] gen, Direction dir) =>
        new(dir == Direction.A2B ? gen[32..64] : gen[64..96]);

    public void AddEpoch(EpochSecret epochSecret)
    {
        if (epochSecret.Epoch != _currentEpoch + 1)
            throw new SpqrException($"epoch must be {_currentEpoch + 1}, got {epochSecret.Epoch}");
        byte[] gen = CryptoPrimitives.Hkdf(epochSecret.Secret, _nextRoot, AddEpochInfo, 96);
        _currentEpoch = epochSecret.Epoch;
        _nextRoot = gen[0..32];
        _links.AddLast(new ChainEpoch
        {
            Send = CedForDirection(gen, _dir),
            Recv = CedForDirection(gen, _dir.Switch()),
        });
    }

    private int EpochIdx(ulong epoch)
    {
        if (epoch > _currentEpoch) throw new SpqrException($"epoch out of range: {epoch}");
        int back = (int)(_currentEpoch - epoch);
        if (back >= _links.Count) throw new SpqrException($"epoch out of range: {epoch}");
        return _links.Count - 1 - back;
    }

    public (uint Index, byte[] Key) SendKey(ulong epoch)
    {
        if (epoch < _sendEpoch) throw new SpqrException($"send key epoch decreased {_sendEpoch} -> {epoch}");
        int epochIndex = EpochIdx(epoch);
        if (_sendEpoch != epoch)
        {
            _sendEpoch = epoch;
            while (epochIndex > EpochsToKeepPriorToSendEpoch)
            {
                _links.RemoveFirst();
                epochIndex--;
            }
            int i = 0;
            foreach (ChainEpoch link in _links)
            {
                if (i >= epochIndex) break;
                link.Send.ClearNext();
                i++;
            }
        }
        return LinkAt(epochIndex).Send.NextKey();
    }

    public byte[] RecvKey(ulong epoch, uint index) => LinkAt(EpochIdx(epoch)).Recv.Key(index, _params);

    private ChainEpoch LinkAt(int index)
    {
        LinkedListNode<ChainEpoch> node = _links.First!;
        for (int i = 0; i < index; i++) node = node.Next!;
        return node.Value;
    }

    private static byte[] Be32(uint v) => new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    // ── serialization (local-only state persistence) ──

    private Chain(Direction dir, ChainParams parameters)
    {
        _dir = dir;
        _params = parameters;
        _nextRoot = Array.Empty<byte>();
    }

    internal void Write(BinaryWriter w)
    {
        w.Write((int)_dir);
        w.Write(_currentEpoch);
        w.Write(_sendEpoch);
        w.WriteBlob(_nextRoot);
        w.Write(_params.MaxJump);
        w.Write(_params.MaxOooKeys);
        w.Write(_links.Count);
        foreach (ChainEpoch link in _links) { WriteDir(w, link.Send); WriteDir(w, link.Recv); }
    }

    private static void WriteDir(BinaryWriter w, ChainEpochDirection d)
    {
        w.Write(d.Ctr);
        w.WriteBlob(d.Next);
        w.WriteBlob(d.Prev.Data);
    }

    internal static Chain Read(BinaryReader r)
    {
        var dir = (Direction)r.ReadInt32();
        ulong cur = r.ReadUInt64();
        ulong send = r.ReadUInt64();
        byte[] nextRoot = r.ReadBlob();
        var p = new ChainParams { MaxJump = r.ReadUInt32(), MaxOooKeys = r.ReadUInt32() };
        var chain = new Chain(dir, p);
        chain._currentEpoch = cur;
        chain._sendEpoch = send;
        chain._nextRoot = nextRoot;
        int n = r.ReadInt32();
        for (int i = 0; i < n; i++)
            chain._links.AddLast(new ChainEpoch { Send = ReadDir(r), Recv = ReadDir(r) });
        return chain;
    }

    private static ChainEpochDirection ReadDir(BinaryReader r)
    {
        uint ctr = r.ReadUInt32();
        byte[] next = r.ReadBlob();
        byte[] prev = r.ReadBlob();
        var d = new ChainEpochDirection(next) { Ctr = ctr };
        d.Prev.Data = prev;
        return d;
    }
}

/// <summary>Errors from the SPQR layer.</summary>
public sealed class SpqrException : Exception
{
    public SpqrException(string message) : base(message) { }
}
