using System.IO;

namespace Wingnal.Protocol.Spqr;

/// <summary>
/// Polynomial fountain/erasure code over GF(2^16), ported from Signal's SparsePostQuantumRatchet
/// v1.5.1 <c>src/encoding/polynomial.rs</c>. A message is split into <see cref="NumPolys"/>=16
/// polynomials (one per 2-byte symbol position, round-robin); chunk <c>idx</c> carries each
/// polynomial evaluated at x=idx (16 symbols = 32 bytes). The first ⌈M/16⌉ chunks are the message
/// itself (systematic); later chunks are redundancy. The decoder Lagrange-interpolates each
/// polynomial once it has enough points. Used to spread large ML-KEM-768 keys/ciphertexts across
/// many ratchet messages.
/// </summary>
public static class Polynomial
{
    public const int ChunkSize = 32;
    public const int NumPolys = ChunkSize / 2; // 16

    /// <summary>A polynomial over GF(2^16), coefficients low-order first (coeff[0] = constant term).</summary>
    public sealed class Poly
    {
        public Gf16[] Coefficients { get; }
        public Poly(Gf16[] coefficients) => Coefficients = coefficients;

        /// <summary>Evaluate f(x) via Horner's method.</summary>
        public Gf16 Evaluate(Gf16 x)
        {
            Gf16 acc = Gf16.Zero;
            for (int i = Coefficients.Length - 1; i >= 0; i--)
                acc = Gf16.Add(Gf16.Mul(acc, x), Coefficients[i]);
            return acc;
        }

        /// <summary>The unique polynomial through the given (x,y) points (distinct x). Standard Lagrange.</summary>
        public static Poly Interpolate((Gf16 X, Gf16 Y)[] points)
        {
            int n = points.Length;
            var coeffs = new Gf16[n];
            for (int i = 0; i < n; i++) coeffs[i] = Gf16.Zero;
            if (n == 0) return new Poly(coeffs);

            for (int i = 0; i < n; i++)
            {
                // basis_i(x) = PRODUCT_{m != i} (x - x_m) / (x_i - x_m), scaled by y_i.
                var basis = new Gf16[n];
                basis[0] = Gf16.One;
                int deg = 0;
                Gf16 denom = Gf16.One;
                for (int m = 0; m < n; m++)
                {
                    if (m == i) continue;
                    // multiply basis by (x - x_m): basis = basis*x + basis*(-x_m). (-x_m == x_m in GF(2^k))
                    var next = new Gf16[n];
                    for (int k = deg; k >= 0; k--)
                    {
                        // contribute basis[k] * x  -> next[k+1]
                        next[k + 1] = Gf16.Add(next[k + 1], basis[k]);
                        // contribute basis[k] * x_m -> next[k]
                        next[k] = Gf16.Add(next[k], Gf16.Mul(basis[k], points[m].X));
                    }
                    basis = next;
                    deg++;
                    denom = Gf16.Mul(denom, Gf16.Sub(points[i].X, points[m].X));
                }
                Gf16 scale = Gf16.Mul(points[i].Y, Gf16.Inv(denom));
                for (int k = 0; k < n; k++)
                    coeffs[k] = Gf16.Add(coeffs[k], Gf16.Mul(basis[k], scale));
            }
            return new Poly(coeffs);
        }
    }

    /// <summary>Encodes a message (even length) into an unbounded stream of 32-byte indexed chunks.</summary>
    public sealed class Encoder
    {
        private readonly List<Gf16>[] _data = new List<Gf16>[NumPolys];
        private readonly Poly?[] _polys = new Poly?[NumPolys];
        private uint _nextIdx;

        public Encoder(byte[] message)
        {
            if (message.Length % 2 != 0)
                throw new ArgumentException("message length must be even", nameof(message));
            for (int j = 0; j < NumPolys; j++) _data[j] = new List<Gf16>();
            for (int i = 0; i < message.Length / 2; i++)
            {
                ushort v = (ushort)((message[2 * i] << 8) | message[2 * i + 1]);
                _data[i % NumPolys].Add(new Gf16(v));
            }
        }

        public (ushort Index, byte[] Data) NextChunk()
        {
            ushort idx = (ushort)_nextIdx;
            _nextIdx++;
            return ChunkAt(idx);
        }

        public (ushort Index, byte[] Data) ChunkAt(ushort idx)
        {
            var data = new byte[ChunkSize];
            for (int j = 0; j < NumPolys; j++)
            {
                Gf16 v = PointAt(j, idx);
                data[2 * j] = (byte)(v.Value >> 8);
                data[2 * j + 1] = (byte)v.Value;
            }
            return (idx, data);
        }

        private Gf16 PointAt(int poly, int idx)
        {
            List<Gf16> pts = _data[poly];
            if (idx < pts.Count)
                return pts[idx]; // systematic: original data value

            // Redundancy point: interpolate (cached) and evaluate.
            Poly p = _polys[poly] ??= BuildPoly(pts);
            return p.Evaluate(new Gf16((ushort)idx));
        }

        private static Poly BuildPoly(List<Gf16> values)
        {
            var points = new (Gf16, Gf16)[values.Count];
            for (int x = 0; x < values.Count; x++)
                points[x] = (new Gf16((ushort)x), values[x]);
            return Poly.Interpolate(points);
        }

        private Encoder() { for (int j = 0; j < NumPolys; j++) _data[j] = new List<Gf16>(); }

        internal void Write(BinaryWriter w)
        {
            w.Write(_nextIdx);
            for (int j = 0; j < NumPolys; j++)
            {
                w.Write(_data[j].Count);
                foreach (Gf16 g in _data[j]) w.Write(g.Value);
            }
        }

        internal static Encoder Read(BinaryReader r)
        {
            var e = new Encoder();
            e._nextIdx = r.ReadUInt32();
            for (int j = 0; j < NumPolys; j++)
            {
                int c = r.ReadInt32();
                for (int k = 0; k < c; k++) e._data[j].Add(new Gf16(r.ReadUInt16()));
            }
            return e;
        }
    }

    /// <summary>Collects chunks until it can reconstruct the original <paramref name="lenBytes"/>-byte message.</summary>
    public sealed class Decoder
    {
        private readonly int _lenBytes;
        private readonly int _symbolCount;                 // M = lenBytes/2 GF16 symbols
        private readonly int[] _pointsPerPoly = new int[NumPolys];
        private readonly Dictionary<ushort, Gf16[]> _chunks = new(); // idx -> 16 symbols

        public Decoder(int lenBytes)
        {
            if (lenBytes % 2 != 0) throw new ArgumentException("length must be even", nameof(lenBytes));
            _lenBytes = lenBytes;
            _symbolCount = lenBytes / 2;
            for (int i = 0; i < _symbolCount; i++)
                _pointsPerPoly[i % NumPolys]++;
        }

        public void AddChunk(ushort index, byte[] data)
        {
            if (data.Length != ChunkSize) throw new ArgumentException("chunk must be 32 bytes", nameof(data));
            var symbols = new Gf16[NumPolys];
            for (int j = 0; j < NumPolys; j++)
                symbols[j] = new Gf16((ushort)((data[2 * j] << 8) | data[2 * j + 1]));
            _chunks[index] = symbols;
        }

        public bool CanReconstruct()
        {
            for (int j = 0; j < NumPolys; j++)
                if (_chunks.Count < _pointsPerPoly[j])
                    return false;
            // Every poly needs pointsPerPoly[j] distinct x; we have _chunks.Count distinct indices,
            // and max points-per-poly <= _chunks.Count is the binding constraint.
            return _chunks.Count >= MaxPoints();
        }

        public byte[]? DecodedMessage()
        {
            if (!CanReconstruct()) return null;

            // Sort received indices for determinism; use the first N for each poly.
            ushort[] indices = _chunks.Keys.OrderBy(k => k).ToArray();
            var msg = new byte[_lenBytes];

            for (int j = 0; j < NumPolys; j++)
            {
                int need = _pointsPerPoly[j];
                if (need == 0) continue;
                var points = new (Gf16, Gf16)[need];
                for (int k = 0; k < need; k++)
                {
                    ushort idx = indices[k];
                    points[k] = (new Gf16(idx), _chunks[idx][j]);
                }
                Poly p = Poly.Interpolate(points);
                for (int x = 0; x < need; x++)
                {
                    int pos = x * NumPolys + j; // message symbol position
                    if (pos >= _symbolCount) break;
                    Gf16 v = x < need ? p.Evaluate(new Gf16((ushort)x)) : Gf16.Zero;
                    msg[2 * pos] = (byte)(v.Value >> 8);
                    msg[2 * pos + 1] = (byte)v.Value;
                }
            }
            return msg;
        }

        private int MaxPoints()
        {
            int max = 0;
            for (int j = 0; j < NumPolys; j++) max = Math.Max(max, _pointsPerPoly[j]);
            return max;
        }

        internal void Write(BinaryWriter w)
        {
            w.Write(_lenBytes);
            w.Write(_chunks.Count);
            foreach (KeyValuePair<ushort, Gf16[]> kv in _chunks)
            {
                w.Write(kv.Key);
                foreach (Gf16 g in kv.Value) w.Write(g.Value);
            }
        }

        internal static Decoder Read(BinaryReader r)
        {
            var d = new Decoder(r.ReadInt32());
            int n = r.ReadInt32();
            for (int i = 0; i < n; i++)
            {
                ushort idx = r.ReadUInt16();
                var syms = new Gf16[NumPolys];
                for (int j = 0; j < NumPolys; j++) syms[j] = new Gf16(r.ReadUInt16());
                d._chunks[idx] = syms;
            }
            return d;
        }
    }
}
