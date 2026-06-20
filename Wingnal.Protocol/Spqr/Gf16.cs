namespace Wingnal.Protocol.Spqr;

/// <summary>
/// Arithmetic in GF(2^16) with reduction polynomial 0x1100b, ported from Signal's
/// SparsePostQuantumRatchet (v1.5.1) <c>src/encoding/gf.rs</c>. This is the base field for the
/// Reed-Solomon-style erasure coding that "sparsely" spreads ML-KEM-768 keys/ciphertexts across
/// messages. Addition/subtraction are XOR; multiplication is carryless-multiply then reduce;
/// inversion is a^(2^16-2) via square-and-multiply.
/// </summary>
public readonly struct Gf16 : IEquatable<Gf16>
{
    public const uint Poly = 0x1100b;

    public static readonly Gf16 Zero = new(0);
    public static readonly Gf16 One = new(1);

    public ushort Value { get; }

    public Gf16(ushort value) => Value = value;

    public static Gf16 Add(Gf16 a, Gf16 b) => new((ushort)(a.Value ^ b.Value));
    public static Gf16 Sub(Gf16 a, Gf16 b) => new((ushort)(a.Value ^ b.Value));

    public static Gf16 Mul(Gf16 a, Gf16 b) => new(PolyReduce(PolyMul(a.Value, b.Value)));

    /// <summary>a / b = a * b^(2^16-2). Dividing by zero yields zero (matches the reference loop).</summary>
    public static Gf16 Div(Gf16 a, Gf16 b)
    {
        // out = self * other^(2+4+...+2^15) = self * other^(2^16-2) = self * inv(other).
        Gf16 square = b;
        Gf16 outp = a;
        for (int i = 1; i < 16; i++)
        {
            square = Mul(square, square);
            outp = Mul(outp, square);
        }
        return outp;
    }

    public static Gf16 Inv(Gf16 a) => Div(One, a);

    /// <summary>Carryless (polynomial) multiply of two 16-bit values into a 32-bit result.</summary>
    private static uint PolyMul(ushort a, ushort b)
    {
        uint acc = 0;
        uint me = a;
        for (int shift = 0; shift < 16; shift++)
            if ((b & (1 << shift)) != 0)
                acc ^= me << shift;
        return acc;
    }

    /// <summary>Reduce a 32-bit carryless product modulo POLY (a 17-bit polynomial) to 16 bits.</summary>
    private static ushort PolyReduce(uint v)
    {
        for (int bit = 31; bit >= 16; bit--)
            if ((v & (1u << bit)) != 0)
                v ^= Poly << (bit - 16);
        return (ushort)v;
    }

    public bool Equals(Gf16 other) => Value == other.Value;
    public override bool Equals(object? obj) => obj is Gf16 g && Equals(g);
    public override int GetHashCode() => Value;
    public override string ToString() => $"GF16({Value})";
}
