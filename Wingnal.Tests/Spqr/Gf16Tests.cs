using Wingnal.Protocol.Spqr;
using Xunit;

namespace Wingnal.Tests.Spqr;

public class Gf16Tests
{
    [Fact]
    public void EveryNonZeroElement_HasMultiplicativeInverse()
    {
        for (int i = 1; i <= 0xFFFF; i++)
        {
            var a = new Gf16((ushort)i);
            Gf16 inv = Gf16.Inv(a);
            Assert.Equal(Gf16.One, Gf16.Mul(a, inv));
        }
    }

    [Fact]
    public void Multiplication_IsCommutativeAndAssociative_AndDistributesOverAdd()
    {
        // A deterministic spread of values across the field.
        ushort[] xs = { 1, 2, 3, 0x100, 0x1234, 0x8001, 0xABCD, 0xFFFF, 0x55AA, 0x0F0F };
        foreach (ushort xi in xs)
            foreach (ushort yi in xs)
                foreach (ushort zi in xs)
                {
                    var x = new Gf16(xi);
                    var y = new Gf16(yi);
                    var z = new Gf16(zi);

                    Assert.Equal(Gf16.Mul(x, y), Gf16.Mul(y, x));
                    Assert.Equal(Gf16.Mul(Gf16.Mul(x, y), z), Gf16.Mul(x, Gf16.Mul(y, z)));
                    // x*(y+z) == x*y + x*z
                    Assert.Equal(
                        Gf16.Mul(x, Gf16.Add(y, z)),
                        Gf16.Add(Gf16.Mul(x, y), Gf16.Mul(x, z)));
                }
    }

    [Fact]
    public void Identities()
    {
        var a = new Gf16(0x1234);
        Assert.Equal(a, Gf16.Mul(a, Gf16.One));
        Assert.Equal(a, Gf16.Add(a, Gf16.Zero));
        Assert.Equal(Gf16.Zero, Gf16.Sub(a, a));
        Assert.Equal(a, Gf16.Div(a, Gf16.One));
        Assert.Equal(Gf16.One, Gf16.Div(a, a));
    }
}
