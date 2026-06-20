using Wingnal.Service.Messaging;
using Xunit;

namespace Wingnal.Tests.Messaging;

public class RecipientResolverTests
{
    [Theory]
    [InlineData("a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d")]
    [InlineData("A1B2C3D4-5E6F-4A7B-8C9D-0E1F2A3B4C5D", "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d")]
    [InlineData("  a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d  ", "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d")]
    public void Resolve_AcceptsAndNormalizesAci(string input, string expected)
    {
        RecipientResolver.Result r = RecipientResolver.Resolve(input);
        Assert.True(r.Ok);
        Assert.Equal(expected, r.ServiceId);
    }

    [Fact]
    public void Resolve_E164_IsNotSupportedYet()
    {
        RecipientResolver.Result r = RecipientResolver.Resolve("+15555550123");
        Assert.False(r.Ok);
        Assert.Contains("CDSI", r.Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-uuid")]
    [InlineData("alice@example.com")]
    public void Resolve_RejectsGarbage(string input)
    {
        RecipientResolver.Result r = RecipientResolver.Resolve(input);
        Assert.False(r.Ok);
        Assert.NotNull(r.Error);
    }
}
