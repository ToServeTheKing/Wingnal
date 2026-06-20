using System.Text;
using Wingnal.Protocol.State;
using Wingnal.Service.Crypto;
using Xunit;

namespace Wingnal.Tests.Crypto;

public class DeviceNameCipherTests
{
    [Theory]
    [InlineData("Wingnal")]
    [InlineData("A longer device name spanning more than one AES block")]
    public void EncryptDeviceName_RoundTrips(string name)
    {
        IdentityKeyPair identity = IdentityKeyPair.Generate();

        byte[] encrypted = DeviceNameCipher.EncryptDeviceName(name, identity);
        string? decrypted = DeviceNameCipher.DecryptDeviceName(encrypted, identity);

        Assert.Equal(name, decrypted);
    }

    [Fact]
    public void DecryptDeviceName_WrongIdentity_ReturnsNull()
    {
        IdentityKeyPair identity = IdentityKeyPair.Generate();
        IdentityKeyPair other = IdentityKeyPair.Generate();

        byte[] encrypted = DeviceNameCipher.EncryptDeviceName("Wingnal", identity);

        // Wrong identity yields a different master secret, so the synthetic-IV check fails.
        Assert.Null(DeviceNameCipher.DecryptDeviceName(encrypted, other));
    }
}
