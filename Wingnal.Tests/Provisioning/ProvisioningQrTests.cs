using Wingnal.Service.Provisioning;
using Xunit;

namespace Wingnal.Tests.Provisioning;

public class ProvisioningQrTests
{
    [Fact]
    public void BuildQrUri_EncodesUuidAndPublicKey()
    {
        byte[] publicKey = Enumerable.Range(0, 33).Select(i => (byte)i).ToArray();
        string uri = ProvisioningManager.BuildQrUri("abc-123", publicKey);

        Assert.StartsWith("sgnl://linkdevice?uuid=abc-123&pub_key=", uri);
        // The base64 of the key contains '+' and '/' which must be percent-encoded in the URI.
        string expectedKey = Uri.EscapeDataString(Convert.ToBase64String(publicKey));
        Assert.EndsWith("pub_key=" + expectedKey, uri);
    }
}
