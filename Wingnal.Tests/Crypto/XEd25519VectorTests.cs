using Wingnal.Protocol.Curve;
using Xunit;

namespace Wingnal.Tests.Crypto;

/// <summary>
/// Validates XEdDSA verify against libsignal's own known-answer vector
/// (rust/core/src/curve/curve25519.rs test_signature). The public key is the 32-byte Montgomery form;
/// the signed message is a 33-byte (0x05-prefixed) value treated as opaque bytes.
/// </summary>
public class XEd25519VectorTests
{
    [Fact]
    public void VerifySignature_LibsignalVector_Valid()
    {
        byte[] pub = TestHex.Decode("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64");
        byte[] msg = TestHex.Decode("05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a");
        byte[] sig = TestHex.Decode(
            "5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfb" +
            "ede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88");

        Assert.True(XEd25519.VerifySignature(pub, msg, sig), "libsignal XEdDSA vector must verify");
    }

    [Fact]
    public void VerifySignature_LibsignalVector_RejectsTamper()
    {
        byte[] pub = TestHex.Decode("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64");
        byte[] msg = TestHex.Decode("05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a");
        byte[] sig = TestHex.Decode(
            "5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfb" +
            "ede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88");
        sig[0] ^= 0x01;
        Assert.False(XEd25519.VerifySignature(pub, msg, sig));
    }
}
