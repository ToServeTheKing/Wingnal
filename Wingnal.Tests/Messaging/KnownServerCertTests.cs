using Google.Protobuf;
using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Service.Messaging;
using Wingnal.Service.Protos.SealedSender;
using Xunit;

namespace Wingnal.Tests.Messaging;

/// <summary>
/// Regression for the live "not seeing others" bug: real Signal sender certificates reference the server
/// certificate by <c>id</c> (field 8) instead of embedding it, so the validator must resolve the id from a
/// known set. This checks that the embedded production server certificate (id 3) is authentic — signed by a
/// production unidentified-sender trust root — and that a sender cert using <c>signer.id = 3</c> gets past
/// the "has no server certificate" rejection (it now validates the resolved chain instead of throwing).
/// </summary>
public class KnownServerCertTests
{
    // The production server certificate (id 3) embedded in SenderCertificateValidator, from libsignal.
    private const string ProdServerCertId3 =
        "0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a" +
        "1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781";

    [Fact]
    public void ProductionServerCert_IsSignedByAProductionTrustRoot()
    {
        ServerCertificate server = ServerCertificate.Parser.ParseFrom(Convert.FromHexString(ProdServerCertId3));
        bool trusted = SenderCertificateValidator.ProductionTrustRoots.Any(root =>
            XEd25519.VerifySignature(Curve25519.DecodePoint(root), server.Certificate.Span, server.Signature.Span));
        Assert.True(trusted, "embedded production server cert (id 3) must verify against a production trust root");

        // And the server certificate's inner key-id matches the map key it is stored under.
        var inner = ServerCertificate.Types.Certificate.Parser.ParseFrom(server.Certificate);
        Assert.Equal(3u, inner.Id);
    }

    [Fact]
    public void SenderCert_WithSignerId_IsResolved_NotRejectedForMissingServerCert()
    {
        // A sender cert that references the server by id=3 (as real Signal certs do). It won't pass the
        // signature check (we can't forge the server's signature), but it must get PAST the
        // "has no server certificate" rejection — i.e. the id is resolved to the known server cert.
        var innerCert = new SenderCertificate.Types.Certificate
        {
            SenderDevice = 1,
            Expires = (ulong)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds(),
            IdentityKey = Google.Protobuf.ByteString.CopyFrom(Curve25519.GenerateKeyPair().PublicKey),
            UuidString = "11111111-2222-3333-4444-555555555555",
            Id = 3,
        };
        var cert = new SenderCertificate
        {
            Certificate = Google.Protobuf.ByteString.CopyFrom(innerCert.ToByteArray()),
            Signature = Google.Protobuf.ByteString.CopyFrom(new byte[64]),
        };

        InvalidMessageException ex = Assert.Throws<InvalidMessageException>(() =>
            SenderCertificateValidator.Validate(cert, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SenderCertificateValidator.ProductionTrustRoots));
        // Resolution succeeded; it failed later on the (forged) sender signature, not on a missing server cert.
        Assert.Equal("sender certificate not signed by the server", ex.Message);
    }
}
