using Wingnal.Protocol.Curve;
using Wingnal.Protocol.Messages;
using Wingnal.Service.Protos.SealedSender;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Validates a sealed-sender <see cref="SenderCertificate"/> against Signal's unidentified-sender trust
/// root: the trust root must have signed the embedded <see cref="ServerCertificate"/>, that server key
/// must have signed the sender certificate, and the certificate must not have expired. This is what
/// proves the claimed sender ACI/device is server-attested (not just self-asserted). Mirrors libsignal
/// sealed_sender.rs <c>SenderCertificate::validate</c>.
/// </summary>
public static class SenderCertificateValidator
{
    /// <summary>Signal's production unidentified-sender trust roots (33-byte DjbECPublicKey).</summary>
    public static readonly IReadOnlyList<byte[]> ProductionTrustRoots = new[]
    {
        Convert.FromBase64String("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"),
        Convert.FromBase64String("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6"),
    };

    /// <summary>Server certificates that real sender certificates reference by id (field 8) instead of
    /// embedding (field 5), to save space — keyed by id. From libsignal's <c>KNOWN_SERVER_CERTIFICATES</c>
    /// (id 2 = staging, id 3 = production). These are the full serialized <see cref="ServerCertificate"/> protobufs.</summary>
    private static readonly IReadOnlyDictionary<uint, byte[]> KnownServerCertificates = new Dictionary<uint, byte[]>
    {
        [2] = Convert.FromHexString(
            "0a25080212210539450d63ebd0752c0fd4038b9d07a916f5e174b756d409b5ca79f4c97400631e" +
            "124064c5a38b1e927497d3d4786b101a623ab34a7da3954fae126b04dba9d7a3604ed88cdc8550950f0d4a9134ceb7e19b94139151d2c3d6e1c81e9d1128aafca806"),
        [3] = Convert.FromHexString(
            "0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a" +
            "1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781"),
    };

    public static void Validate(SenderCertificate cert, long nowMs, IReadOnlyList<byte[]> trustRoots)
    {
        SenderCertificate.Types.Certificate inner =
            SenderCertificate.Types.Certificate.Parser.ParseFrom(cert.Certificate);

        // The signer is either embedded (field 5) or referenced by id (field 8); real Signal certs use the id.
        byte[] serverCertBytes = inner.SignerCase switch
        {
            SenderCertificate.Types.Certificate.SignerOneofCase.Certificate_ => inner.Certificate_.ToByteArray(),
            SenderCertificate.Types.Certificate.SignerOneofCase.Id when KnownServerCertificates.TryGetValue(inner.Id, out byte[]? c) => c,
            SenderCertificate.Types.Certificate.SignerOneofCase.Id =>
                throw new InvalidMessageException($"unknown sealed-sender server certificate id {inner.Id}"),
            _ => throw new InvalidMessageException("sender certificate has no server certificate"),
        };
        if ((long)inner.Expires < nowMs)
            throw new InvalidMessageException("sender certificate expired");

        // 1) The trust root must have signed the server certificate.
        ServerCertificate server = ServerCertificate.Parser.ParseFrom(serverCertBytes);
        bool serverTrusted = trustRoots.Any(root =>
            XEd25519.VerifySignature(Curve25519.DecodePoint(root),
                server.Certificate.Span, server.Signature.Span));
        if (!serverTrusted)
            throw new InvalidMessageException("server certificate not signed by a trust root");

        // 2) The server key must have signed the sender certificate.
        ServerCertificate.Types.Certificate serverInner =
            ServerCertificate.Types.Certificate.Parser.ParseFrom(server.Certificate);
        byte[] serverKey = Curve25519.DecodePoint(serverInner.Key.Span);
        if (!XEd25519.VerifySignature(serverKey, cert.Certificate.Span, cert.Signature.Span))
            throw new InvalidMessageException("sender certificate not signed by the server");
    }
}
