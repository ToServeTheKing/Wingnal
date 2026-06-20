using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Wingnal.Service.Net;

/// <summary>
/// Certificate pinning for Signal's service. chat.signal.org is served from Signal's own private
/// root CA (not a publicly trusted authority), so the OS trust store rejects it. This validates the
/// server chain against the bundled Signal root only — and trusts nothing else.
/// </summary>
public static class SignalTrust
{
    private static readonly X509Certificate2 SignalRootCa = LoadRootCa();

    /// <summary>Validation callback for <see cref="System.Net.Http.SocketsHttpHandler"/> and
    /// <see cref="System.Net.WebSockets.ClientWebSocket"/>: accept only chains anchored at the
    /// pinned Signal root with a matching hostname.</summary>
    public static bool Validate(object sender, X509Certificate? certificate, X509Chain? _, SslPolicyErrors errors)
    {
        // The hostname is checked by the TLS stack before this callback; never accept a mismatch.
        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            return false;
        if (certificate is null)
            return false;

        using var leaf = new X509Certificate2(certificate);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(SignalRootCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }

    private static X509Certificate2 LoadRootCa()
    {
        Assembly assembly = typeof(SignalTrust).Assembly;
        const string resource = "Wingnal.Service.Resources.signal-ca.pem";
        using Stream stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"embedded resource {resource} not found");
        using var reader = new StreamReader(stream);
        return X509Certificate2.CreateFromPem(reader.ReadToEnd());
    }
}
