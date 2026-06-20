using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.ZkCredential;

namespace Wingnal.Protocol.ZkGroup;

/// <summary>
/// Signal's published <c>ServerPublicParams</c> — the server's public credential/signature keys that every
/// client embeds (it is NOT derivable; like the pinned CA, it is fixed production data). We only need two of
/// its fields: the <see cref="GenericCredentialPublicKey"/> (to receive + present the AuthCredentialWithPni)
/// and the <see cref="SigPublicKey"/> (to verify the server's signature on a GroupChange).
///
/// Layout is bincode in struct-field order (total <c>SERVER_PUBLIC_PARAMS_LEN</c> = 673):
/// reserved(1) ‖ 6×oldCredentialPublicKey(64 = C_W‖I) with sig_public_key(32) as the 3rd field ‖
/// generic_credential_public_key(224 = C_W‖I[6]) ‖ endorsement_public_key(32). So sig = [129,161),
/// generic = [417,641).
/// </summary>
public sealed class ServerPublicParams
{
    public const int SerializedLen = 673;
    private const int SigPublicKeyOffset = 129;
    private const int GenericCredentialOffset = 417;
    private const int GenericCredentialLen = 224;

    public CredentialPublicKey GenericCredentialPublicKey { get; }
    public Ristretto255 SigPublicKey { get; }

    private ServerPublicParams(CredentialPublicKey generic, Ristretto255 sig)
    {
        GenericCredentialPublicKey = generic;
        SigPublicKey = sig;
    }

    public static ServerPublicParams Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != SerializedLen)
            throw new ArgumentException($"ServerPublicParams must be {SerializedLen} bytes, got {bytes.Length}");
        if (bytes[0] != 0) throw new ArgumentException("ServerPublicParams: bad reserved byte");
        Ristretto255 sig = Ristretto255.Decode(bytes.Slice(SigPublicKeyOffset, 32))
                           ?? throw new ArgumentException("ServerPublicParams: bad sig public key");
        CredentialPublicKey generic = CredentialPublicKey.Deserialize(
            bytes.Slice(GenericCredentialOffset, GenericCredentialLen));
        return new ServerPublicParams(generic, sig);
    }

    /// <summary>The base64 of Signal's PRODUCTION ServerPublicParams (from Signal-Android
    /// <c>BuildConfig.ZKGROUP_SERVER_PUBLIC_PARAMS</c>; the staging value differs).</summary>
    public const string ProductionBase64 =
        "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8" +
        "Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt" +
        "8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGv" +
        "CoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQF" +
        "j5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCn" +
        "ImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw" +
        "3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw" +
        "2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6w" +
        "kU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCW" +
        "JmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPV" +
        "OOmR0RW6bgRvc7DSF20V/omg+YBw==";

    private static readonly Lazy<ServerPublicParams> _production =
        new(() => Parse(Convert.FromBase64String(ProductionBase64)));

    /// <summary>The parsed production server public params.</summary>
    public static ServerPublicParams Production => _production.Value;
}
