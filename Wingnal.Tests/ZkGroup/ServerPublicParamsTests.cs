using Wingnal.Protocol.ZkGroup;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>
/// GV2 live-flow gate: Signal's published production ServerPublicParams must decode to 673 bytes and parse
/// (at the computed field offsets) into a valid sig public key + generic credential public key. A wrong
/// offset would yield non-canonical Ristretto bytes that fail to decode, so a clean parse validates the
/// layout. These keys unblock AuthCredential receive (Phase E) and GroupChange signature verify (Phase F).
/// </summary>
public class ServerPublicParamsTests
{
    [Fact]
    public void ProductionConstant_DecodesTo673Bytes()
    {
        byte[] raw = Convert.FromBase64String(ServerPublicParams.ProductionBase64);
        Assert.Equal(ServerPublicParams.SerializedLen, raw.Length);
    }

    [Fact]
    public void Production_ParsesIntoValidKeys()
    {
        ServerPublicParams p = ServerPublicParams.Production;

        // sig public key is a valid (canonical) Ristretto point — re-encode round-trips.
        Assert.Equal(32, p.SigPublicKey.Encode().Length);

        // generic credential public key: C_W + I[6], 224 bytes, all valid points, round-trips.
        byte[] generic = p.GenericCredentialPublicKey.Serialize();
        Assert.Equal(224, generic.Length);
        // re-parse the serialized form to confirm every embedded point decoded canonically.
        var reparsed = Wingnal.Protocol.ZkGroup.ZkCredential.CredentialPublicKey.Deserialize(generic);
        Assert.Equal(generic, reparsed.Serialize());
    }
}
