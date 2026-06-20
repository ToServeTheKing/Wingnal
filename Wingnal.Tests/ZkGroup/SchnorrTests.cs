using System.Collections.Generic;
using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Xunit;

namespace Wingnal.Tests.ZkGroup;

/// <summary>GV2 Phase C gate (part 2): the Schnorr proof engine must reproduce poksho's own
/// <c>test_complex_statement</c> proof byte-for-byte, prove↔verify, and reject tampered proofs/messages.</summary>
public class SchnorrTests
{
    [Fact]
    public void StatementEncoding_MatchesPokshoVectors()
    {
        var s1 = new Statement(); s1.Add("A", ("a", "G"));
        Assert.Equal(new byte[] { 1, 1, 1, 0, 0 }, s1.ToBytes());

        var s2 = new Statement(); s2.Add("A", ("a", "G")); s2.Add("B", ("a", "H"));
        Assert.Equal(new byte[] { 2, 1, 1, 0, 0, 2, 1, 0, 3 }, s2.ToBytes());

        var s3 = new Statement(); s3.Add("A", ("a", "G"), ("b", "H"));
        Assert.Equal(new byte[] { 1, 1, 2, 0, 0, 1, 2 }, s3.ToBytes());
    }

    [Fact]
    public void ComplexStatement_ProveVerify_MatchesPokshoProofVector()
    {
        byte[] block32 = new byte[32];
        for (int i = 0; i < 32; i++) block32[i] = (byte)i;
        byte[] Block64(int start) { var b = new byte[64]; for (int i = 0; i < 64; i++) b[i] = (byte)(start + i); return b; }

        Scalar25519 a = Scalar25519.FromBytesModOrderWide(Block64(10));
        Scalar25519 b = Scalar25519.FromBytesModOrderWide(Block64(20));
        Scalar25519 c = Scalar25519.FromBytesModOrderWide(Block64(30));
        Scalar25519 d = Scalar25519.FromBytesModOrderWide(Block64(40));
        Ristretto255 g = Ristretto255.BasePoint;
        Ristretto255 H = g.Multiply(Scalar25519.FromBytesModOrderWide(Block64(50)));
        Ristretto255 I = g.Multiply(Scalar25519.FromBytesModOrderWide(Block64(60)));

        Ristretto255 A = Ristretto255.Add(Ristretto255.Add(g.Multiply(a), H.Multiply(b)), I.Multiply(c));
        Ristretto255 B = Ristretto255.Add(H.Multiply(c), I.Multiply(d));

        var st = new Statement();
        st.Add("A", ("a", "G"), ("b", "H"), ("c", "I"));
        st.Add("B", ("c", "H"), ("d", "I"));
        Assert.Equal(new byte[] { 2, 1, 3, 0, 0, 1, 2, 2, 3, 4, 2, 2, 2, 3, 3 }, st.ToBytes());

        var scalars = new Dictionary<string, Scalar25519> { ["a"] = a, ["b"] = b, ["c"] = c, ["d"] = d };
        var points = new Dictionary<string, Ristretto255> { ["A"] = A, ["B"] = B, ["H"] = H, ["I"] = I };
        byte[] message = System.Array.Empty<byte>();

        byte[] proof = st.Prove(scalars, points, message, block32);

        const string expected =
            "8efc676c33e6b2d0670ed5461a507f6a4bc9153e261db80fa438f3cd80a5c909" +
            "b113cc0d7990ad616d0a2fc4b831d06357a5ee5d36d44b3427c7901061180c0f" +
            "b1798c51680fe21b9f98e97955b1597c49314725c1546a369328cf54daae710b" +
            "fc4a9911422aa77ed6d7231de3003ba5ae9d9fd0c53ced7ad782e29b04684a07" +
            "221a6ef47ce61d817f01117cf59df69ac35b5bb590f1f7b6d029717bc1a62501";
        Assert.Equal(expected, Convert.ToHexString(proof).ToLowerInvariant());

        Assert.True(st.VerifyProof(proof, points, message));

        // Tampered message → fail.
        Assert.False(st.VerifyProof(proof, points, block32));

        // Tampered proof (last byte) → fail.
        byte[] bad = (byte[])proof.Clone(); bad[^1] ^= 1;
        Assert.False(st.VerifyProof(bad, points, message));

        // Extra trailing byte → fail (not a multiple of 32).
        Assert.False(st.VerifyProof(proof.Append((byte)0).ToArray(), points, message));
    }
}
