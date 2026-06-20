using Wingnal.Protocol.ZkGroup.Curve;
using Wingnal.Protocol.ZkGroup.Poksho;
using Wingnal.Service.Protos.Groups;

namespace Wingnal.Service.Groups;

/// <summary>
/// Verifies the server's signature on a <c>GroupChange</c> (the storage service signs the serialized
/// <c>actions</c> with its sig key so a client can trust a change it didn't author). Callers must verify
/// BEFORE applying a change (<see cref="GroupChangeApplier"/>).
///
/// The server's sig public key is the <c>sig_public_key</c> field of Signal's published
/// <c>ServerPublicParams</c>; obtaining/parsing that production constant is the remaining live-flow step
/// (see SHORTCUTS.md). This method takes the already-parsed key so the verification logic itself is testable.
/// </summary>
public static class GroupSignatureVerifier
{
    public static bool Verify(Ristretto255 serverSigPublicKey, GroupChange change) =>
        !change.ServerSignature.IsEmpty &&
        PokshoSignature.Verify(change.ServerSignature.ToByteArray(), serverSigPublicKey, change.Actions.ToByteArray());
}
