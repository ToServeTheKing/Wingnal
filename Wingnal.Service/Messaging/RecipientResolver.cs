using System.Text.RegularExpressions;

namespace Wingnal.Service.Messaging;

/// <summary>
/// Resolves user-entered recipient text into a destination service id (ACI UUID). An ACI is accepted
/// directly (normalized to lowercase canonical form). A phone number (e164) currently can't be resolved
/// client-side: Signal removed the unauthenticated number→ACI lookup, so it requires the Contact
/// Discovery Service (CDSI, an SGX-attested enclave) which Wingnal doesn't implement yet — see
/// SHORTCUTS.md. Until then, paste the contact's ACI UUID.
/// </summary>
public static partial class RecipientResolver
{
    public sealed record Result(bool Ok, string? ServiceId, string? Error);

    [GeneratedRegex(@"^\+[1-9]\d{6,14}$")]
    private static partial Regex E164();

    public static Result Resolve(string? input)
    {
        string text = (input ?? string.Empty).Trim();
        if (text.Length == 0)
            return new Result(false, null, "Enter a recipient.");

        if (Guid.TryParse(text, out Guid aci))
            return new Result(true, aci.ToString("D").ToLowerInvariant(), null);

        if (E164().IsMatch(text))
            return new Result(false, null,
                "Phone-number lookup needs Signal's Contact Discovery (CDSI), which Wingnal doesn't " +
                "support yet. Paste the contact's ACI UUID instead.");

        return new Result(false, null, "Not a valid ACI UUID (or +e164 number).");
    }
}
