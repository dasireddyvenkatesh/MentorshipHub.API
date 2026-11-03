namespace MentorshipHub.API.Application.Validators;

public static class NameValidationRules
{
    // Unicode letters (including combining marks), spaces, apostrophes and hyphens.
    public const string Pattern = @"^[\p{L}\p{M}]+(?:[ '\u2019-][\p{L}\p{M}]+)*$";
    public const string IndianMobilePattern = @"^(?:\+?91[\s-]?)?[6-9][0-9]{9}$";

    public static string? NormalizeIndianMobile(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var digits = new string(value.Where(c => c is >= '0' and <= '9').ToArray());
        if (digits.Length == 12 && digits.StartsWith("91", StringComparison.Ordinal))
            digits = digits[2..];

        return digits.Length == 10 ? $"+91{digits}" : value.Trim();
    }
}
