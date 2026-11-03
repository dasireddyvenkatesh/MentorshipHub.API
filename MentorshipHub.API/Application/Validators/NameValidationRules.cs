namespace MentorshipHub.API.Application.Validators;

public static class NameValidationRules
{
    // Unicode letters (including combining marks), spaces, apostrophes and hyphens.
    public const string Pattern = @"^[\\p{L}\\p{M}]+(?:[ '\\u2019-][\\p{L}\\p{M}]+)*$";
    public const string IndianMobilePattern = @"^(?:\\+?91[\\s-]?)?[6-9][0-9]{9}$";
}
