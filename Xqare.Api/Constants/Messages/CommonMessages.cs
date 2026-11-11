namespace Xqare.Api.Constants.Messages;

public static class CommonMessages
{
    public const string UnexpectedErrorTitle = "An unexpected error occurred.";
    public const string UnexpectedError = "An unexpected error occurred. Please try again later.";
    public static string RateLimitExceededFor(int retryAfterSeconds)
        => $"Too many requests. Please try again in {FormatDuration(retryAfterSeconds)}.";

    public static string FormatDuration(int totalSeconds)
    {
        totalSeconds = Math.Max(1, totalSeconds);

        if (totalSeconds < 60)
            return totalSeconds == 1 ? "1 second" : $"{totalSeconds} seconds";

        var totalMinutes = (int)Math.Ceiling(totalSeconds / 60d);
        if (totalMinutes < 60)
            return totalMinutes == 1 ? "1 minute" : $"{totalMinutes} minutes";

        var hours = totalMinutes / 60;
        var minutes = totalMinutes % 60;
        var hourText = hours == 1 ? "1 hour" : $"{hours} hours";
        if (minutes == 0)
            return hourText;

        var minuteText = minutes == 1 ? "1 minute" : $"{minutes} minutes";
        return $"{hourText} {minuteText}";
    }
}
