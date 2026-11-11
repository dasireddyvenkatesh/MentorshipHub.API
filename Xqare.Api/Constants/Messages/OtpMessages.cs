namespace MentorshipHub.API.Constants.Messages;

public static class OtpMessages
{
    public const string PendingRegistrationGeneric = "If this address has a pending registration, a verification code can be sent.";
    public const string RegistrationDetailsRequired = "Registration verification details are required.";
    public const string EmailAndCodeRequired = "Email and verification code are required.";
    public const string NotFound = "OTP not found. Request a new verification code.";
    public const string AlreadyUsed = "This OTP has already been used. Request a new verification code.";
    public const string LockedForMinutes = "Too many incorrect attempts. Try again in {0} minutes.";
    public const string Expired = "OTP expired. Request a new verification code.";
    public const string LockedFor24Hours = "Too many incorrect attempts. Try again in 24 hours.";
    public const string InvalidAttemptsRemaining = "Invalid OTP. {0} attempt(s) remaining.";
    public const string UserNotFound = "User not found.";
    public const string AccountInactive = "Account is inactive.";
    public const string EmailAlreadyVerified = "Email is already verified. Please sign in.";
    public const string EmailVerifiedPrefix = "Email verified successfully. ";

    public const string TooManyFailedAttempts = "Too many failed attempts. Try again in {0} minutes.";
    public const string ResendWaitSeconds = "Please wait {0} seconds before requesting another code.";
    public const string HourlyLimitReached = "Hourly OTP limit reached. Please try again in {0} minutes.";
    public const string DailyLimitReached = "Daily OTP limit reached. Please try again in {0} hours.";
    public const string EmailSendFailed = "We couldn't send the verification email. Please try again in 60 seconds.";
    public const string CodeSent = "Verification code sent to your email.";
}
