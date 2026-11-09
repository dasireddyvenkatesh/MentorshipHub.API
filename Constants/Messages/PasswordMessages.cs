namespace MentorshipHub.API.Constants.Messages;

public static class PasswordMessages
{
    public const string ResetRequestGeneric = "If an account with that email exists, we'll send a password reset link shortly.";
    public const string CurrentPasswordRequired = "Enter your current password.";
    public const string PasswordSignInNotEnabled = "Password sign-in is not enabled for this account. Use the password recovery process to establish a password.";
    public const string CurrentPasswordIncorrect = "Your current password is incorrect.";
    public const string NewPasswordMustDiffer = "Choose a new password that is different from your current password.";
    public const string ChangedOtherSessionsSignedOut = "Your password has been changed. Other active sessions have been signed out.";
    public const string ResetLinkInvalidOrExpired = "This password reset link is invalid or has expired. Request a new one.";
    public const string ResetSuccessful = "Your password has been reset successfully. Please sign in again.";

    public const string PasswordRequired = "Password is required.";
    public const string PasswordTooLong = "Password cannot exceed 128 characters.";
    public const string PasswordPolicy = "Password must be at least 8 characters and include uppercase, lowercase, a number, and a symbol.";
    public const string PasswordsDoNotMatch = "Passwords do not match.";
}
