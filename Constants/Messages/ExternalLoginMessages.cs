namespace MentorshipHub.API.Constants.Messages;

public static class ExternalLoginMessages
{
    public const string ProviderInvalidBare = "Invalid authentication provider";
    public const string ProviderInvalid = "Invalid authentication provider.";
    public const string SessionInactiveConnect = "Your XQARE session is no longer active. Sign in again before connecting an account.";
    public const string ContinueConnect = "Continue to your provider to connect this account.";
    public const string LinkExpired = "The account-link request has expired. Try again from Settings.";
    public const string LinkInvalidOrExpired = "The account-link request is invalid or has expired. Try again from Settings.";
    public const string SignInFailed = "External sign-in failed. Please try again.";
    public const string LinkCouldNotValidate = "The account-link request could not be validated. Start again from Settings.";
    public const string LinkAlreadyUsed = "The account-link request has already been used or has expired. Start again from Settings.";
    public const string RecoveryCouldNotComplete = "The recovery verification could not be completed. Start account recovery again.";
    public const string ProviderCouldNotBeVerified = "The linked provider could not be verified.";
    public const string ProviderIdentifierMissing = "The provider did not return a usable account identifier.";
    public const string SignInCouldNotComplete = "Sign-in could not be completed. Please try again.";
    public const string VerificationCouldNotComplete = "The verification request could not be completed. Please sign in again.";
    public const string RecoveryInvalidOrExpired = "The recovery verification is invalid or expired.";
    public const string ContinueLinkedProvider = "Continue to your linked provider to verify account ownership.";
    public const string RecoveryExpired = "The recovery verification has expired. Start account recovery again.";
    public const string TrustedOriginRequired = "A trusted request origin is required.";
    public const string TrustedCookieMfaOriginRequired = "A trusted request origin is required for cookie-based MFA verification.";
    public const string UntrustedOrigin = "Untrusted request origin.";
    public const string LogoutSuccess = "Logged out successfully";
}
