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
    public const string AccountCouldNotBeVerified = "The account could not be verified.";
    public const string DefaultMemberRoleMissing = "The default Member role is not configured. Please contact support.";
    public const string ConnectedMethodsRetrieved = "Connected sign-in methods retrieved.";
    public const string ProviderIdentifierInvalid = "The external provider did not return a valid account identifier.";
    public const string InvalidProviderService = "This sign-in provider is not supported.";
    public const string SessionInactiveChange = "Your XQARE session is no longer active. Sign in again before changing connected accounts.";
    public const string AccountCouldNotVerify = "The XQARE account could not be verified.";
    public const string ProviderEmailUnverified = "This provider did not supply a verified email address. XQARE can only connect providers that return a verified matching email.";
    public const string ProviderEmailMismatch = "The verified email on this provider account does not match your XQARE account email. Sign in to the XQARE account with that email before connecting this provider.";
    public const string ProviderAlreadyConnected = "This provider account is already connected to another XQARE account.";
    public const string SetPasswordBeforeDisconnect = "Set up email and password sign-in before disconnecting a provider.";
    public const string ProviderIdentityInvalid = "The external identity provider did not return a valid account identifier.";
    public const string ProviderEmailMissingForSignIn = "This provider did not return a verified email address. Sign in using another linked method and review your connected accounts.";
    public const string ProviderEmailNoLongerMatches = "The email returned by this provider no longer matches the email on the linked XQARE account. Sign in using another linked method and review your connected accounts.";
    public const string ProviderEmailMissingForRegistration = "This provider did not supply a verified email address. Use email registration or an already-linked provider.";
    public const string ExistingAccountForEmail = "An account already exists with this email. Sign in using your existing method before linking another provider.";
    public const string EmailNotVerified = "This account's email is not verified. Complete registration from the Register page first.";
}
