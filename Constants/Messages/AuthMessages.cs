namespace MentorshipHub.API.Constants.Messages;

public static class AuthMessages
{
    public const string CredentialsRequired = "Enter your email address and password to sign in.";
    public const string AccountLocked = "This account is temporarily locked after multiple unsuccessful sign-in attempts. Try again in {0} minute(s).";
    public const string InvalidCredentials = "The email address or password is incorrect. Check your details and try again.";
    public const string AccountInactive = "This account is currently inactive. Contact support if you think this is a mistake.";
    public const string EmailVerificationRequired = "Your registration is not complete. Choose Create one free to verify your email and set your password.";
    public const string SignInExchangeExpired = "The sign-in exchange has expired. Please sign in again.";
    public const string MfaVerificationExpired = "The verification request has expired. Please sign in again.";
    public const string SignInSessionInvalid = "The sign-in session is no longer valid. Please sign in again.";
    public const string LoginSuccessful = "Login successful";
    public const string RecoveryRequestGeneric = "If the account is eligible, a recovery verification code will be sent to its registered email address.";
    public const string RecoveryVerificationGenericFailure = "The recovery verification could not be completed. Request a new code and try again.";
    public const string RecoveryEmailVerifiedPasswordless = "Email verified. Continue by signing in with an external account already connected to this XQARE account.";
    public const string RecoveryVerificationSucceeded = "Recovery verification succeeded. Continue with authenticator replacement.";
    public const string RecoveryCouldNotComplete = "The recovery verification could not be completed. Start account recovery again.";
    public const string RecoveryExternalIdentityVerified = "External identity verified. Continue with authenticator replacement.";
    public const string RecoverySessionInvalidOrExpired = "The recovery session is invalid or has expired. Request account recovery again.";
    public const string RecoverySessionCodeRequired = "Enter a valid recovery session and six-digit authenticator code.";
    public const string AuthenticatorRecoveryCompleted = "Authenticator recovery completed. All existing sessions were signed out. Save your new recovery codes now; they are shown only once.";
    public const string AccountNotEligibleForAuthenticator = "The account is not eligible for authenticator setup.";
    public const string ConfirmCurrentAccountPassword = "Confirm your current account password before setting up an authenticator.";
    public const string CurrentAuthenticatorCodeRequired = "Enter a valid current authenticator code before replacing it.";
    public const string CurrentPasswordIncorrectForDisable = "Current password is incorrect.";
    public const string AuthenticatorDisabledSuccessfully = "Authenticator disabled successfully.";
}

public static class MfaMessages
{
    public const string RecoveryRequestGeneric = "If the account is eligible, a recovery verification code will be sent to its registered email address.";
    public const string SetupRequired = "Authenticator setup is required for this account. Use the account recovery process before signing in.";
    public const string EnterSixDigitCode = "Enter the six-digit code from your authenticator app.";
    public const string InvalidVerificationRequest = "The MFA verification request is invalid.";
    public const string UnsupportedVerificationMethod = "Unsupported MFA verification method.";
    public const string ChallengeExpired = "The MFA challenge has expired or is no longer valid. Please sign in again.";
    public const string ChallengeUnsupported = "This authenticator challenge is no longer supported. Sign in again.";
    public const string ChallengeInvalid = "The MFA challenge is no longer valid.";
    public const string TooManyChallengeAttempts = "Too many incorrect verification attempts. Sign in again to restart.";

    public const string EnrollmentUnavailable = "Authenticator enrollment is unavailable until a valid AES-256 TOTP encryption key is configured in the API application settings.";
    public const string AlreadyEnabled = "An authenticator is already enabled.";
    public const string ScanQrToFinishSetup = "Scan the QR code with your authenticator app, then enter the current six-digit code to finish setup.";
    public const string SetupExpired = "Your authenticator setup has expired. Start enrollment again.";
    public const string SetupLocked = "Authenticator setup is temporarily locked. Try again later.";
    public const string TooManySetupCodes = "Too many incorrect codes. Authenticator setup is temporarily locked.";
    public const string IncorrectSetupCode = "The authenticator code is incorrect. Check your device time and try again.";
    public const string EnabledSuccessfully = "Authenticator enabled successfully. Save these recovery codes now; they will only be displayed once.";
    public const string StatusRetrieved = "Authenticator status retrieved.";
    public const string EnterCurrentSixDigitCode = "Enter the current six-digit authenticator code.";
    public const string RecoveryCodesRegenerated = "New recovery codes generated. Previous unused codes are no longer valid.";
    public const string EnterValidSixDigitCode = "Enter a valid six-digit authenticator code.";
    public const string NotEnabled = "Authenticator is not enabled for this account.";
    public const string NotEnabledForDisable = "Authenticator is not enabled.";
    public const string VerificationLocked = "Authenticator verification is temporarily locked. Try again later.";
    public const string TooManyVerificationCodes = "Too many incorrect codes. Authenticator verification is temporarily locked.";
    public const string InvalidOrReusedCode = "The authenticator code is invalid or has already been used.";
    public const string CodeVerified = "Authenticator code verified.";
}
