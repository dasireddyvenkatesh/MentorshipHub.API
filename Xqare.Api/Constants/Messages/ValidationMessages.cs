namespace Xqare.Api.Constants.Messages;

public static class ValidationMessages
{
    public const string FullNameRequired = "Full name is required.";
    public const string FullNameMaxLength = "Full name must be 100 characters or fewer.";
    public const string FullNameCharacters = "Full name can contain letters, spaces, apostrophes and hyphens only.";
    public const string EmailRequired = "Email is required.";
    public const string InvalidEmail = "Enter a valid email address.";
    public const string PasswordRequired = "Password is required.";
    public const string PasswordInputTooLong = "Password input is too long.";
    public const string CurrentPasswordRequired = "Current password is required.";
    public const string NewPasswordRequired = "New password is required.";
    public const string PasswordMinLength = "Password must be at least 8 characters.";
    public const string PasswordMaxLength = "Password cannot exceed 128 characters.";
    public const string UppercaseRequired = "Include at least one uppercase letter.";
    public const string LowercaseRequired = "Include at least one lowercase letter.";
    public const string NumberRequired = "Include at least one number.";
    public const string SymbolRequired = "Include at least one symbol.";
    public const string ConfirmPasswordRequired = "Confirm your new password.";
    public const string PasswordsDoNotMatch = "Passwords do not match.";
    public const string ResetTokenRequired = "The password reset token is required.";
    public const string VerificationCodeRequired = "Verification code is required.";
    public const string OtpSixDigits = "OTP must contain exactly six digits.";
    public const string ChooseVerificationMethod = "Choose a verification method.";
    public const string SupportedVerificationMethod = "Choose a supported verification method.";
    public const string VerificationCodeTooLong = "The verification code is too long.";
    public const string ValidAuthenticatorOrRecoveryCode = "Enter a valid six-digit authenticator code or recovery code.";
    public const string FirstNameRequired = "First name is required.";
    public const string FirstNameCharacters = "First name can contain letters, spaces, apostrophes and hyphens only.";
    public const string LastNameRequired = "Last name is required.";
    public const string LastNameCharacters = "Last name can contain letters, spaces, apostrophes and hyphens only.";
    public const string IndianMobileInvalid = "Enter a valid Indian mobile number (10 digits, optionally with +91 or 0 prefix).";
    public const string SubjectRequired = "Subject is required.";
    public const string SubjectMinLength = "Subject must contain at least 5 characters.";
    public const string MessageRequired = "Message is required.";
    public const string MessageMinLength = "Message must contain at least 20 characters.";
    public const string AuthenticatorCodeSixDigits = "Authenticator code must contain exactly six digits.";
    public const string AuthenticatorCodeRequired = "Authenticator code is required.";
    public const string EnterSixDigitAuthenticatorCode = "Enter the six-digit authenticator code.";
}
