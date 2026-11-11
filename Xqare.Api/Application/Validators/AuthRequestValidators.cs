using FluentValidation;
using Xqare.Api.Constants.Messages;
using Xqare.Api.Application.DTO.Auth;

namespace Xqare.Api.Application.Validators;

public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.FullName)
            .Must(value => !string.IsNullOrWhiteSpace(value))
            .WithMessage(ValidationMessages.FullNameRequired)
            .MaximumLength(100).WithMessage(ValidationMessages.FullNameMaxLength)
            .Matches(NameValidationRules.Pattern)
            .WithMessage(ValidationMessages.FullNameCharacters);

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);
    }
}

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);

        // Sign-in validates presence only. Do not impose new length/complexity
        // restrictions on existing credentials during authentication.
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage(ValidationMessages.PasswordRequired)
            // Bound untrusted request work without imposing registration complexity
            // rules on existing credentials.
            .MaximumLength(1024).WithMessage(ValidationMessages.PasswordInputTooLong);

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);
    }
}

public sealed class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage(ValidationMessages.CurrentPasswordRequired)
            .MaximumLength(128);

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage(ValidationMessages.NewPasswordRequired)
            .MinimumLength(8).WithMessage(ValidationMessages.PasswordMinLength)
            .MaximumLength(128).WithMessage(ValidationMessages.PasswordMaxLength)
            .Matches("[A-Z]").WithMessage(ValidationMessages.UppercaseRequired)
            .Matches("[a-z]").WithMessage(ValidationMessages.LowercaseRequired)
            .Matches("[0-9]").WithMessage(ValidationMessages.NumberRequired)
            .Matches(@"[\W_]").WithMessage(ValidationMessages.SymbolRequired);

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage(ValidationMessages.ConfirmPasswordRequired)
            .Equal(x => x.NewPassword).WithMessage(ValidationMessages.PasswordsDoNotMatch)
            .MaximumLength(128);
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty().WithMessage(ValidationMessages.ResetTokenRequired)
            .MaximumLength(512);

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage(ValidationMessages.PasswordRequired)
            .MinimumLength(8).WithMessage(ValidationMessages.PasswordMinLength)
            .MaximumLength(128).WithMessage(ValidationMessages.PasswordMaxLength)
            .Matches("[A-Z]").WithMessage(ValidationMessages.UppercaseRequired)
            .Matches("[a-z]").WithMessage(ValidationMessages.LowercaseRequired)
            .Matches("[0-9]").WithMessage(ValidationMessages.NumberRequired)
            .Matches(@"[\W_]").WithMessage(ValidationMessages.SymbolRequired);

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage(ValidationMessages.ConfirmPasswordRequired)
            .Equal(x => x.Password).WithMessage(ValidationMessages.PasswordsDoNotMatch)
            .MaximumLength(128);
    }
}


public sealed class ForgotPasswordRequestValidator : AbstractValidator<ForgotPasswordRequest>
{
    public ForgotPasswordRequestValidator()
    {
        // Only validate address syntax. The endpoint still returns the same
        // generic success message for valid addresses whether or not an account exists.
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);
    }
}

public sealed class EmailOtpRequestValidator : AbstractValidator<EmailOtpRequest>
{
    public EmailOtpRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);
    }
}

public sealed class VerifyEmailOtpRequestValidator : AbstractValidator<VerifyEmailOtpRequest>
{
    public VerifyEmailOtpRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);

        RuleFor(x => x.OtpCode)
            .NotEmpty().WithMessage(ValidationMessages.VerificationCodeRequired)
            .Matches(@"^\d{6}$").WithMessage(ValidationMessages.OtpSixDigits);

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);
    }
}

public sealed class VerifyRegisterEmailOtpRequestValidator : AbstractValidator<VerifyRegisterEmailOtpRequest>
{
    public VerifyRegisterEmailOtpRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);

        RuleFor(x => x.OtpCode)
            .NotEmpty().WithMessage(ValidationMessages.VerificationCodeRequired)
            .Matches(@"^\d{6}$").WithMessage(ValidationMessages.OtpSixDigits);

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);

        // Password strength and confirmation are validated in AuthService only
        // after the OTP is correct, so invalid OTP attempts are always counted.

    }
}

public sealed class VerifyMfaChallengeRequestValidator : AbstractValidator<VerifyMfaChallengeRequest>
{
    public VerifyMfaChallengeRequestValidator()
    {
        RuleFor(x => x.Factor)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage(ValidationMessages.ChooseVerificationMethod)
            .Must(value => new[] { "auto", "totp", "recovery" }
                .Contains(value.Trim(), StringComparer.OrdinalIgnoreCase))
            .WithMessage(ValidationMessages.SupportedVerificationMethod);

        RuleFor(x => x.ChallengeToken).MaximumLength(512);

        RuleFor(x => x.Code)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage(ValidationMessages.VerificationCodeRequired)
            .MaximumLength(36).WithMessage(ValidationMessages.VerificationCodeTooLong)
            .Must((request, value) =>
            {
                var code = value?.Trim() ?? string.Empty;
                var factor = (request.Factor ?? string.Empty).Trim().ToLowerInvariant();
                var normalized = new string(code.Where(char.IsLetterOrDigit).ToArray());

                if (factor == "recovery")
                    return normalized.Length >= 20 && normalized.Length <= 36;

                if (factor == "auto")
                    return (code.Length == 6 && code.All(char.IsDigit)) ||
                           (normalized.Length >= 20 && normalized.Length <= 36);

                return code.Length == 6 && code.All(char.IsDigit);
            })
            .WithMessage(ValidationMessages.ValidAuthenticatorOrRecoveryCode);
    }
}
