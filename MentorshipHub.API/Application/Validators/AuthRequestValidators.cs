using FluentValidation;
using MentorshipHub.API.Application.DTO.Auth;

namespace MentorshipHub.API.Application.Validators;

public sealed class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.FullName)
            .Must(value => !string.IsNullOrWhiteSpace(value))
            .WithMessage("Full name is required.")
            .MaximumLength(25).WithMessage("Full name must be 25 characters or fewer.");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Enter a valid email address.")
            .MaximumLength(256);

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
            .MaximumLength(128).WithMessage("Password cannot exceed 128 characters.")
            .Matches("[A-Z]").WithMessage("Include at least one uppercase letter.")
            .Matches("[a-z]").WithMessage("Include at least one lowercase letter.")
            .Matches("[0-9]").WithMessage("Include at least one number.")
            .Matches(@"[\W_]").WithMessage("Include at least one symbol.");

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);
    }
}

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Enter a valid email address.")
            .MaximumLength(256);

        // Sign-in validates presence only. Do not require registration password complexity here.
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MaximumLength(128);

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);
    }
}

public sealed class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("Current password is required.")
            .MaximumLength(128);

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("New password is required.")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
            .MaximumLength(128).WithMessage("Password cannot exceed 128 characters.")
            .Matches("[A-Z]").WithMessage("Include at least one uppercase letter.")
            .Matches("[a-z]").WithMessage("Include at least one lowercase letter.")
            .Matches("[0-9]").WithMessage("Include at least one number.")
            .Matches(@"[\W_]").WithMessage("Include at least one symbol.");

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage("Confirm your new password.")
            .Equal(x => x.NewPassword).WithMessage("Passwords do not match.")
            .MaximumLength(128);
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty().WithMessage("The password reset token is required.")
            .MaximumLength(512);

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
            .MaximumLength(128).WithMessage("Password cannot exceed 128 characters.")
            .Matches("[A-Z]").WithMessage("Include at least one uppercase letter.")
            .Matches("[a-z]").WithMessage("Include at least one lowercase letter.")
            .Matches("[0-9]").WithMessage("Include at least one number.")
            .Matches(@"[\W_]").WithMessage("Include at least one symbol.");

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty().WithMessage("Confirm your new password.")
            .Equal(x => x.Password).WithMessage("Passwords do not match.")
            .MaximumLength(128);
    }
}

public sealed class EmailOtpRequestValidator : AbstractValidator<EmailOtpRequest>
{
    public EmailOtpRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Enter a valid email address.")
            .MaximumLength(256);
    }
}

public sealed class VerifyEmailOtpRequestValidator : AbstractValidator<VerifyEmailOtpRequest>
{
    public VerifyEmailOtpRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Enter a valid email address.")
            .MaximumLength(256);

        RuleFor(x => x.OtpCode)
            .NotEmpty().WithMessage("Verification code is required.")
            .Matches(@"^\d{6}$").WithMessage("OTP must contain exactly six digits.");

        RuleFor(x => x.DeviceId).MaximumLength(256);
        RuleFor(x => x.DeviceName).MaximumLength(256);

        // Password fields are only sent by the registration-verification endpoint.
        // Login email verification must not require a password here.
        When(x => x.Password is not null || x.ConfirmPassword is not null, () =>
        {
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required.")
                .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
                .MaximumLength(128)
                .Matches("[A-Z]").WithMessage("Include at least one uppercase letter.")
                .Matches("[a-z]").WithMessage("Include at least one lowercase letter.")
                .Matches("[0-9]").WithMessage("Include at least one number.")
                .Matches(@"[\W_]").WithMessage("Include at least one symbol.");

            RuleFor(x => x.ConfirmPassword)
                .NotEmpty().WithMessage("Confirm your password.")
                .Equal(x => x.Password).WithMessage("Passwords do not match.")
                .MaximumLength(128);
        });
    }
}

public sealed class VerifyMfaChallengeRequestValidator : AbstractValidator<VerifyMfaChallengeRequest>
{
    public VerifyMfaChallengeRequestValidator()
    {
        RuleFor(x => x.Factor)
            .Must(value => new[] { "auto", "totp", "recovery" }
                .Contains(value?.Trim(), StringComparer.OrdinalIgnoreCase))
            .WithMessage("Choose a supported verification method.");

        RuleFor(x => x.ChallengeToken).MaximumLength(512);

        RuleFor(x => x.Code)
            .NotEmpty().WithMessage("A verification code is required.")
            .Must((request, value) =>
            {
                var code = value?.Trim() ?? string.Empty;
                var factor = request.Factor?.Trim().ToLowerInvariant();

                if (factor == "recovery")
                {
                    var normalized = new string(code.Where(char.IsLetterOrDigit).ToArray());
                    return normalized.Length >= 20 && normalized.Length <= 36;
                }

                return code.Length == 6 && code.All(char.IsDigit);
            })
            .WithMessage("Enter a valid six-digit authenticator code or recovery code.");
    }
}
