using FluentValidation;
using MentorshipHub.API.Application.DTO.Auth;

namespace MentorshipHub.API.Application.Validators;

public sealed class TotpEnrollmentStartRequestValidator : AbstractValidator<TotpEnrollmentStartRequest>
{
    public TotpEnrollmentStartRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("Current password is required.")
            .MaximumLength(128);

        RuleFor(x => x.CurrentTotpCode)
            .Must(code => string.IsNullOrWhiteSpace(code) || System.Text.RegularExpressions.Regex.IsMatch(code, @"^\d{6}$"))
            .WithMessage("Authenticator code must contain exactly six digits.");
    }
}

public sealed class TotpEnrollmentConfirmRequestValidator : AbstractValidator<TotpEnrollmentConfirmRequest>
{
    public TotpEnrollmentConfirmRequestValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty().WithMessage("Authenticator code is required.")
            .Matches(@"^\d{6}$").WithMessage("Enter the six-digit authenticator code.");
    }
}

public sealed class TotpDisableRequestValidator : AbstractValidator<TotpDisableRequest>
{
    public TotpDisableRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage("Current password is required.")
            .MaximumLength(128);

        RuleFor(x => x.Code)
            .NotEmpty().WithMessage("Authenticator code is required.")
            .Matches(@"^\d{6}$").WithMessage("Enter the six-digit authenticator code.");
    }
}

public sealed class TotpRecoveryCodesRegenerateRequestValidator : AbstractValidator<TotpRecoveryCodesRegenerateRequest>
{
    public TotpRecoveryCodesRegenerateRequestValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty().WithMessage("Authenticator code is required.")
            .Matches(@"^\d{6}$").WithMessage("Enter the six-digit authenticator code.");
    }
}
