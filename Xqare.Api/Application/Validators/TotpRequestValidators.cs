using FluentValidation;
using MentorshipHub.API.Constants.Messages;
using MentorshipHub.API.Application.DTO.Auth;

namespace MentorshipHub.API.Application.Validators;

public sealed class TotpEnrollmentStartRequestValidator : AbstractValidator<TotpEnrollmentStartRequest>
{
    public TotpEnrollmentStartRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage(ValidationMessages.CurrentPasswordRequired)
            .MaximumLength(128);

        RuleFor(x => x.CurrentTotpCode)
            .Must(code => string.IsNullOrWhiteSpace(code) || System.Text.RegularExpressions.Regex.IsMatch(code, @"^\d{6}$"))
            .WithMessage(ValidationMessages.AuthenticatorCodeSixDigits);
    }
}

public sealed class TotpEnrollmentConfirmRequestValidator : AbstractValidator<TotpEnrollmentConfirmRequest>
{
    public TotpEnrollmentConfirmRequestValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty().WithMessage(ValidationMessages.AuthenticatorCodeRequired)
            .Matches(@"^\d{6}$").WithMessage(ValidationMessages.EnterSixDigitAuthenticatorCode);
    }
}

public sealed class TotpDisableRequestValidator : AbstractValidator<TotpDisableRequest>
{
    public TotpDisableRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty().WithMessage(ValidationMessages.CurrentPasswordRequired)
            .MaximumLength(128);

        RuleFor(x => x.Code)
            .NotEmpty().WithMessage(ValidationMessages.AuthenticatorCodeRequired)
            .Matches(@"^\d{6}$").WithMessage(ValidationMessages.EnterSixDigitAuthenticatorCode);
    }
}

public sealed class TotpRecoveryCodesRegenerateRequestValidator : AbstractValidator<TotpRecoveryCodesRegenerateRequest>
{
    public TotpRecoveryCodesRegenerateRequestValidator()
    {
        RuleFor(x => x.Code)
            .NotEmpty().WithMessage(ValidationMessages.AuthenticatorCodeRequired)
            .Matches(@"^\d{6}$").WithMessage(ValidationMessages.EnterSixDigitAuthenticatorCode);
    }
}
