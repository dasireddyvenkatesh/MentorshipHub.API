using FluentValidation;
using MentorshipHub.API.Constants.Messages;
using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.DTO.Profile;

namespace MentorshipHub.API.Application.Validators;

public sealed class UpdateMyProfileRequestValidator : AbstractValidator<UpdateMyProfileRequest>
{
    public UpdateMyProfileRequestValidator()
    {
        RuleFor(x => x.FirstName)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage(ValidationMessages.FirstNameRequired)
            .MaximumLength(80)
            .Matches(NameValidationRules.Pattern)
            .WithMessage(ValidationMessages.FirstNameCharacters);

        RuleFor(x => x.LastName)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage(ValidationMessages.LastNameRequired)
            .MaximumLength(80)
            .Matches(NameValidationRules.Pattern)
            .WithMessage(ValidationMessages.LastNameCharacters);

        RuleFor(x => x.PhoneNumber)
            .Must(value => string.IsNullOrWhiteSpace(value) ||
                           System.Text.RegularExpressions.Regex.IsMatch(
                               value.Trim(), NameValidationRules.IndianMobilePattern))
            .WithMessage(ValidationMessages.IndianMobileInvalid);
        RuleFor(x => x.Bio).MaximumLength(600);
    }
}

public sealed class ContactUsRequestValidator : AbstractValidator<ContactUsRequest>
{
    public ContactUsRequestValidator()
    {
        RuleFor(x => x.FullName)
            .Cascade(CascadeMode.Stop)
            .NotEmpty().WithMessage(ValidationMessages.FullNameRequired)
            .MaximumLength(100)
            .Matches(NameValidationRules.Pattern)
            .WithMessage(ValidationMessages.FullNameCharacters);

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(ValidationMessages.EmailRequired)
            .EmailAddress().WithMessage(ValidationMessages.InvalidEmail)
            .MaximumLength(256);

        RuleFor(x => x.Subject)
            .NotEmpty().WithMessage(ValidationMessages.SubjectRequired)
            .MinimumLength(5).WithMessage(ValidationMessages.SubjectMinLength)
            .MaximumLength(100);

        RuleFor(x => x.Message)
            .NotEmpty().WithMessage(ValidationMessages.MessageRequired)
            .MinimumLength(20).WithMessage(ValidationMessages.MessageMinLength)
            .MaximumLength(500);
    }
}
