using FluentValidation;
using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.DTO.Profile;

namespace MentorshipHub.API.Application.Validators;

public sealed class UpdateMyProfileRequestValidator : AbstractValidator<UpdateMyProfileRequest>
{
    public UpdateMyProfileRequestValidator()
    {
        RuleFor(x => x.FirstName)
            .NotEmpty().WithMessage("First name is required.")
            .MaximumLength(80);

        RuleFor(x => x.LastName)
            .NotEmpty().WithMessage("Last name is required.")
            .MaximumLength(80);

        RuleFor(x => x.PhoneNumber).MaximumLength(32);
        RuleFor(x => x.Bio).MaximumLength(600);
    }
}

public sealed class ContactUsRequestValidator : AbstractValidator<ContactUsRequest>
{
    public ContactUsRequestValidator()
    {
        RuleFor(x => x.FullName)
            .NotEmpty().WithMessage("Full name is required.")
            .MaximumLength(100);

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Enter a valid email address.")
            .MaximumLength(256);

        RuleFor(x => x.Subject)
            .NotEmpty().WithMessage("Subject is required.")
            .MinimumLength(5).WithMessage("Subject must contain at least 5 characters.")
            .MaximumLength(100);

        RuleFor(x => x.Message)
            .NotEmpty().WithMessage("Message is required.")
            .MinimumLength(20).WithMessage("Message must contain at least 20 characters.")
            .MaximumLength(500);
    }
}
