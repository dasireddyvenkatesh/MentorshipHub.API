namespace MentorshipHub.API.Application.Interfaces.Email
{
    public interface IEmailTemplateService
    {
        (string subject, string body) BuildResendOtp(string name, string code);
        (string subject, string body) BuildRegistrationOtp(string firstName, string otpCode);
        (string subject, string body) BuildMfaOtp(string firstName, string otpCode);
        (string subject, string body) ContactUsCustomerTemplate(string firstName);
        (string subject, string body) ContactUsSupportTemplate(string firstName, string email, string subject, string message);
    }
}
