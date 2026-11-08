namespace MentorshipHub.API.Application.Interfaces.Email
{
    public interface IEmailTemplateService
    {
        (string subject, string body) BuildResendOtp(string name, string code);
        (string subject, string body) BuildRegistrationOtp(string firstName, string otpCode);
        (string subject, string body) BuildMfaAccountRecoveryOtp(string firstName, string otpCode);
        (string subject, string body) BuildMfaAccountRecoveryCompleted(string firstName);
        (string subject, string body) BuildPasswordReset(string firstName, string resetUrl);
        (string subject, string body) ContactUsCustomerTemplate(string firstName);
        (string subject, string body) ContactUsSupportTemplate(string firstName, string email, string subject, string message);
    }
}
