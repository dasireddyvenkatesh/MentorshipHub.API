namespace MentorshipHub.API.Application.Interfaces.Email
{
    public interface IEmailTemplateService
    {
        (string subject, string body) BuildResendOtp(string name, string code);
        (string subject, string body) BuildRegistrationOtp(string firstName, string otpCode);
    }
}
