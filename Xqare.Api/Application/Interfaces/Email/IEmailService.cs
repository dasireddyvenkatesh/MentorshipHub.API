namespace MentorshipHub.API.Application.Interfaces.Email
{
    public interface IEmailService
    {
        Task<bool> SendEmail(string to, string subject, string body);
    }
}
