using MentorshipHub.API.Application.DTO.Auth;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IOtpService
    {
        Task<EmailOtpResponse> GenerateEmailVerificationOtp(string name, string email, bool isResend = false);
        Task<MfaOtpResponse> GenerateMfaOtp(Guid id);

    }
}
