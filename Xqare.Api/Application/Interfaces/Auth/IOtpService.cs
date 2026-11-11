using Xqare.Api.Application.DTO.Auth;

namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface IOtpService
    {
        Task<EmailOtpResponse> GenerateEmailVerificationOtp(string name, string email, bool isResend = false);

    }
}
