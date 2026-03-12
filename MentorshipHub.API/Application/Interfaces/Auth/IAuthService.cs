using MentorshipHub.API.Application.DTO.Auth;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request);
        Task<EmailOtpResponse> ResendEmailOtp(EmailOtpRequest request);
        Task<LoginResponse> VerifyMfaOtpAsync(VerifyMfaOtpRequest request);
        Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken);
        Task<LoginResponse> VerifyEmailOtp(VerifyEmailOtpRequest request);
        Task<MfaOtpResponse> MfaOtpAsync(MfaOtpRequest request);
        Task<RegisterResponse> RegisterAsync(RegisterRequest request);
        Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request);
    }
}
