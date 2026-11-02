using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request);
        Task<ResponseDTO> RequestPasswordResetAsync(ForgotPasswordRequest request);
        Task<ResponseDTO> ResetPasswordAsync(ResetPasswordRequest request);
        Task<EmailOtpResponse> ResendEmailOtp(EmailOtpRequest request);
        Task<LoginResponse> VerifyMfaOtpAsync(VerifyMfaOtpRequest request);
        Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken);
        Task<LoginResponse> VerifyEmailOtp(VerifyEmailOtpRequest request);
        Task<LoginResponse> VerifyRegisterEmailOtp(VerifyEmailOtpRequest request);
        Task<MfaOtpResponse> MfaOtpAsync(MfaOtpRequest request);
        Task<RegisterResponse> RegisterAsync(RegisterRequest request);
        Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request);
    }
}
