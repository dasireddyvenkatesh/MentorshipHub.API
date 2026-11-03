using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request);
        Task<ResponseDTO> RequestPasswordResetAsync(ForgotPasswordRequest request);
        Task<ResponseDTO> ResetPasswordAsync(ResetPasswordRequest request);
        Task<ResponseDTO> ChangePasswordAsync(Guid userId, Guid currentSessionId, ChangePasswordRequest request);
        Task<EmailOtpResponse> ResendEmailOtp(EmailOtpRequest request);
        Task<LoginResponse> VerifyMfaChallengeAsync(VerifyMfaChallengeRequest request, string challengeToken);
        Task<TotpEnrollmentStartResponse> StartTotpEnrollmentAsync(Guid userId, TotpEnrollmentStartRequest request);
        Task<TotpEnrollmentConfirmResponse> ConfirmTotpEnrollmentAsync(Guid userId, TotpEnrollmentConfirmRequest request);
        Task<TotpStatusResponse> GetTotpStatusAsync(Guid userId);
        Task<TotpEnrollmentConfirmResponse> RegenerateTotpRecoveryCodesAsync(Guid userId, TotpRecoveryCodesRegenerateRequest request);
        Task<ResponseDTO> DisableTotpAsync(Guid userId, TotpDisableRequest request);
        Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken);
        Task<LoginResponse> VerifyEmailOtp(VerifyEmailOtpRequest request);
        Task<LoginResponse> VerifyRegisterEmailOtp(VerifyRegisterEmailOtpRequest request);
        Task<RegisterResponse> RegisterAsync(RegisterRequest request);
        Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request);
    }
}
