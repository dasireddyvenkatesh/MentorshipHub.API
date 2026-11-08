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
        Task<LoginResponse> VerifyRegisterEmailOtp(VerifyRegisterEmailOtpRequest request);
        Task<RegisterResponse> RegisterAsync(RegisterRequest request);
        Task<ConnectedAccountsResponse> GetConnectedAccountsAsync(Guid userId);
        Task<string?> CreateExternalLinkChallengeAsync(Guid userId, Guid sessionId);
        Task<bool> ConsumeExternalLinkChallengeAsync(Guid userId, string nonce);
        Task<MentorshipHub.API.Application.DTO.Common.ResponseDTO> LinkExternalLoginAsync(Guid userId, Guid sessionId, ExternalLoginRequest request);
        Task<ResponseDTO> DisconnectExternalLoginAsync(Guid userId, Guid sessionId, string provider, string currentPassword);
        Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request);
        Task<string?> CreateExternalLoginExchangeChallengeAsync(string refreshToken);
        Task<LoginResponse> ExchangeExternalLoginChallengeAsync(string code);
    }
}
