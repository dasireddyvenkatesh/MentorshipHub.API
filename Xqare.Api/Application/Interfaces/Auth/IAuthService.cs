using Xqare.Api.Application.DTO.Auth;
using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request);
        Task<ResponseDTO> RequestMfaAccountRecoveryAsync(MfaAccountRecoveryRequest request);
        Task<MfaAccountRecoveryVerifyResponse> VerifyMfaAccountRecoveryOtpAsync(MfaAccountRecoveryVerifyRequest request);
        Task<MfaAccountRecoveryVerifyResponse> CompleteExternalMfaRecoveryAsync(string emailProof, ExternalLoginRequest externalIdentity);
        Task<TotpEnrollmentStartResponse> StartMfaRecoveryEnrollmentAsync(MfaAccountRecoveryEnrollmentStartRequest request);
        Task<TotpEnrollmentConfirmResponse> CompleteMfaAccountRecoveryAsync(MfaAccountRecoveryCompleteRequest request);
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
        Task<Xqare.Api.Application.DTO.Common.ResponseDTO> LinkExternalLoginAsync(Guid userId, Guid sessionId, ExternalLoginRequest request);
        Task<ResponseDTO> DisconnectExternalLoginAsync(Guid userId, Guid sessionId, string provider, string currentPassword);
        Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request);
        Task<string?> CreateExternalLoginExchangeChallengeAsync(string refreshToken);
        Task<string?> CreateExternalMfaLoginExchangeChallengeAsync(string mfaChallengeToken);
        Task<LoginResponse> ExchangeExternalLoginChallengeAsync(string code);
    }
}
