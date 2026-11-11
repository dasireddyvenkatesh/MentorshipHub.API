using Xqare.Api.Application.DTO.Auth;
namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface ITotpService
    {
        Task<TotpEnrollmentStartResponse> StartEnrollmentAsync(Guid userId, string email, bool allowReplace = false);
        Task<TotpEnrollmentConfirmResponse> ConfirmEnrollmentAsync(Guid userId, string code);
        Task<TotpStatusResponse> GetStatusAsync(Guid userId);
        Task<TotpEnrollmentConfirmResponse> RegenerateRecoveryCodesAsync(Guid userId, string code);
        Task<TotpVerificationResult> VerifyCodeAndConsumeAsync(Guid userId, string code);
        Task<bool> ConsumeRecoveryCodeAsync(Guid userId, string code);
        Task<bool> IsEnabledAsync(Guid userId);
        Task DisableAsync(Guid userId);
    }
    public sealed record TotpVerificationResult(bool IsValid, string Message, int? RetryAfterSeconds = null);
}
