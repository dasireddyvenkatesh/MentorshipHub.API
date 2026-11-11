using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public class LoginResponse : ResponseDTO
    {
        public string? ErrorCode { get; set; }
        public bool RequiresEmailVerification { get; set; }
        public int? RetryAfterSeconds { get; set; }
        public bool RequiresMfa { get; set; }
        public string? MfaChallengeToken { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? AccessTokenExpiry { get; set; }
        public string? UserPublicId { get; set; }
        public Guid? UserId { get; set; }
        public string? Email { get; set; }
    }
}