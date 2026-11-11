using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public class RegisterResponse : ResponseDTO
    {
        public string? UserPublicId { get; set; }
        public string Email { get; set; }
        public bool RequiresEmailVerification { get; set; }
        public bool CanVerifyExistingOtp { get; set; }
        public int? RetryAfterSeconds { get; set; }
    }
}
