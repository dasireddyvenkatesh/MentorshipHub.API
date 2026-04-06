using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public class LoginResponse : ResponseDTO
    {
        public bool RequiresEmailVerification { get; set; }
        public bool RequiresMfa { get; set; }

        public string AccessToken { get; set; } = default!;

        public string RefreshToken { get; set; } = default!;

        public DateTime? AccessTokenExpiry { get; set; }

        public string? UserPublicId { get; set; }

        public string? Email { get; set; }
    }
}
