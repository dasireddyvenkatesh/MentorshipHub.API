using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public class RefreshTokenResponse : ResponseDTO
    {
        public string AccessToken { get; set; } = default!;
    }
}
