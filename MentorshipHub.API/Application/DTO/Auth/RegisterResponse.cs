using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public class RegisterResponse : ResponseDTO
    {
        public string? UserPublicId { get; set; }
        public string Email { get; set; }
        public bool RequiresEmailVerification { get; set; }
    }
}
