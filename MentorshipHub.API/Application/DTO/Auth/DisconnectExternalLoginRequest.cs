namespace MentorshipHub.API.Application.DTO.Auth
{
    public class DisconnectExternalLoginRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
    }
}