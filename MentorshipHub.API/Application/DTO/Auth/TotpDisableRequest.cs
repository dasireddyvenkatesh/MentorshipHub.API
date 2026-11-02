namespace MentorshipHub.API.Application.DTO.Auth
{
    public class TotpDisableRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
