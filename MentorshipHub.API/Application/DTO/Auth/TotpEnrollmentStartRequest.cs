namespace MentorshipHub.API.Application.DTO.Auth
{
    public class TotpEnrollmentStartRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string? CurrentTotpCode { get; set; }
    }
}
