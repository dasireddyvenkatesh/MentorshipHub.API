namespace MentorshipHub.API.Application.DTO.Auth
{
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string DeviceId { get; set; }
        public string? DeviceName { get; set; }
    }
}
