namespace MentorshipHub.API.Application.DTO.Auth
{
    public class RegisterRequest
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string DeviceId { get; set; }
        public string? DeviceName { get; set; }
    }
}
