namespace MentorshipHub.API.Application.DTO.Auth
{
    public class ExternalLoginRequest
    {
        public string Provider { get; set; }
        public string ProviderId { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
        public string Avatar { get; set; }
        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
    }
}
