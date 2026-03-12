namespace MentorshipHub.API.Application.DTO.Auth
{
    public class VerifyEmailOtpRequest
    {
        public string Email { get; set; }
        public string Code { get; set; }

        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
    }
}
