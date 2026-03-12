namespace MentorshipHub.API.Application.DTO.Auth
{
    public class VerifyMfaOtpRequest
    {
        public Guid UserId { get; set; }
        public string Code { get; set; }

        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
    }
}
