namespace MentorshipHub.API.Application.DTO.Auth
{
    public class VerifyEmailOtpRequest
    {
        public string Email { get; set; }
        public string OtpCode { get; set; }

        public string DeviceId { get; set; }
        public string DeviceName { get; set; }
        // Required only by the registration verification endpoint.
        public string? Password { get; set; }
        public string? ConfirmPassword { get; set; }
    }
    /// <summary>
    /// Registration-only email verification request. Password and confirmation
    /// are mandatory for this flow; login email verification uses VerifyEmailOtpRequest.
    /// </summary>
    public sealed class VerifyRegisterEmailOtpRequest : VerifyEmailOtpRequest
    {
    }
}
