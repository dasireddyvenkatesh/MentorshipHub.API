using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public class EmailOtpResponse : ResponseDTO
    {
        public bool CanVerifyExistingOtp { get; set; }
        public int? RetryAfterSeconds { get; set; }
    }
}
