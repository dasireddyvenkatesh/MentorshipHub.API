using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryEnrollmentStartRequest
    {
        [Required, StringLength(128, MinimumLength = 32)]
        public string RecoveryGrant { get; set; } = string.Empty;
    }
}
