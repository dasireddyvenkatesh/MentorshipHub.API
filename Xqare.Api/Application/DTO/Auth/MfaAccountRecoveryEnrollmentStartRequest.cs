using System.ComponentModel.DataAnnotations;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryEnrollmentStartRequest
    {
        [Required, StringLength(128, MinimumLength = 32)]
        public string RecoveryGrant { get; set; } = string.Empty;
    }
}
