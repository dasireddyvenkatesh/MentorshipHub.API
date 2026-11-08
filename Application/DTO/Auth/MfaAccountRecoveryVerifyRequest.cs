using System.ComponentModel.DataAnnotations;
using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryVerifyRequest
    {
        [Required, EmailAddress, StringLength(256)]
        public string Email { get; set; } = string.Empty;

        [Required, RegularExpression(@"^\\d{6}$")]
        public string OtpCode { get; set; } = string.Empty;
    }

    public sealed class MfaAccountRecoveryVerifyResponse : ResponseDTO
    {
        public string? RecoveryGrant { get; set; }
    }
}
