using System.ComponentModel.DataAnnotations;
using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryVerifyRequest
    {
        [Required, EmailAddress, StringLength(256)]
        public string Email { get; set; } = string.Empty;

        [Required, RegularExpression(@"^\d{6}$")]
        public string OtpCode { get; set; } = string.Empty;
    }

    public sealed class MfaAccountRecoveryVerifyResponse : ResponseDTO
    {
        public string? RecoveryGrant { get; set; }
        public string? EmailProof { get; set; }
        public bool RequiresExternalVerification { get; set; }
    }
}
