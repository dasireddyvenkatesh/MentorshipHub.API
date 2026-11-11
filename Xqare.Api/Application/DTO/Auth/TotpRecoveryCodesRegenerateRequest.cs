using System.ComponentModel.DataAnnotations;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class TotpRecoveryCodesRegenerateRequest
    {
        [Required]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "The authenticator code must contain exactly six digits.")]
        public string Code { get; set; } = string.Empty;
    }
}
