using System.ComponentModel.DataAnnotations;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class TotpDisableRequest
    {
        [Required]
        [StringLength(128)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "The authenticator code must contain exactly six digits.")]
        public string Code { get; set; } = string.Empty;
    }
}
