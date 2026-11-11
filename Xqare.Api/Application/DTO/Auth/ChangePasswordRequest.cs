using System.ComponentModel.DataAnnotations;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class ChangePasswordRequest
    {
        [Required]
        [StringLength(128)]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [StringLength(128, MinimumLength = 8)]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [StringLength(128)]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
