using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class TotpEnrollmentStartRequest
    {
        [Required]
        [StringLength(128)]
        public string CurrentPassword { get; set; } = string.Empty;

        [RegularExpression(@"^\d{6}$", ErrorMessage = "The current authenticator code must contain exactly six digits.")]
        public string? CurrentTotpCode { get; set; }
    }
}
