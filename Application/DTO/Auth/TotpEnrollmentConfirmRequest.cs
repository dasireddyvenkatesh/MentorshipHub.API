using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class TotpEnrollmentConfirmRequest
    {
        [Required]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "The authenticator code must contain exactly six digits.")]
        public string Code { get; set; } = string.Empty;
    }
}
