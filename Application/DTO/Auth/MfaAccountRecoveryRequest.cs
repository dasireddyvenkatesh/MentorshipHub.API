using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryRequest
    {
        [Required, EmailAddress, StringLength(256)]
        public string Email { get; set; } = string.Empty;

        [StringLength(128)]
        public string? Password { get; set; }
    }
}
