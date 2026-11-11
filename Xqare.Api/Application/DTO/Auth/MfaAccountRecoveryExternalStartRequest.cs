using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class MfaAccountRecoveryExternalStartRequest
    {
        [Required, StringLength(128, MinimumLength = 32)]
        public string EmailProof { get; set; } = string.Empty;
    }
}