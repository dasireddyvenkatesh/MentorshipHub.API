using MentorshipHub.API.Application.DTO.Common;
namespace MentorshipHub.API.Application.DTO.Auth
{
    public class TotpEnrollmentConfirmResponse : ResponseDTO
    {
        public IReadOnlyList<string> RecoveryCodes { get; set; } = Array.Empty<string>();
    }
}
