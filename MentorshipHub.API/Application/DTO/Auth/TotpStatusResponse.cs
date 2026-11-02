using MentorshipHub.API.Application.DTO.Common;
namespace MentorshipHub.API.Application.DTO.Auth
{
    public class TotpStatusResponse : ResponseDTO
    {
        public bool IsEnabled { get; set; }
        public DateTime? EnabledAt { get; set; }
        public int RecoveryCodesRemaining { get; set; }
    }
}
