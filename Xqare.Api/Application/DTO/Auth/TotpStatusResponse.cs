using Xqare.Api.Application.DTO.Common;
namespace Xqare.Api.Application.DTO.Auth
{
    public class TotpStatusResponse : ResponseDTO
    {
        public bool IsEnabled { get; set; }
        public bool CanEnroll { get; set; }
        public DateTime? EnabledAt { get; set; }
        public int RecoveryCodesRemaining { get; set; }
    }
}
