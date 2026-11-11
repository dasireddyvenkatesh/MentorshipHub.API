using Xqare.Api.Application.DTO.Common;
namespace Xqare.Api.Application.DTO.Auth
{
    public class TotpEnrollmentConfirmResponse : ResponseDTO
    {
        public IReadOnlyList<string> RecoveryCodes { get; set; } = Array.Empty<string>();
        public int? RetryAfterSeconds { get; set; }
    }
}
