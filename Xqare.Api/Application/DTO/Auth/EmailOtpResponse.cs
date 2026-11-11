using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public class EmailOtpResponse : ResponseDTO
    {
        public bool CanVerifyExistingOtp { get; set; }
        public int? RetryAfterSeconds { get; set; }
    }
}
