using Xqare.Api.Application.DTO.Common;
namespace Xqare.Api.Application.DTO.Auth
{
    public class TotpEnrollmentStartResponse : ResponseDTO
    {
        public string? Secret { get; set; }
        public string? ProvisioningUri { get; set; }
        public string? QrCodeDataUri { get; set; }
    }
}
