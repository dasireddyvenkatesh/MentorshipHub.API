using MentorshipHub.API.Application.DTO.Common;
namespace MentorshipHub.API.Application.DTO.Auth
{
    public class TotpEnrollmentStartResponse : ResponseDTO
    {
        public string? Secret { get; set; }
        public string? ProvisioningUri { get; set; }
        public string? QrCodeDataUri { get; set; }
    }
}
