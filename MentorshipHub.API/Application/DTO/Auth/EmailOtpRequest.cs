using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public class EmailOtpRequest
    {
        public string Email { get; set; }
    }
}
