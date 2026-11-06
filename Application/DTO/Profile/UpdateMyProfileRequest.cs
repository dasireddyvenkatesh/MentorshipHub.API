using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Application.DTO.Profile
{
    public sealed class UpdateMyProfileRequest
    {
        [Required]
        [StringLength(80, MinimumLength = 1)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(80, MinimumLength = 1)]
        public string LastName { get; set; } = string.Empty;

        [StringLength(32)]
        public string? PhoneNumber { get; set; }

        [StringLength(600)]
        public string? Bio { get; set; }
    }
}
