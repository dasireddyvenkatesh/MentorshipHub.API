using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Infrastructure.EntityModels.Profile
{
    public class UserProfile
    {
        [Key]
        public Guid UserId { get; set; }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string? PhoneNumber { get; set; }
        public string? ProfileImageUrl { get; set; }
        public string? Bio { get; set; }

        public User User { get; set; }
    }
}
