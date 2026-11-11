using MentorshipHub.API.Infrastructure.EntityModels.Common;
using MentorshipHub.API.Infrastructure.EntityModels.Profile;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class User : BaseEntity
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string? PasswordHash { get; set; }

        public bool IsActive { get; set; } = true;
        public bool IsEmailConfirmed { get; set; }

        public DateTime? LastLoginAt { get; set; }

        public UserSecuritySetting SecuritySetting { get; set; }
        public UserProfile Profile { get; set; }

        public ICollection<UserRole> UserRoles { get; set; }
        public ICollection<UserSession> Sessions { get; set; }
    }
}
