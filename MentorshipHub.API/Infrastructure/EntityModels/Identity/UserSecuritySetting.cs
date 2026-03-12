using System.ComponentModel.DataAnnotations;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class UserSecuritySetting
    {
        [Key]
        public Guid UserId { get; set; }

        public bool MfaEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LockoutEnd { get; set; }

        public User User { get; set; }
    }
}
