using System.ComponentModel.DataAnnotations;

namespace Xqare.Api.Infrastructure.EntityModels.Identity
{
    public class UserSecuritySetting
    {
        [Key]
        public Guid UserId { get; set; }

        public bool MfaEnabled { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LockoutEnd { get; set; }
        public DateTime? FailedLoginWindowStartedAt { get; set; }
        public int LockoutLevel { get; set; }

        public User User { get; set; }
    }
}
