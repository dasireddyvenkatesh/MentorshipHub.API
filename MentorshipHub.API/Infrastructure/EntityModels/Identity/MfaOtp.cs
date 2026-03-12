using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class MfaOtp : BaseEntity
    {
        public Guid UserId { get; set; }

        public string CodeHash { get; set; }

        public int AttemptCount { get; set; }
        public int MaxAttempts { get; set; } = 3;

        public DateTime? LockedUntil { get; set; }

        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; }

        public User User { get; set; }
    }
}
