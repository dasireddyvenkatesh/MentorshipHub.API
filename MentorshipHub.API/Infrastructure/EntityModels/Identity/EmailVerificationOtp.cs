using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class EmailVerificationOtp : BaseEntity
    {
        public string Email { get; set; }
        public string CodeHash { get; set; }

        public int AttemptCount { get; set; }
        public int MaxAttempts { get; set; } = 3;

        public DateTime ExpiresAt { get; set; }
        public DateTime? LockedUntil { get; set; }

        public bool IsUsed { get; set; }
    }
}
