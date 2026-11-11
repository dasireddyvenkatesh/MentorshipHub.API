using MentorshipHub.API.Infrastructure.EntityModels.Common;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class TotpCredential : BaseEntity
    {
        public Guid UserId { get; set; }

        // The active secret remains valid while a replacement is pending.
        public string? EncryptedSecret { get; set; }
        public string? PendingEncryptedSecret { get; set; }
        public DateTime? PendingEnrollmentExpiresAt { get; set; }

        public bool IsEnabled { get; set; }
        public DateTime? EnabledAt { get; set; }
        public DateTime? DisabledAt { get; set; }
        public long? LastAcceptedTimeStep { get; set; }

        public int FailedAttemptCount { get; set; }
        public DateTime? FailedAttemptWindowStartedAt { get; set; }
        public DateTime? LockoutEnd { get; set; }

        public User User { get; set; } = default!;
    }
}
