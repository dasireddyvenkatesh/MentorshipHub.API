using MentorshipHub.API.Infrastructure.EntityModels.Common;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class MfaLoginChallenge : BaseEntity
    {
        public Guid UserId { get; set; }
        public string TokenHash { get; set; } = string.Empty;
        public string Purpose { get; set; } = string.Empty;

        public string? DeviceId { get; set; }
        public string? DeviceName { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }

        public DateTime ExpiresAt { get; set; }
        public int AttemptCount { get; set; }
        public DateTime? ConsumedAt { get; set; }

        public User User { get; set; } = default!;
    }
}
