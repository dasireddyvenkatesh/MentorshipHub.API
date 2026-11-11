using Xqare.Api.Infrastructure.EntityModels.Common;
using Xqare.Api.Infrastructure.EntityModels.Identity;

namespace Xqare.Api.Infrastructure.EntityModels.Identity
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
