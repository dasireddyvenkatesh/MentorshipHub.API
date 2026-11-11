using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class UserSession : BaseEntity
    {
        public Guid UserId { get; set; }

        public string RefreshTokenHash { get; set; }

        public string DeviceId { get; set; }
        public string DeviceName { get; set; }

        public string IpAddress { get; set; } = default!;
        public string UserAgent { get; set; }

        public DateTime ExpiresAt { get; set; }

        public DateTime? LastActivityAt { get; set; }

        public bool IsRevoked { get; set; }
        public DateTime? RevokedAt { get; set; }

        public User User { get; set; }
    }
}
