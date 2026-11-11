using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class PasswordResetToken : BaseEntity
    {
        public Guid UserId { get; set; }

        public string TokenHash { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool Used { get; set; }

        public User User { get; set; }
    }
}
