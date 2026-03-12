using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Identity
{
    public class ExternalLogin : BaseEntity
    {
        public Guid UserId { get; set; }

        public string Provider { get; set; }
        public string ProviderUserId { get; set; }

        public User User { get; set; }
    }
}
