using Xqare.Api.Infrastructure.EntityModels.Common;

namespace Xqare.Api.Infrastructure.EntityModels.Identity
{
    public class ExternalLogin : BaseEntity
    {
        public Guid UserId { get; set; }

        public string Provider { get; set; }
        public string ProviderUserId { get; set; }

        public User User { get; set; }
    }
}
