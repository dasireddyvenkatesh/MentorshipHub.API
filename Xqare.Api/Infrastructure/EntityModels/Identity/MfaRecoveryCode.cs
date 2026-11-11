using Xqare.Api.Infrastructure.EntityModels.Common;
using Xqare.Api.Infrastructure.EntityModels.Identity;

namespace Xqare.Api.Infrastructure.EntityModels.Identity
{
    public class MfaRecoveryCode : BaseEntity
    {
        public Guid UserId { get; set; }
        public Guid BatchId { get; set; }
        public string CodeHash { get; set; } = string.Empty;
        public DateTime? UsedAt { get; set; }
        public DateTime? InvalidatedAt { get; set; }

        public User User { get; set; } = default!;
    }
}
