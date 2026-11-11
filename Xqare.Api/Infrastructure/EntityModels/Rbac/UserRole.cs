using Xqare.Api.Infrastructure.EntityModels.Identity;

namespace Xqare.Api.Infrastructure.EntityModels.Rbac
{
    public class UserRole
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }

        public User User { get; set; }
        public Role Role { get; set; }
    }
}
