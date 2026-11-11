using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Rbac
{
    public class Role : BaseEntity
    {
        public string Name { get; set; }
        public string Code { get; set; }
        public bool IsSystem { get; set; }

        public ICollection<UserRole> UserRoles { get; set; }

        public ICollection<RolePermission> RolePermissions { get; set; }
    }
}
