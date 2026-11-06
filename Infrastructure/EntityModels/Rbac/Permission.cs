using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Rbac
{
    public class Permission : BaseEntity
    {
        public string Name { get; set; }
        public string Code { get; set; }
        public string Module { get; set; }

        public ICollection<RolePermission> RolePermissions { get; set; }
    }
}
