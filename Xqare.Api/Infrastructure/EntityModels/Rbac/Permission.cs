using Xqare.Api.Infrastructure.EntityModels.Common;

namespace Xqare.Api.Infrastructure.EntityModels.Rbac
{
    public class Permission : BaseEntity
    {
        public string Name { get; set; }
        public string Code { get; set; }
        public string Module { get; set; }
        public string Description { get; set; }

        public ICollection<RolePermission> RolePermissions { get; set; }
    }
}
