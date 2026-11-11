using Xqare.Api.Enities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace Xqare.Api.Presentation.Authorization
{
    public sealed class PermissionAuthorizationHandler
        : AuthorizationHandler<PermissionRequirement>
    {
        private readonly AppDbContext _db;

        public PermissionAuthorizationHandler(AppDbContext db)
        {
            _db = db;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            if (!Guid.TryParse(context.User.FindFirst("uid")?.Value, out var userId))
                return;

            var isAuthorized = await _db.UserRoles
                .AsNoTracking()
                .AnyAsync(userRole =>
                    userRole.UserId == userId &&
                    userRole.User.IsActive &&
                    (
                        userRole.Role.Code == "SUPERADMIN" ||
                        userRole.Role.RolePermissions.Any(rolePermission =>
                            rolePermission.Permission.Code == requirement.PermissionCode)
                    ));

            if (isAuthorized)
                context.Succeed(requirement);
        }
    }
}