using MentorshipHub.API.Enities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Presentation.Authorization
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

            // Check the current database assignments on every authorization decision.
            // This makes permission removals effective immediately instead of waiting
            // for an access token containing older permission claims to expire.
            var hasPermission = await _db.UserRoles
                .AsNoTracking()
                .AnyAsync(userRole =>
                    userRole.UserId == userId &&
                    userRole.User.IsActive &&
                    userRole.Role.RolePermissions.Any(rolePermission =>
                        rolePermission.Permission.Code == requirement.PermissionCode));

            if (hasPermission)
                context.Succeed(requirement);
        }
    }
}
