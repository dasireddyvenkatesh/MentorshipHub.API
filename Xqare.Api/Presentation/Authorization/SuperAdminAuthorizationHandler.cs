using System.Security.Claims;
using MentorshipHub.API.Enities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Presentation.Authorization
{
    public sealed class SuperAdminAuthorizationHandler
        : AuthorizationHandler<SuperAdminRequirement>
    {
        private readonly AppDbContext _db;

        public SuperAdminAuthorizationHandler(AppDbContext db)
        {
            _db = db;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            SuperAdminRequirement requirement)
        {
            if (!Guid.TryParse(context.User.FindFirst("uid")?.Value, out var userId))
                return;

            // Resolve the system role by its immutable code rather than its display
            // name or a potentially stale role claim embedded in the access token.
            var isSuperAdmin = await _db.UserRoles.AsNoTracking().AnyAsync(x =>
                x.UserId == userId &&
                x.User.IsActive &&
                x.Role.Code == "SUPERADMIN");

            if (isSuperAdmin)
                context.Succeed(requirement);
        }
    }
}
