using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Services.Rbac
{
    public sealed record PermissionDefinition(string Code, string Name, string Module);

    /// <summary>
    /// Application-owned permission catalogue. Codes are stable authorization identifiers;
    /// names and modules are display metadata for administration screens.
    /// </summary>
    public static class RbacPermissionCatalog
    {
        public static IReadOnlyList<PermissionDefinition> Definitions { get; } =
        [
            new("ADMIN.OVERVIEW.VIEW", "View administration overview", "Administration"),
            new("ADMIN.USERS.VIEW", "View and search users", "User Management"),
            new("ADMIN.USERS.MANAGE", "Enable or disable user accounts", "User Management"),

            new("RBAC.ROLES.VIEW", "View roles", "Role Management"),
            new("RBAC.ROLES.MANAGE", "Create, rename and delete custom roles", "Role Management"),
            new("RBAC.PERMISSIONS.VIEW", "View the permission catalogue", "Role Management"),
            new("RBAC.PERMISSIONS.MANAGE", "Assign permissions to roles", "Role Management"),
            new("RBAC.ASSIGNMENTS.MANAGE", "Assign or remove roles from users", "Role Management")
        ];

        /// <summary>
        /// Inserts missing catalogue entries only. Existing permission records and
        /// role-permission assignments are deliberately left untouched.
        /// </summary>
        public static async Task SeedAsync(AppDbContext db, CancellationToken cancellationToken = default)
        {
            var existingCodes = await db.Permissions
                .AsNoTracking()
                .Select(permission => permission.Code)
                .ToListAsync(cancellationToken);

            var existing = existingCodes.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var missing = Definitions
                .Where(definition => !existing.Contains(definition.Code))
                .Select(definition => new Permission
                {
                    Code = definition.Code,
                    Name = definition.Name,
                    Module = definition.Module
                })
                .ToList();

            if (missing.Count == 0)
                return;

            await db.Permissions.AddRangeAsync(missing, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
        }
    }
}