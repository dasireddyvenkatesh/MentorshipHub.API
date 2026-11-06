using System.Text.Json;
using System.Text.RegularExpressions;
using MentorshipHub.API.Application.DTO.Rbac;
using MentorshipHub.API.Application.Interfaces.Rbac;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Services.Rbac
{
    public sealed class RbacService : IRbacService
    {
        private const string SuperAdminCode = "SUPERADMIN";
        private readonly AppDbContext _db;
        private readonly IRbacAuditService _audit;

        public RbacService(AppDbContext db, IRbacAuditService audit)
        {
            _db = db;
            _audit = audit;
        }

        public async Task<IReadOnlyList<RoleResponse>> GetRolesAsync()
        {
            return await _db.Roles.AsNoTracking()
                .OrderBy(x => x.IsSystem ? 0 : 1)
                .ThenBy(x => x.Name)
                .Select(x => new RoleResponse
                {
                    Id = x.Id,
                    Name = x.Name,
                    Code = x.Code,
                    IsSystem = x.IsSystem,
                    AssignedUsers = x.UserRoles.Count,
                    PermissionCount = x.RolePermissions.Count
                })
                .ToListAsync();
        }

        public async Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync()
        {
            return await _db.Permissions.AsNoTracking()
                .OrderBy(x => x.Module)
                .ThenBy(x => x.Name)
                .Select(x => new PermissionResponse
                {
                    Id = x.Id,
                    Name = x.Name,
                    Code = x.Code,
                    Module = x.Module
                })
                .ToListAsync();
        }

        public async Task<RolePermissionsResponse?> GetRolePermissionsAsync(Guid roleId)
        {
            var role = await _db.Roles.AsNoTracking()
                .Where(x => x.Id == roleId)
                .Select(x => new RolePermissionsResponse
                {
                    RoleId = x.Id,
                    RoleName = x.Name,
                    RoleCode = x.Code
                })
                .FirstOrDefaultAsync();

            if (role == null)
                return null;

            role.Permissions = await _db.RolePermissions.AsNoTracking()
                .Where(x => x.RoleId == roleId)
                .OrderBy(x => x.Permission.Module)
                .ThenBy(x => x.Permission.Name)
                .Select(x => new PermissionResponse
                {
                    Id = x.Permission.Id,
                    Name = x.Permission.Name,
                    Code = x.Permission.Code,
                    Module = x.Permission.Module
                })
                .ToListAsync();

            return role;
        }

        public async Task<RbacOperationResponse> CreateRoleAsync(Guid actorUserId, string name, string code)
        {
            name = name.Trim();
            code = code.Trim().ToUpperInvariant();

            if (name.Length is < 2 or > 80 ||
                !Regex.IsMatch(code, @"^[A-Z][A-Z0-9_]{1,49}$"))
                return Fail("INVALID_ROLE", "Provide a valid role name and code.");

            if (code == SuperAdminCode)
                return Fail("RESERVED_ROLE", "The SUPERADMIN role code is reserved.");

            if (await _db.Roles.AnyAsync(x => x.Code == code))
                return Fail("ROLE_EXISTS", "A role with this code already exists.");

            var role = new Role { Name = name, Code = code, IsSystem = false };

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.Roles.Add(role);
            _audit.Add(actorUserId, "ROLE_CREATED", "ROLE", role.Id, targetRoleId: role.Id,
                afterData: JsonSerializer.Serialize(new { role.Name, role.Code, role.IsSystem }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("The role was created.");
        }

        public async Task<RbacOperationResponse> UpdateRoleAsync(Guid actorUserId, Guid roleId, string name)
        {
            name = name.Trim();
            if (name.Length is < 2 or > 80)
                return Fail("INVALID_ROLE", "Role name must contain between 2 and 80 characters.");

            var role = await _db.Roles.FirstOrDefaultAsync(x => x.Id == roleId);
            if (role == null)
                return Fail("NOT_FOUND", "The role could not be found.");
            if (role.IsSystem || role.Code == SuperAdminCode)
                return Fail("SYSTEM_ROLE_PROTECTED", "System roles cannot be renamed.");

            var before = JsonSerializer.Serialize(new { role.Name, role.Code });
            if (role.Name == name)
                return Ok("No changes were required.");

            await using var transaction = await _db.Database.BeginTransactionAsync();
            role.Name = name;
            _audit.Add(actorUserId, "ROLE_UPDATED", "ROLE", role.Id, targetRoleId: role.Id,
                beforeData: before,
                afterData: JsonSerializer.Serialize(new { role.Name, role.Code }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("The role was updated.");
        }

        public async Task<RbacOperationResponse> DeleteRoleAsync(Guid actorUserId, Guid roleId)
        {
            var role = await _db.Roles
                .Include(x => x.UserRoles)
                .Include(x => x.RolePermissions)
                    .ThenInclude(x => x.Permission)
                .FirstOrDefaultAsync(x => x.Id == roleId);

            if (role == null)
                return Fail("NOT_FOUND", "The role could not be found.");
            if (role.IsSystem || role.Code == SuperAdminCode)
                return Fail("SYSTEM_ROLE_PROTECTED", "System roles cannot be deleted.");
            if (role.UserRoles.Count != 0)
                return Fail("ROLE_IN_USE", "Remove all users from this role before deleting it.");

            var before = JsonSerializer.Serialize(new
            {
                role.Name,
                role.Code,
                PermissionCodes = role.RolePermissions.Select(x => x.Permission.Code).ToArray()
            });

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.RolePermissions.RemoveRange(role.RolePermissions);
            _db.Roles.Remove(role);
            _audit.Add(actorUserId, "ROLE_DELETED", "ROLE", role.Id, targetRoleId: role.Id,
                beforeData: before);
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("The role was deleted.");
        }

        public async Task<RbacOperationResponse> AssignRoleAsync(Guid actorUserId, Guid userId, Guid roleId)
        {
            var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == userId);
            var role = await _db.Roles.AsNoTracking().FirstOrDefaultAsync(x => x.Id == roleId);

            if (user == null || role == null)
                return Fail("NOT_FOUND", "The user or role could not be found.");
            if (!user.IsActive)
                return Fail("USER_DISABLED", "A role cannot be assigned to a disabled account.");
            if (role.Code == SuperAdminCode)
                return Fail("SUPERADMIN_PROTECTED", "SUPERADMIN assignments must be managed through the protected recovery process.");
            if (await _db.UserRoles.AnyAsync(x => x.UserId == userId && x.RoleId == roleId))
                return Fail("ALREADY_ASSIGNED", "The user already has this role.");

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.UserRoles.Add(new UserRole { UserId = userId, RoleId = roleId });
            _audit.Add(actorUserId, "USER_ROLE_ASSIGNED", "USER_ROLE", targetId: roleId,
                targetUserId: userId, targetRoleId: roleId,
                afterData: JsonSerializer.Serialize(new { UserId = userId, RoleId = roleId, RoleCode = role.Code }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("The role was assigned to the user.");
        }

        public async Task<RbacOperationResponse> RemoveRoleAsync(Guid actorUserId, Guid userId, Guid roleId)
        {
            var assignment = await _db.UserRoles
                .Include(x => x.Role)
                .FirstOrDefaultAsync(x => x.UserId == userId && x.RoleId == roleId);

            if (assignment == null)
                return Fail("NOT_FOUND", "The user-role assignment could not be found.");
            if (assignment.Role.Code == SuperAdminCode)
                return Fail("SUPERADMIN_PROTECTED", "SUPERADMIN assignments cannot be removed through this endpoint.");

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.UserRoles.Remove(assignment);
            _audit.Add(actorUserId, "USER_ROLE_REMOVED", "USER_ROLE", targetId: roleId,
                targetUserId: userId, targetRoleId: roleId,
                beforeData: JsonSerializer.Serialize(new
                {
                    UserId = userId,
                    RoleId = roleId,
                    RoleCode = assignment.Role.Code
                }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("The role was removed from the user.");
        }

        public async Task<RbacOperationResponse> SetRolePermissionsAsync(
            Guid actorUserId, Guid roleId, IReadOnlyCollection<string> permissionCodes)
        {
            var role = await _db.Roles
                .Include(x => x.RolePermissions)
                    .ThenInclude(x => x.Permission)
                .FirstOrDefaultAsync(x => x.Id == roleId);

            if (role == null)
                return Fail("NOT_FOUND", "The role could not be found.");
            if (role.Code == SuperAdminCode)
                return Fail("SUPERADMIN_PROTECTED", "SUPERADMIN permissions are protected.");

            var requestedCodes = permissionCodes
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim().ToUpperInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (requestedCodes.Length > 200)
                return Fail("TOO_MANY_PERMISSIONS", "A role cannot have more than 200 permissions.");

            var permissions = await _db.Permissions
                .Where(x => requestedCodes.Contains(x.Code))
                .ToListAsync();

            if (permissions.Count != requestedCodes.Length)
                return Fail("UNKNOWN_PERMISSION", "One or more permission codes are not in the permission catalogue.");

            var currentCodes = role.RolePermissions
                .Select(x => x.Permission.Code)
                .OrderBy(x => x)
                .ToArray();
            var newCodes = requestedCodes.OrderBy(x => x).ToArray();

            if (currentCodes.SequenceEqual(newCodes, StringComparer.Ordinal))
                return Ok("No permission changes were required.");

            var before = JsonSerializer.Serialize(new { PermissionCodes = currentCodes });
            await using var transaction = await _db.Database.BeginTransactionAsync();

            _db.RolePermissions.RemoveRange(role.RolePermissions);
            foreach (var permission in permissions)
                _db.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = permission.Id });

            _audit.Add(actorUserId, "ROLE_PERMISSIONS_UPDATED", "ROLE", role.Id,
                targetRoleId: role.Id,
                beforeData: before,
                afterData: JsonSerializer.Serialize(new { PermissionCodes = newCodes }));

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok("Role permissions were updated.");
        }

        private static RbacOperationResponse Ok(string message)
            => new() { IsSuccess = true, Message = message };

        private static RbacOperationResponse Fail(string code, string message)
            => new() { IsSuccess = false, ErrorCode = code, Message = message };
    }
}