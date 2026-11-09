using System.Text.Json;
using System.Text.RegularExpressions;
using MentorshipHub.API.Application.DTO.Rbac;
using MentorshipHub.API.Constants.Messages;
using MentorshipHub.API.Application.Interfaces.Rbac;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Services.Rbac
{
    public sealed class RbacService : IRbacService
    {
        private const string SuperAdminCode = "SUPERADMIN";
        private static readonly string[] SuperAdminDelegatedPermissionCodes =
        [
            "RBAC_PERMISSIONS_MANAGE",
            "RBAC_ASSIGNMENTS_MANAGE"
        ];
        private readonly AppDbContext _db;
        private readonly IRbacAuditService _audit;

        public RbacService(AppDbContext db, IRbacAuditService audit)
        {
            _db = db;
            _audit = audit;
        }

        public async Task<IReadOnlyList<RoleResponse>> GetRolesAsync()
        {
            return await ProjectRoleList(_db.Roles.AsNoTracking()).ToListAsync();
        }

        public async Task<IReadOnlyList<RoleResponse>> GetAssignableRolesAsync(Guid actorUserId)
        {
            var isSuperAdmin = await IsActiveSuperAdminAsync(actorUserId);
            var query = _db.Roles.AsNoTracking()
                .Where(role => role.Code != SuperAdminCode);

            if (!isSuperAdmin)
            {
                query = query.Where(role => !role.RolePermissions.Any(rolePermission =>
                    SuperAdminDelegatedPermissionCodes.Contains(rolePermission.Permission.Code)));
            }

            return await ProjectRoleList(query).ToListAsync();
        }

        private static IQueryable<RoleResponse> ProjectRoleList(IQueryable<Role> roles)
            => roles
                .OrderBy(role => role.IsSystem ? 0 : 1)
                .ThenBy(role => role.Name)
                .Select(role => new RoleResponse
                {
                    Id = role.Id,
                    Name = role.Name,
                    Code = role.Code,
                    IsSystem = role.IsSystem,
                    AssignedUsers = role.UserRoles.Count,
                    PermissionCount = role.RolePermissions.Count
                });

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
                    Module = x.Module,
                    Description = x.Description
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
                    Module = x.Permission.Module,
                    Description = x.Permission.Description
                })
                .ToListAsync();

            return role;
        }

        public async Task<RbacOperationResponse> CreateRoleAsync(
            Guid actorUserId, string name, string code, IReadOnlyCollection<string> permissionCodes)
        {
            name = name.Trim();
            code = code.Trim().ToUpperInvariant();

            if (name.Length is < 2 or > 80 ||
                !Regex.IsMatch(code, @"^[A-Z][A-Z0-9_]{1,49}$"))
                return Fail("INVALID_ROLE", RbacMessages.InvalidRole);

            if (code == SuperAdminCode)
                return Fail("RESERVED_ROLE", RbacMessages.ReservedRole);

            if (await _db.Roles.AnyAsync(x => x.Code == code))
                return Fail("ROLE_EXISTS", RbacMessages.RoleExists);

            var requestedCodes = (permissionCodes ?? Array.Empty<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim().ToUpperInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (requestedCodes.Length > 200)
                return Fail("TOO_MANY_PERMISSIONS", RbacMessages.TooManyPermissions);

            var permissions = await _db.Permissions
                .Where(x => requestedCodes.Contains(x.Code))
                .ToListAsync();

            if (permissions.Count != requestedCodes.Length)
                return Fail("UNKNOWN_PERMISSION", RbacMessages.UnknownPermission);

            if (requestedCodes.Any(IsSuperAdminDelegatedPermission) &&
                !await IsActiveSuperAdminAsync(actorUserId))
                return Fail("SUPERADMIN_REQUIRED",
                    RbacMessages.CreateDelegationRequiresSuperAdmin);

            var role = new Role { Name = name, Code = code, IsSystem = false };

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.Roles.Add(role);
            foreach (var permission in permissions)
                _db.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = permission.Id });

            _audit.Add(actorUserId, "ROLE_CREATED", "ROLE", role.Id, targetRoleId: role.Id,
                afterData: JsonSerializer.Serialize(new
                {
                    role.Name,
                    role.Code,
                    role.IsSystem,
                    PermissionCodes = requestedCodes
                }));

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok(RbacMessages.RoleCreated);
        }

        public async Task<RbacOperationResponse> UpdateRoleAsync(Guid actorUserId, Guid roleId, string name)
        {
            name = name.Trim();
            if (name.Length is < 2 or > 80)
                return Fail("INVALID_ROLE", RbacMessages.RoleNameLength);

            var role = await _db.Roles.FirstOrDefaultAsync(x => x.Id == roleId);
            if (role == null)
                return Fail("NOT_FOUND", RbacMessages.RoleNotFound);
            if (role.IsSystem || role.Code == SuperAdminCode)
                return Fail("SYSTEM_ROLE_PROTECTED", RbacMessages.SystemRoleRenameProtected);

            var before = JsonSerializer.Serialize(new { role.Name, role.Code });
            if (role.Name == name)
                return Ok(RbacMessages.NoChangesRequired);

            await using var transaction = await _db.Database.BeginTransactionAsync();
            role.Name = name;
            _audit.Add(actorUserId, "ROLE_UPDATED", "ROLE", role.Id, targetRoleId: role.Id,
                beforeData: before,
                afterData: JsonSerializer.Serialize(new { role.Name, role.Code }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok(RbacMessages.RoleUpdated);
        }

        public async Task<RbacOperationResponse> DeleteRoleAsync(Guid actorUserId, Guid roleId)
        {
            var role = await _db.Roles
                .Include(x => x.UserRoles)
                .Include(x => x.RolePermissions)
                    .ThenInclude(x => x.Permission)
                .FirstOrDefaultAsync(x => x.Id == roleId);

            if (role == null)
                return Fail("NOT_FOUND", RbacMessages.RoleNotFound);
            if (role.IsSystem || role.Code == SuperAdminCode)
                return Fail("SYSTEM_ROLE_PROTECTED", RbacMessages.SystemRoleDeleteProtected);
            if (role.UserRoles.Count != 0)
                return Fail("ROLE_IN_USE", RbacMessages.RoleInUse);

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

            return Ok(RbacMessages.RoleDeleted);
        }

        public async Task<RbacOperationResponse> AssignRoleAsync(Guid actorUserId, Guid userId, Guid roleId)
        {
            var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == userId);
            var role = await _db.Roles.AsNoTracking().FirstOrDefaultAsync(x => x.Id == roleId);

            if (user == null || role == null)
                return Fail("NOT_FOUND", RbacMessages.UserOrRoleNotFound);
            if (!user.IsActive)
                return Fail("USER_DISABLED", RbacMessages.DisabledUserAssignment);
            if (role.Code == SuperAdminCode)
                return Fail("SUPERADMIN_PROTECTED", RbacMessages.SuperAdminAssignmentProtected);

            var containsDelegatedPermissions = await _db.RolePermissions
                .AsNoTracking()
                .AnyAsync(x => x.RoleId == roleId &&
                    SuperAdminDelegatedPermissionCodes.Contains(x.Permission.Code));

            if (containsDelegatedPermissions && !await IsActiveSuperAdminAsync(actorUserId))
                return Fail("SUPERADMIN_REQUIRED",
                    RbacMessages.AssignDelegatedRoleRequiresSuperAdmin);

            if (await _db.UserRoles.AnyAsync(x => x.UserId == userId && x.RoleId == roleId))
                return Fail("ALREADY_ASSIGNED", RbacMessages.AlreadyAssigned);

            await using var transaction = await _db.Database.BeginTransactionAsync();
            _db.UserRoles.Add(new UserRole { UserId = userId, RoleId = roleId });
            _audit.Add(actorUserId, "USER_ROLE_ASSIGNED", "USER_ROLE", targetId: roleId,
                targetUserId: userId, targetRoleId: roleId,
                afterData: JsonSerializer.Serialize(new { UserId = userId, RoleId = roleId, RoleCode = role.Code }));
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return Ok(RbacMessages.RoleAssigned);
        }

        public async Task<RbacOperationResponse> RemoveRoleAsync(Guid actorUserId, Guid userId, Guid roleId)
        {
            var assignment = await _db.UserRoles
                .Include(x => x.Role)
                .FirstOrDefaultAsync(x => x.UserId == userId && x.RoleId == roleId);

            if (assignment == null)
                return Fail("NOT_FOUND", RbacMessages.AssignmentNotFound);
            if (assignment.Role.Code == SuperAdminCode)
                return Fail("SUPERADMIN_PROTECTED", RbacMessages.SuperAdminRemovalProtected);

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

            return Ok(RbacMessages.RoleRemoved);
        }

        public async Task<RbacOperationResponse> SetRolePermissionsAsync(
            Guid actorUserId, Guid roleId, IReadOnlyCollection<string> permissionCodes)
        {
            var role = await _db.Roles
                .Include(x => x.RolePermissions)
                    .ThenInclude(x => x.Permission)
                .FirstOrDefaultAsync(x => x.Id == roleId);

            if (role == null)
                return Fail("NOT_FOUND", RbacMessages.RoleNotFound);
            if (role.IsSystem || role.Code == SuperAdminCode)
                return Fail("SYSTEM_ROLE_PROTECTED", RbacMessages.SystemRolePermissionsProtected);

            var requestedCodes = permissionCodes
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim().ToUpperInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (requestedCodes.Length > 200)
                return Fail("TOO_MANY_PERMISSIONS", RbacMessages.TooManyPermissions);

            var permissions = await _db.Permissions
                .Where(x => requestedCodes.Contains(x.Code))
                .ToListAsync();

            if (permissions.Count != requestedCodes.Length)
                return Fail("UNKNOWN_PERMISSION", RbacMessages.UnknownPermission);

            var currentCodeSet = role.RolePermissions
                .Select(x => x.Permission.Code)
                .ToHashSet(StringComparer.Ordinal);
            var addsDelegatedPermission = requestedCodes.Any(code =>
                IsSuperAdminDelegatedPermission(code) && !currentCodeSet.Contains(code));

            if (addsDelegatedPermission && !await IsActiveSuperAdminAsync(actorUserId))
                return Fail("SUPERADMIN_REQUIRED",
                    RbacMessages.AddDelegatedPermissionRequiresSuperAdmin);

            var currentCodes = currentCodeSet.OrderBy(x => x).ToArray();
            var newCodes = requestedCodes.OrderBy(x => x).ToArray();

            if (currentCodes.SequenceEqual(newCodes, StringComparer.Ordinal))
                return Ok(RbacMessages.NoPermissionChangesRequired);

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

            return Ok(RbacMessages.PermissionsUpdated);
        }

        private static bool IsSuperAdminDelegatedPermission(string permissionCode)
            => SuperAdminDelegatedPermissionCodes.Contains(permissionCode, StringComparer.Ordinal);

        private async Task<bool> IsActiveSuperAdminAsync(Guid userId)
            => await _db.UserRoles.AsNoTracking().AnyAsync(x =>
                x.UserId == userId &&
                x.User.IsActive &&
                x.Role.Code == SuperAdminCode);

        private static RbacOperationResponse Ok(string message)
            => new() { IsSuccess = true, Message = message };

        private static RbacOperationResponse Fail(string code, string message)
            => new() { IsSuccess = false, ErrorCode = code, Message = message };
    }
}