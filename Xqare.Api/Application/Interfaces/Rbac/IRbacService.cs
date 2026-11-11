using Xqare.Api.Application.DTO.Rbac;

namespace Xqare.Api.Application.Interfaces.Rbac
{
    public interface IRbacService
    {
        Task<IReadOnlyList<RoleResponse>> GetRolesAsync();
        Task<IReadOnlyList<RoleResponse>> GetAssignableRolesAsync(Guid actorUserId);
        Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync();
        Task<RolePermissionsResponse?> GetRolePermissionsAsync(Guid roleId);
        Task<RbacOperationResponse> CreateRoleAsync(Guid actorUserId, string name, string code, IReadOnlyCollection<string> permissionCodes);
        Task<RbacOperationResponse> UpdateRoleAsync(Guid actorUserId, Guid roleId, string name);
        Task<RbacOperationResponse> DeleteRoleAsync(Guid actorUserId, Guid roleId);
        Task<RbacOperationResponse> AssignRoleAsync(Guid actorUserId, Guid userId, Guid roleId);
        Task<RbacOperationResponse> RemoveRoleAsync(Guid actorUserId, Guid userId, Guid roleId);
        Task<RbacOperationResponse> SetRolePermissionsAsync(Guid actorUserId, Guid roleId, IReadOnlyCollection<string> permissionCodes);
    }
}