using MentorshipHub.API.Application.DTO.Rbac;

namespace MentorshipHub.API.Application.Interfaces.Rbac
{
    public interface IRbacService
    {
        Task<IReadOnlyList<RoleResponse>> GetRolesAsync();
        Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync();
        Task<RbacOperationResponse> CreateRoleAsync(Guid actorUserId, string name, string code);
        Task<RbacOperationResponse> UpdateRoleAsync(Guid actorUserId, Guid roleId, string name);
        Task<RbacOperationResponse> DeleteRoleAsync(Guid actorUserId, Guid roleId);
        Task<RbacOperationResponse> AssignRoleAsync(Guid actorUserId, Guid userId, Guid roleId);
        Task<RbacOperationResponse> RemoveRoleAsync(Guid actorUserId, Guid userId, Guid roleId);
        Task<RbacOperationResponse> SetRolePermissionsAsync(Guid actorUserId, Guid roleId, IReadOnlyCollection<string> permissionCodes);
    }
}