namespace MentorshipHub.API.Application.DTO.Rbac
{
    public sealed class CreateRoleRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public List<string> PermissionCodes { get; set; } = [];
    }

    public sealed class UpdateRoleRequest
    {
        public string Name { get; set; } = string.Empty;
    }

    public sealed class RoleAssignmentRequest
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
    }

    public sealed class SetRolePermissionsRequest
    {
        public List<string> PermissionCodes { get; set; } = [];
    }
}