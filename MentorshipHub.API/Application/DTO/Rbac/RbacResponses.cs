namespace MentorshipHub.API.Application.DTO.Rbac
{
    public sealed class RbacOperationResponse
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ErrorCode { get; set; }
    }

    public sealed class RoleResponse
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public bool IsSystem { get; set; }
        public int AssignedUsers { get; set; }
        public int PermissionCount { get; set; }
    }

    public sealed class PermissionResponse
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string Module { get; set; } = string.Empty;
    }
}