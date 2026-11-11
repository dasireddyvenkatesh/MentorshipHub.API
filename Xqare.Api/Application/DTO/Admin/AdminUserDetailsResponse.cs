namespace Xqare.Api.Application.DTO.Admin
{
    public sealed class AdminUserRoleAssignmentResponse
    {
        public Guid RoleId { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public string RoleCode { get; set; } = string.Empty;
    }

    public sealed class AdminUserDetailsResponse
    {
        public bool IsSuccess { get; set; } = true;
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public string? Bio { get; set; }
        public string? ProfileImageUrl { get; set; }
        public bool IsActive { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public int ActiveSessionCount { get; set; }
        public int TotalSessionCount { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTime? LockoutEndUtc { get; set; }
        public int FailedLoginCount { get; set; }
        public int LockoutLevel { get; set; }
        public List<string> Roles { get; set; } = new();
        public List<AdminUserRoleAssignmentResponse> RoleAssignments { get; set; } = new();
    }
}