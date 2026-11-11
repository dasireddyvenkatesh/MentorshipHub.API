namespace Xqare.Api.Application.DTO.Admin
{
    public sealed class AdminUserListItemResponse
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? ProfileImageUrl { get; set; }
        public bool IsActive { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTime? LockoutEndUtc { get; set; }
        public int FailedLoginCount { get; set; }
        public int LockoutLevel { get; set; }
        public List<string> Roles { get; set; } = new();
    }
}