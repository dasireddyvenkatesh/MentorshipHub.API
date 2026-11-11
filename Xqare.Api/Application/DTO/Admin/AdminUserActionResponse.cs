namespace MentorshipHub.API.Application.DTO.Admin
{
    public sealed class AdminUserActionResponse
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? ErrorCode { get; set; }
        public bool? IsActive { get; set; }
        public int AffectedSessions { get; set; }
    }
}
