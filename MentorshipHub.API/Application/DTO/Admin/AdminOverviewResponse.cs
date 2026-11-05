namespace MentorshipHub.API.Application.DTO.Admin
{
    public sealed class AdminOverviewResponse
    {
        public bool IsSuccess { get; set; } = true;
        public string Message { get; set; } = "Administration overview retrieved.";
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int DisabledUsers { get; set; }
        public int NewRegistrationsLast30Days { get; set; }
        public int ActiveSessions { get; set; }
        public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;
    }
}
