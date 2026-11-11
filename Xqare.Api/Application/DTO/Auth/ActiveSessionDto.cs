namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class ActiveSessionDto
    {
        public Guid SessionId { get; set; }
        public string DeviceName { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastActivityAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsCurrentSession { get; set; }
    }
}
