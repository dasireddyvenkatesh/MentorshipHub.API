using MentorshipHub.API.Infrastructure.EntityModels.Common;

namespace MentorshipHub.API.Infrastructure.EntityModels.Rbac
{
    public class RbacAuditLog : BaseEntity
    {
        public Guid? ActorUserId { get; set; }
        public string ActionCode { get; set; } = string.Empty;
        public string TargetType { get; set; } = string.Empty;
        public Guid? TargetId { get; set; }
        public Guid? TargetUserId { get; set; }
        public Guid? TargetRoleId { get; set; }
        public string? BeforeData { get; set; }
        public string? AfterData { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public string? CorrelationId { get; set; }
    }
}