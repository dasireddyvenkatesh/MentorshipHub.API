using System.Security.Claims;
using MentorshipHub.API.Application.Interfaces.Rbac;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;

namespace MentorshipHub.API.Application.Services.Rbac
{
    public sealed class RbacAuditService : IRbacAuditService
    {
        private readonly AppDbContext _db;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public RbacAuditService(AppDbContext db, IHttpContextAccessor httpContextAccessor)
        {
            _db = db;
            _httpContextAccessor = httpContextAccessor;
        }

        // Adds the audit row to the current DbContext without saving it.
        // The calling RBAC operation saves it in the same transaction as its data change.
        public void Add(
            Guid? actorUserId,
            string actionCode,
            string targetType,
            Guid? targetId = null,
            Guid? targetUserId = null,
            Guid? targetRoleId = null,
            string? beforeData = null,
            string? afterData = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;

            _db.RbacAuditLogs.Add(new RbacAuditLog
            {
                ActorUserId = actorUserId,
                ActionCode = actionCode,
                TargetType = targetType,
                TargetId = targetId,
                TargetUserId = targetUserId,
                TargetRoleId = targetRoleId,
                BeforeData = beforeData,
                AfterData = afterData,
                IpAddress = httpContext?.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Limit(httpContext?.Request.Headers.UserAgent.ToString(), 1024),
                CorrelationId = Limit(
                    httpContext?.TraceIdentifier ??
                    httpContext?.Request.Headers["X-Correlation-ID"].FirstOrDefault(), 128),
                CreatedAt = DateTime.UtcNow
            });
        }

        private static string? Limit(string? value, int maxLength)
            => string.IsNullOrWhiteSpace(value)
                ? null
                : value.Length <= maxLength ? value : value[..maxLength];
    }
}