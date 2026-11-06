using MentorshipHub.API.Infrastructure.EntityModels.Rbac;

namespace MentorshipHub.API.Application.Interfaces.Rbac
{
    public interface IRbacAuditService
    {
        void Add(
            Guid? actorUserId,
            string actionCode,
            string targetType,
            Guid? targetId = null,
            Guid? targetUserId = null,
            Guid? targetRoleId = null,
            string? beforeData = null,
            string? afterData = null);
    }
}