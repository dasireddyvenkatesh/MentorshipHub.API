using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class SessionActionResponse : ResponseDTO
    {
        public int AffectedSessions { get; set; }
        public bool IsCurrentSession { get; set; }
    }
}
