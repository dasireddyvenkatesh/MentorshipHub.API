using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class SessionActionResponse : ResponseDTO
    {
        public int AffectedSessions { get; set; }
        public bool IsCurrentSession { get; set; }
    }
}
