using MentorshipHub.API.Application.DTO.Common;

namespace MentorshipHub.API.Application.DTO.Auth
{
    public sealed class ActiveSessionsResponse : ResponseDTO
    {
        public List<ActiveSessionDto> Sessions { get; set; } = new();
    }
}
