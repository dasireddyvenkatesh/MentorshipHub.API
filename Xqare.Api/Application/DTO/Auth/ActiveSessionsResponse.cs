using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public sealed class ActiveSessionsResponse : ResponseDTO
    {
        public List<ActiveSessionDto> Sessions { get; set; } = new();
    }
}
