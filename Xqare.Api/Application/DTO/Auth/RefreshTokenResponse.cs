using Xqare.Api.Application.DTO.Common;

namespace Xqare.Api.Application.DTO.Auth
{
    public class RefreshTokenResponse : ResponseDTO
    {
        public string AccessToken { get; set; } = default!;
    }
}
