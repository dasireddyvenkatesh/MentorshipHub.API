using Xqare.Api.Application.DTO.Auth;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface IOAuthUserMapper
    {
        ExternalLoginRequest Map(string provider, ClaimsPrincipal user, AuthenticationProperties properties);
    }
}
