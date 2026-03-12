using MentorshipHub.API.Application.DTO.Auth;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IOAuthUserMapper
    {
        ExternalLoginRequest Map(string provider, ClaimsPrincipal user, AuthenticationProperties properties);
    }
}
