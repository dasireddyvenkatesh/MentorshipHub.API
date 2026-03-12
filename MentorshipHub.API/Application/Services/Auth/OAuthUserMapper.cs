using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace MentorshipHub.API.Application.Services.Auth
{
    public class OAuthUserMapper : IOAuthUserMapper
    {
        public ExternalLoginRequest Map(string provider, ClaimsPrincipal user, AuthenticationProperties properties)
        {
            var email = user.FindFirst(ClaimTypes.Email)?.Value;
            var name = user.FindFirst(ClaimTypes.Name)?.Value;

            var avatar =
                user.FindFirst("picture")?.Value ??
                user.FindFirst("avatar_url")?.Value ??
                user.FindFirst("urn:twitter:profile_image")?.Value ??
                user.FindFirst("profile_image_url")?.Value;

            var providerId =
                user.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
                user.FindFirst("sub")?.Value ??
                user.FindFirst("id")?.Value;

            if (avatar != null && avatar.Contains("_normal"))
            {
                avatar = avatar.Replace("_normal", "_400x400");
            }

            return new ExternalLoginRequest
            {
                Provider = provider,
                ProviderId = providerId,
                Email = email,
                Name = name,
                Avatar = avatar,
                DeviceId = properties.Items["deviceId"] ?? default!,
                DeviceName = properties.Items["deviceName"] ?? default!
            };
        }
    }
}
