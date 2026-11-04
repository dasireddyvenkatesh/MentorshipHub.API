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

            var emailVerified = bool.TryParse(user.FindFirst("email_verified")?.Value, out var isVerified) && isVerified;

            // The Microsoft Twitter OAuth 1.0a handler retrieves user details using
            // account/verify_credentials.json?include_email=true. X returns a null email
            // when the account email is absent or unverified, so a non-empty email from
            // this specific handler is the verification signal for Twitter.
            if (string.Equals(provider, "Twitter", StringComparison.OrdinalIgnoreCase))
                emailVerified = !string.IsNullOrWhiteSpace(email);

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
                EmailVerified = emailVerified,
                Name = name,
                Avatar = avatar,
                DeviceId = properties.Items["deviceId"] ?? default!,
                DeviceName = properties.Items["deviceName"] ?? default!
            };
        }
    }
}
