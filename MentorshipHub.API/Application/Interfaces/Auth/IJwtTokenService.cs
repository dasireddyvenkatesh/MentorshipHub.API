using MentorshipHub.API.Infrastructure.EntityModels.Identity;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IJwtTokenService
    {
        string GenerateAccessToken(User user, IList<string> roles, IList<string> permissions, Guid sessionId);
        string GenerateRefreshToken();
        string Hash(string value);
    }
}
