using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;

namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IUserSessionService
    {
        Task<UserSession?> GetByTokenAsync(string refreshToken);
        Task CreateAsync(UserSession session);
        Task RotateAsync(UserSession session, string newRefreshToken);
        Task RevokeAsync(string refreshToken);
        Task HandleLoginSessionAsync(Guid userId, LoginRequest request, string refreshToken);

    }
}
