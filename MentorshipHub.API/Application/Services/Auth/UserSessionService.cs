using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class UserSessionService : IUserSessionService
    {
        private static readonly TimeSpan RefreshWindow = TimeSpan.FromDays(7);
        private static readonly TimeSpan MaximumSessionAge = TimeSpan.FromDays(30);
        private readonly AppDbContext _db;
        private readonly IJwtTokenService _jwt;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserSessionService(AppDbContext db, IJwtTokenService jwt, IHttpContextAccessor httpContextAccessor)
        {
            _db = db;
            _jwt = jwt;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<UserSession?> GetByTokenAsync(string refreshToken)
        {
            var hash = _jwt.Hash(refreshToken);

            return await _db.UserSessions
                .Include(x => x.User)
                .FirstOrDefaultAsync(x => x.RefreshTokenHash == hash);
        }

        public async Task CreateAsync(UserSession session)
        {
            _db.UserSessions.Add(session);
            await _db.SaveChangesAsync();
        }

        public async Task RotateAsync(UserSession session, string newRefreshToken)
        {
            var now = DateTime.UtcNow;
            var absoluteExpiry = session.CreatedAt.Add(MaximumSessionAge);

            session.RefreshTokenHash = _jwt.Hash(newRefreshToken);
            session.ExpiresAt = now.Add(RefreshWindow) < absoluteExpiry
                ? now.Add(RefreshWindow)
                : absoluteExpiry;
            session.LastActivityAt = now;

            await _db.SaveChangesAsync();
        }

        public async Task RevokeAsync(string refreshToken)
        {
            var hash = _jwt.Hash(refreshToken);

            var session = await _db.UserSessions
                .FirstOrDefaultAsync(x => x.RefreshTokenHash == hash);

            if (session == null) return;

            session.IsRevoked = true;
            session.RevokedAt = DateTime.UtcNow;
            session.LastActivityAt = DateTime.UtcNow;

            await _db.SaveChangesAsync();
        }

        public async Task HandleLoginSessionAsync(Guid userId, LoginRequest request, string refreshToken)
        {
            var existingSession = await _db.UserSessions
                .Where(x => x.UserId == userId &&
                            x.RevokedAt == null &&
                            x.ExpiresAt > DateTime.UtcNow &&
                            x.IsRevoked == false)
                .FirstOrDefaultAsync();

            var context = _httpContextAccessor.HttpContext;

            string ipAddress = context?.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim() ?? string.Empty;
            string userAgent = context?.Request.Headers["User-Agent"].FirstOrDefault() ?? string.Empty;

            if (existingSession != null)
            {

                if (existingSession.DeviceId == request.DeviceId)
                {

                    // SAME DEVICE → UPDATE
                    var now = DateTime.UtcNow;
                    // A fresh credential login starts a new maximum-age window.
                    existingSession.CreatedAt = now;
                    existingSession.RefreshTokenHash = _jwt.Hash(refreshToken);
                    existingSession.ExpiresAt = now.Add(RefreshWindow);
                    existingSession.IpAddress = ipAddress;
                    existingSession.UserAgent = userAgent;
                    existingSession.LastActivityAt = DateTime.UtcNow;
                }
                else
                {
                    // DIFFERENT DEVICE → REVOKE OLD + CREATE NEW
                    existingSession.RevokedAt = DateTime.UtcNow;
                    existingSession.IsRevoked = true;

                    await _db.UserSessions.AddAsync(new UserSession
                    {
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow,
                        DeviceId = request.DeviceId,
                        DeviceName = request.DeviceName ?? string.Empty,
                        IpAddress = ipAddress,
                        UserAgent = userAgent,
                        RefreshTokenHash = _jwt.Hash(refreshToken),
                        ExpiresAt = DateTime.UtcNow.Add(RefreshWindow)
                    });
                }
            }
            else
            {
                await _db.UserSessions.AddAsync(new UserSession
                {
                    UserId = userId,
                    CreatedAt = DateTime.UtcNow,
                    DeviceId = request.DeviceId,
                    DeviceName = request.DeviceName ?? string.Empty,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    RefreshTokenHash = _jwt.Hash(refreshToken),
                    ExpiresAt = DateTime.UtcNow.Add(RefreshWindow)
                });
            }

            var user = await _db.Users.FindAsync(userId);
            if (user != null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                _db.Users.Update(user);

            }

            await _db.SaveChangesAsync();
        }
    }
}
