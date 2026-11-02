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
        private const int MaxActiveSessions = 2;
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

        public async Task<Guid> HandleLoginSessionAsync(Guid userId, LoginRequest request, string refreshToken)
        {
            // Serialize logins for one account so concurrent requests cannot exceed the cap.
            // MFA verification already owns a transaction while it locks/consumes the
            // challenge and TOTP credential. Reuse it instead of opening a nested
            // transaction on the same DbContext connection.
            await using var transaction = _db.Database.CurrentTransaction == null
                ? await _db.Database.BeginTransactionAsync()
                : null;

            var lockKey = "session:" + userId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

            var now = DateTime.UtcNow;
            var activeSessions = await _db.UserSessions
                .Where(x => x.UserId == userId &&
                            !x.IsRevoked &&
                            x.RevokedAt == null &&
                            x.ExpiresAt > now)
                .OrderByDescending(x => x.LastActivityAt ?? x.CreatedAt)
                .ThenByDescending(x => x.CreatedAt)
                .ToListAsync();

            var context = _httpContextAccessor.HttpContext;
            var ipAddress = context?.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim() ?? string.Empty;
            var userAgent = context?.Request.Headers["User-Agent"].FirstOrDefault() ?? string.Empty;
            var requestedDeviceId = request.DeviceId ?? string.Empty;
            var currentSession = activeSessions.FirstOrDefault(x => x.DeviceId == requestedDeviceId);

            if (currentSession != null)
            {
                // Re-authentication on an already-active device reuses that session slot.
                currentSession.CreatedAt = now;
                currentSession.RefreshTokenHash = _jwt.Hash(refreshToken);
                currentSession.ExpiresAt = now.Add(RefreshWindow);
                currentSession.DeviceName = request.DeviceName ?? currentSession.DeviceName;
                currentSession.IpAddress = ipAddress;
                currentSession.UserAgent = userAgent;
                currentSession.LastActivityAt = now;
            }
            else
            {
                currentSession = new UserSession
                {
                    UserId = userId,
                    CreatedAt = now,
                    DeviceId = requestedDeviceId,
                    DeviceName = request.DeviceName ?? string.Empty,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    RefreshTokenHash = _jwt.Hash(refreshToken),
                    ExpiresAt = now.Add(RefreshWindow),
                    LastActivityAt = now
                };
                _db.UserSessions.Add(currentSession);
            }

            var user = await _db.Users.FindAsync(userId);
            if (user != null)
                user.LastLoginAt = now;

            await _db.SaveChangesAsync();

            // Keep the two most recently active sessions. Older sessions are revoked
            // atomically so their sid-bound access tokens fail on subsequent API requests.
            var sessionsAfterLogin = await _db.UserSessions
                .Where(x => x.UserId == userId &&
                            !x.IsRevoked &&
                            x.RevokedAt == null &&
                            x.ExpiresAt > now)
                .OrderByDescending(x => x.LastActivityAt ?? x.CreatedAt)
                .ThenByDescending(x => x.CreatedAt)
                .ToListAsync();

            foreach (var excess in sessionsAfterLogin.Skip(MaxActiveSessions))
            {
                excess.IsRevoked = true;
                excess.RevokedAt = now;
                excess.LastActivityAt = now;
            }

            await _db.SaveChangesAsync();
            if (transaction != null)
                await transaction.CommitAsync();

            return currentSession.Id;
        }

    }
}
