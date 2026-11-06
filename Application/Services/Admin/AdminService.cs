using MentorshipHub.API.Application.DTO.Admin;
using MentorshipHub.API.Application.Interfaces.Admin;
using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Services.Admin
{
    public sealed class AdminService : IAdminService
    {
        private const string SuperAdminCode = "SUPERADMIN";
        private readonly AppDbContext _db;

        public AdminService(AppDbContext db)
        {
            _db = db;
        }

        public async Task<AdminOverviewResponse> GetOverviewAsync()
        {
            var now = DateTime.UtcNow;
            var registrationsSince = now.AddDays(-30);

            var totalUsers = await _db.Users.CountAsync();
            var activeUsers = await _db.Users.CountAsync(x => x.IsActive);
            var disabledUsers = totalUsers - activeUsers;
            var recentRegistrations = await _db.Users.CountAsync(x => x.CreatedAt >= registrationsSince);
            var activeSessions = await _db.UserSessions.CountAsync(x =>
                x.User.IsActive &&
                !x.IsRevoked &&
                x.RevokedAt == null &&
                x.ExpiresAt > now);

            return new AdminOverviewResponse
            {
                TotalUsers = totalUsers,
                ActiveUsers = activeUsers,
                DisabledUsers = disabledUsers,
                NewRegistrationsLast30Days = recentRegistrations,
                ActiveSessions = activeSessions,
                GeneratedAtUtc = now
            };
        }

        public async Task<AdminUsersResponse> GetUsersAsync(
            string? search, bool? isActive, int page, int pageSize)
        {
            page = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 100);

            var query = _db.Users
                .AsNoTracking()
                .Include(x => x.Profile)
                .Include(x => x.UserRoles)
                    .ThenInclude(x => x.Role)
                .AsQueryable();

            if (isActive.HasValue)
                query = query.Where(x => x.IsActive == isActive.Value);

            if (!string.IsNullOrWhiteSpace(search))
            {
                var term = search.Trim().ToLowerInvariant();
                query = query.Where(x =>
                    x.Email.ToLower().Contains(term) ||
                    x.Username.ToLower().Contains(term) ||
                    (x.Profile != null &&
                        (x.Profile.FirstName.ToLower().Contains(term) ||
                         x.Profile.LastName.ToLower().Contains(term))));
            }

            var totalCount = await query.CountAsync();
            var users = await query
                .OrderByDescending(x => x.CreatedAt)
                .ThenBy(x => x.Email)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return new AdminUsersResponse
            {
                Page = page,
                PageSize = pageSize,
                TotalCount = totalCount,
                TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize),
                Items = users.Select(x => new AdminUserListItemResponse
                {
                    UserId = x.Id,
                    Email = x.Email,
                    Username = x.Username,
                    FirstName = x.Profile?.FirstName ?? string.Empty,
                    LastName = x.Profile?.LastName ?? string.Empty,
                    ProfileImageUrl = x.Profile?.ProfileImageUrl,
                    IsActive = x.IsActive,
                    IsEmailConfirmed = x.IsEmailConfirmed,
                    CreatedAt = x.CreatedAt,
                    LastLoginAt = x.LastLoginAt,
                    Roles = x.UserRoles
                        .Select(userRole => userRole.Role.Name)
                        .OrderBy(role => role)
                        .ToList()
                }).ToList()
            };
        }

        public async Task<AdminUserDetailsResponse?> GetUserDetailsAsync(Guid userId)
        {
            var user = await _db.Users
                .AsNoTracking()
                .Include(x => x.Profile)
                .Include(x => x.UserRoles)
                    .ThenInclude(x => x.Role)
                .FirstOrDefaultAsync(x => x.Id == userId);

            if (user == null)
                return null;

            var now = DateTime.UtcNow;
            var sessionQuery = _db.UserSessions.Where(x => x.UserId == userId);
            var activeSessions = await sessionQuery.CountAsync(x =>
                !x.IsRevoked && x.RevokedAt == null && x.ExpiresAt > now);
            var totalSessions = await sessionQuery.CountAsync();

            return new AdminUserDetailsResponse
            {
                UserId = user.Id,
                Email = user.Email,
                Username = user.Username,
                FirstName = user.Profile?.FirstName ?? string.Empty,
                LastName = user.Profile?.LastName ?? string.Empty,
                PhoneNumber = user.Profile?.PhoneNumber,
                Bio = user.Profile?.Bio,
                ProfileImageUrl = user.Profile?.ProfileImageUrl,
                IsActive = user.IsActive,
                IsEmailConfirmed = user.IsEmailConfirmed,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt,
                ActiveSessionCount = activeSessions,
                TotalSessionCount = totalSessions,
                Roles = user.UserRoles
                    .Select(userRole => userRole.Role.Name)
                    .OrderBy(role => role)
                    .ToList()
            };
        }

        public async Task<AdminUserActionResponse> UpdateUserStatusAsync(
            Guid actorUserId, Guid targetUserId, bool isActive)
        {
            if (!isActive && actorUserId == targetUserId)
            {
                return new AdminUserActionResponse
                {
                    IsSuccess = false,
                    ErrorCode = "SELF_DISABLE",
                    Message = "You cannot disable your own administrator account."
                };
            }

            await using var transaction = await _db.Database.BeginTransactionAsync();

            // Serialize account-status changes so concurrent administrators cannot
            // disable the final active Super Admin at the same time.
            const string lockKey = "xqare-admin-user-status";
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

            var user = await _db.Users
                .Include(x => x.UserRoles)
                    .ThenInclude(x => x.Role)
                .FirstOrDefaultAsync(x => x.Id == targetUserId);

            if (user == null)
            {
                await transaction.RollbackAsync();
                return new AdminUserActionResponse
                {
                    IsSuccess = false,
                    ErrorCode = "NOT_FOUND",
                    Message = "The requested user could not be found."
                };
            }

            var isSuperAdmin = user.UserRoles.Any(x => IsSuperAdminRole(x.Role.Code, x.Role.Name));

            if (!isActive && isSuperAdmin)
            {
                var activeSuperAdmins = await _db.UserRoles.CountAsync(x =>
                    x.User.IsActive &&
                    x.Role.Code == SuperAdminCode);

                if (activeSuperAdmins <= 1)
                {
                    await transaction.RollbackAsync();
                    return new AdminUserActionResponse
                    {
                        IsSuccess = false,
                        ErrorCode = "LAST_SUPERADMIN",
                        Message = "The last active Super Admin cannot be disabled."
                    };
                }
            }

            var now = DateTime.UtcNow;
            var affectedSessions = 0;

            if (isActive)
            {
                user.IsActive = true;
            }
            else
            {
                user.IsActive = false;

                var sessions = await _db.UserSessions
                    .Where(x => x.UserId == targetUserId &&
                                !x.IsRevoked &&
                                x.RevokedAt == null)
                    .ToListAsync();

                foreach (var session in sessions)
                {
                    session.IsRevoked = true;
                    session.RevokedAt = now;
                    session.LastActivityAt = now;
                }

                affectedSessions = sessions.Count;
            }

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return new AdminUserActionResponse
            {
                IsSuccess = true,
                Message = isActive
                    ? "The account has been enabled. The user can sign in again."
                    : "The account has been disabled and its active sessions have been revoked.",
                IsActive = user.IsActive,
                AffectedSessions = affectedSessions
            };
        }

        private static bool IsSuperAdminRole(string? code, string? name)
            => string.Equals(code, SuperAdminCode, StringComparison.OrdinalIgnoreCase);
    }
}
