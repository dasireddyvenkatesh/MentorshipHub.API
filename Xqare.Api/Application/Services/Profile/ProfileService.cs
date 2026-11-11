using Xqare.Api.Application.DTO.Profile;
using Xqare.Api.Constants.Messages;
using Xqare.Api.Application.Interfaces.Profile;
using Xqare.Api.Enities;
using Xqare.Api.Infrastructure.EntityModels.Profile;
using Xqare.Api.Infrastructure.EntityModels.Identity;
using Microsoft.EntityFrameworkCore;

namespace Xqare.Api.Application.Services.Profile
{
    public sealed class ProfileService : IProfileService
    {
        private readonly AppDbContext _db;

        public ProfileService(AppDbContext db)
        {
            _db = db;
        }

        public async Task<MyProfileResponse?> GetMyProfileAsync(Guid userId)
        {
            var user = await LoadUserAsync(userId);
            return user == null ? null : Map(user);
        }

        public async Task<MyProfileResponse?> UpdateMyProfileAsync(Guid userId, UpdateMyProfileRequest request)
        {
            var user = await _db.Users
                .Include(x => x.Profile)
                .Include(x => x.UserRoles)
                    .ThenInclude(x => x.Role)
                .FirstOrDefaultAsync(x => x.Id == userId);

            if (user == null)
                return null;

            var firstName = request.FirstName.Trim();
            var lastName = request.LastName.Trim();

            if (string.IsNullOrWhiteSpace(firstName) || string.IsNullOrWhiteSpace(lastName))
                throw new ArgumentException(ProfileMessages.NamesRequired);

            var profile = user.Profile;
            if (profile == null)
            {
                profile = new UserProfile { UserId = user.Id, FirstName = string.Empty, LastName = string.Empty };
                _db.UserProfiles.Add(profile);
                user.Profile = profile;
            }

            profile.FirstName = firstName;
            profile.LastName = lastName;
            profile.PhoneNumber = string.IsNullOrWhiteSpace(request.PhoneNumber)
                ? null
                : request.PhoneNumber.Trim();
            profile.Bio = string.IsNullOrWhiteSpace(request.Bio)
                ? null
                : request.Bio.Trim();

            await _db.SaveChangesAsync();

            return Map(user);
        }

        private Task<User?> LoadUserAsync(Guid userId)
            => _db.Users.AsNoTracking()
                .Include(x => x.Profile)
                .Include(x => x.UserRoles)
                    .ThenInclude(x => x.Role)
                .FirstOrDefaultAsync(x => x.Id == userId);

        private static MyProfileResponse Map(User user)
        {
            var firstName = user.Profile?.FirstName?.Trim() ?? string.Empty;
            var lastName = user.Profile?.LastName?.Trim() ?? string.Empty;
            var displayName = string.Join(" ", new[] { firstName, lastName }.Where(x => !string.IsNullOrWhiteSpace(x)));

            if (string.IsNullOrWhiteSpace(displayName))
                displayName = user.Username;

            return new MyProfileResponse
            {
                UserId = user.Id,
                Email = user.Email,
                DisplayName = displayName,
                FirstName = firstName,
                LastName = lastName,
                PhoneNumber = user.Profile?.PhoneNumber ?? string.Empty,
                ProfileImageUrl = user.Profile?.ProfileImageUrl,
                Bio = user.Profile?.Bio ?? string.Empty,
                IsEmailConfirmed = user.IsEmailConfirmed,
                IsActive = user.IsActive,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt,
                Roles = user.UserRoles?
                    .Where(x => x.Role != null)
                    .Select(x => x.Role.Name)
                    .Distinct()
                    .OrderBy(x => x)
                    .ToList() ?? new List<string>()
            };
        }
    }
}
