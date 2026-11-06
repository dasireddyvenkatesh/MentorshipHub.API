using MentorshipHub.API.Application.DTO.Profile;

namespace MentorshipHub.API.Application.Interfaces.Profile
{
    public interface IProfileService
    {
        Task<MyProfileResponse?> GetMyProfileAsync(Guid userId);
        Task<MyProfileResponse?> UpdateMyProfileAsync(Guid userId, UpdateMyProfileRequest request);
    }
}
