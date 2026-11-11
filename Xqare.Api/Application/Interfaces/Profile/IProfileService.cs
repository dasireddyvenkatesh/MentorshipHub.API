using Xqare.Api.Application.DTO.Profile;

namespace Xqare.Api.Application.Interfaces.Profile
{
    public interface IProfileService
    {
        Task<MyProfileResponse?> GetMyProfileAsync(Guid userId);
        Task<MyProfileResponse?> UpdateMyProfileAsync(Guid userId, UpdateMyProfileRequest request);
    }
}
