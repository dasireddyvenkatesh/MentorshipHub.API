using MentorshipHub.API.Application.DTO.Admin;

namespace MentorshipHub.API.Application.Interfaces.Admin
{
    public interface IAdminService
    {
        Task<AdminOverviewResponse> GetOverviewAsync();
        Task<AdminUsersResponse> GetUsersAsync(string? search, bool? isActive, int page, int pageSize);
        Task<AdminUserDetailsResponse?> GetUserDetailsAsync(Guid userId);
        Task<AdminUserActionResponse> UpdateUserStatusAsync(Guid actorUserId, Guid targetUserId, bool isActive);
    }
}
