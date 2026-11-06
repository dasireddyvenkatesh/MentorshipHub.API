using System.Security.Claims;
using MentorshipHub.API.Application.DTO.Admin;
using MentorshipHub.API.Application.Interfaces.Admin;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/admin")]
    public sealed class AdminController : ControllerBase
    {
        private readonly IAdminService _adminService;

        public AdminController(IAdminService adminService)
        {
            _adminService = adminService;
        }

        [HttpGet("overview")]
        [Authorize(Policy = "Permission:ADMIN_OVERVIEW_VIEW")]
        public async Task<ActionResult<AdminOverviewResponse>> GetOverview()
            => Ok(await _adminService.GetOverviewAsync());

        [HttpGet("users")]
        [Authorize(Policy = "Permission:ADMIN_USERS_VIEW")]
        public async Task<ActionResult<AdminUsersResponse>> GetUsers(
            [FromQuery] string? search,
            [FromQuery] bool? isActive,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20)
        {
            if (search?.Length > 100)
                return BadRequest(new { isSuccess = false, message = "Search text cannot exceed 100 characters." });

            page = Math.Max(1, page);
            pageSize = Math.Clamp(pageSize, 1, 100);

            return Ok(await _adminService.GetUsersAsync(search, isActive, page, pageSize));
        }

        [HttpGet("users/{userId:guid}")]
        [Authorize(Policy = "Permission:ADMIN_USERS_VIEW")]
        public async Task<ActionResult<AdminUserDetailsResponse>> GetUserDetails(Guid userId)
        {
            var user = await _adminService.GetUserDetailsAsync(userId);
            return user == null
                ? NotFound(new { isSuccess = false, message = "The requested user could not be found." })
                : Ok(user);
        }

        [HttpPut("users/{userId:guid}/status")]
        [Authorize(Policy = "Permission:ADMIN_USERS_MANAGE")]
        public async Task<ActionResult<AdminUserActionResponse>> UpdateUserStatus(
            Guid userId,
            [FromBody] UpdateAdminUserStatusRequest request)
        {
            if (!Guid.TryParse(User.FindFirst("uid")?.Value, out var actorUserId))
                return Unauthorized(new { isSuccess = false, message = "The administrator identity is invalid." });

            var result = await _adminService.UpdateUserStatusAsync(
                actorUserId, userId, request.IsActive);

            return result.ErrorCode switch
            {
                "NOT_FOUND" => NotFound(result),
                "SELF_DISABLE" => BadRequest(result),
                "LAST_SUPERADMIN" => Conflict(result),
                _ when result.IsSuccess => Ok(result),
                _ => BadRequest(result)
            };
        }
    }
}
