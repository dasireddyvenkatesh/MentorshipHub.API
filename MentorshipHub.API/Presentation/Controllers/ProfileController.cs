using System.Security.Claims;
using MentorshipHub.API.Application.DTO.Profile;
using MentorshipHub.API.Application.Interfaces.Profile;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/profile")]
    public sealed class ProfileController : ControllerBase
    {
        private readonly IProfileService _profileService;

        public ProfileController(IProfileService profileService)
        {
            _profileService = profileService;
        }

        [HttpGet("me")]
        public async Task<IActionResult> GetMyProfile()
        {
            if (!Guid.TryParse(User.FindFirst("uid")?.Value, out var userId))
                return Unauthorized(new { isSuccess = false, message = "The authenticated user identity is invalid." });

            var profile = await _profileService.GetMyProfileAsync(userId);
            if (profile == null)
                return NotFound(new { isSuccess = false, message = "The account profile could not be found." });

            return Ok(profile);
        }

        [HttpPut("me")]
        public async Task<IActionResult> UpdateMyProfile([FromBody] UpdateMyProfileRequest request)
        {
            if (!Guid.TryParse(User.FindFirst("uid")?.Value, out var userId))
                return Unauthorized(new { isSuccess = false, message = "The authenticated user identity is invalid." });

            var profile = await _profileService.UpdateMyProfileAsync(userId, request);
            if (profile == null)
                return NotFound(new { isSuccess = false, message = "The account profile could not be found." });

            profile.Message = "Your profile has been updated.";
            return Ok(profile);
        }
    }
}
