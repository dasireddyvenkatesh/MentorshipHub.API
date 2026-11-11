using System.Security.Claims;
using Xqare.Api.Application.DTO.Profile;
using Xqare.Api.Constants.Messages;
using Xqare.Api.Application.Interfaces.Profile;
using Xqare.Api.Application.Validators;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Xqare.Api.Presentation.Controllers
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
                return Unauthorized(new { isSuccess = false, message = ProfileMessages.IdentityInvalid });

            var profile = await _profileService.GetMyProfileAsync(userId);
            if (profile == null)
                return NotFound(new { isSuccess = false, message = ProfileMessages.NotFound });

            return Ok(profile);
        }

        [HttpPut("me")]
        public async Task<IActionResult> UpdateMyProfile([FromBody] UpdateMyProfileRequest request)
        {
            if (!Guid.TryParse(User.FindFirst("uid")?.Value, out var userId))
                return Unauthorized(new { isSuccess = false, message = ProfileMessages.IdentityInvalid });

            // Store valid Indian mobile numbers in one canonical +91 format.
            request.PhoneNumber = NameValidationRules.NormalizeIndianMobile(request.PhoneNumber);

            var profile = await _profileService.UpdateMyProfileAsync(userId, request);
            if (profile == null)
                return NotFound(new { isSuccess = false, message = ProfileMessages.NotFound });

            profile.Message = ProfileMessages.Updated;
            return Ok(profile);
        }
    }
}
