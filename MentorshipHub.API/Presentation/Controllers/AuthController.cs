using AspNet.Security.OAuth.GitHub;
using AspNet.Security.OAuth.LinkedIn;
using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Web;

namespace MentorshipHub.API.Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserSessionService _userSessionService;
        private readonly IOAuthUserMapper _oauthUserMapper;
        private readonly IWebHostEnvironment _env;

        public AuthController(
            IAuthService authService,
            IUserSessionService userSessionService,
            IOAuthUserMapper oauthUserMapper,
            IWebHostEnvironment env)
        {
            _authService = authService;
            _userSessionService = userSessionService;
            _oauthUserMapper = oauthUserMapper;
            _env = env;
        }

        private void SetRefreshTokenCookie(string token)
        {
            Response.Cookies.Append("refreshToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                MaxAge = TimeSpan.FromDays(7),
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var response = await _authService.LoginAsync(request);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
            }

            return Ok(response);
        }

        [HttpGet("{provider}-login")]
        public IActionResult ExternalLogin(string provider, string deviceId, string deviceName)
        {
            var schemes = new List<string>
            {
                GoogleDefaults.AuthenticationScheme,
                GitHubAuthenticationDefaults.AuthenticationScheme,
                TwitterDefaults.AuthenticationScheme,
                LinkedInAuthenticationDefaults.AuthenticationScheme
            };

            var scheme = schemes.FirstOrDefault(s =>
                s.Equals(provider, StringComparison.OrdinalIgnoreCase));

            if (scheme == null)
                return BadRequest("Invalid authentication provider");

            var redirectUrl = Url.Action("ExternalResponse", "Auth", new { provider = scheme });

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            };

            properties.Items["deviceId"] = deviceId;
            properties.Items["deviceName"] = deviceName;

            return Challenge(properties, scheme);
        }

        [HttpGet("{provider}-response")]
        public async Task<IActionResult> ExternalResponse(string provider)
        {
            var result = await HttpContext.AuthenticateAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            if (!result.Succeeded)
                return Unauthorized();

            var oauthUser = _oauthUserMapper.Map(provider, result.Principal, result.Properties);

            var response = await _authService.ExternalLoginAsync(oauthUser);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
            }

            var frontendUrl = _env.IsDevelopment()
                ? "https://localhost:7161/login"
                : "https://proud-pebble-0f828cd0f.6.azurestaticapps.net/login";

            var json = JsonSerializer.Serialize(response);
            var encoded = HttpUtility.UrlEncode(json);

            return Redirect($"{frontendUrl}?data={encoded}");
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var response = await _authService.RegisterAsync(request);

            return Ok(response);
        }

        [HttpPost("resend-email-otp")]
        public async Task<IActionResult> ResendEmailOtp([FromBody] EmailOtpRequest request)
        {
            var response = await _authService.ResendEmailOtp(request);

            return Ok(response);
        }

        [HttpPost("request-mfa-otp")]
        public async Task<IActionResult> RequestMfaOtp([FromBody] MfaOtpRequest request)
        {
            var response = await _authService.MfaOtpAsync(request);

            return Ok(response);
        }

        [HttpPost("verify-email-otp")]
        public async Task<IActionResult> VerifyEmailOtp([FromBody] VerifyEmailOtpRequest request)
        {
            var response = await _authService.VerifyEmailOtp(request);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
            }

            return Ok(response);
        }

        [HttpPost("verify-mfa-otp")]
        public async Task<IActionResult> VerifyMfaOtp([FromBody] VerifyMfaOtpRequest request)
        {
            var response = await _authService.VerifyMfaOtpAsync(request);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
            }

            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return Unauthorized(new { message = "Refresh token missing" });

            var result = await _authService.RefreshAsync(refreshToken);

            if (result.response.IsSuccess && !string.IsNullOrEmpty(result.refreshToken))
            {
                SetRefreshTokenCookie(result.refreshToken);
            }

            return Ok(result.response);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
            {
                await _userSessionService.RevokeAsync(refreshToken);
                Response.Cookies.Delete("refreshToken");
            }

            return Ok(new { message = "Logged out successfully" });
        }


    }
}