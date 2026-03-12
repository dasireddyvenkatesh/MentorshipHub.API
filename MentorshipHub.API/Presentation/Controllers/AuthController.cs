using AspNet.Security.OAuth.GitHub;
using AspNet.Security.OAuth.LinkedIn;
using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Mvc;

namespace MentorshipHub.API.Presentation.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserSessionService _userSessionService;
        private readonly IOAuthUserMapper _oauthUserMapper;

        public AuthController(IAuthService authService, IUserSessionService userSessionService, IOAuthUserMapper oauthUserMapper)
        {
            _authService = authService;
            _userSessionService = userSessionService;
            _oauthUserMapper = oauthUserMapper;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {

            var response = await _authService.LoginAsync(request);

            if (!string.IsNullOrEmpty(response.RefreshToken))
            {
                Response.Cookies.Append("refreshToken", response.RefreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    MaxAge = TimeSpan.FromDays(7),
                    IsEssential = true,
                    Path = "/api/auth"
                });
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

            provider = schemes.First(s => provider.Equals(s, StringComparison.OrdinalIgnoreCase));

            var redirectUrl = Url.Action("ExternalResponse", "Auth", new { provider });

            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            };

            properties.Items["deviceId"] = deviceId;
            properties.Items["deviceName"] = deviceName;

            return Challenge(properties, provider);
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

            return Ok(response);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            var response = await _authService.RegisterAsync(request);

            return Ok(response);
        }

        [HttpPost("resend-email-otp")]
        public async Task<IActionResult> ResendEmailOtp(EmailOtpRequest request)
        {
            var response = await _authService.ResendEmailOtp(request);

            return Ok(response);
        }

        [HttpPost("request-mfa-otp")]
        public async Task<IActionResult> MfaOtpRequest(MfaOtpRequest request)
        {
            var response = await _authService.MfaOtpAsync(request);

            return Ok(response);
        }


        [HttpPost("verify-email-otp")]
        public async Task<IActionResult> EmailVerficationOtp(VerifyEmailOtpRequest request)
        {
            var response = await _authService.VerifyEmailOtp(request);

            return Ok(response);
        }

        [HttpPost("verify-mfa-otp")]
        public async Task<IActionResult> VerifyMfaOtp(VerifyMfaOtpRequest request)
        {
            var response = await _authService.VerifyMfaOtpAsync(request);

            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            string refreshToken = Request.Cookies["refreshToken"] ?? string.Empty;

            var result = await _authService.RefreshAsync(refreshToken);

            if (result.response.IsSuccess)
            {
                Response.Cookies.Append("refreshToken", result.refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    MaxAge = TimeSpan.FromDays(7),
                    IsEssential = true,
                    Path = "/api/auth"
                });
            }

            return Ok(result);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
                await _userSessionService.RevokeAsync(refreshToken);

            Response.Cookies.Delete("refreshToken");

            return Ok();
        }
    }
}
