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
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;

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

        private static CookieOptions RefreshTokenCookieOptions() => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            // Scope the refresh cookie to authentication endpoints only.
            Path = "/api/auth",
            MaxAge = TimeSpan.FromDays(7)
        };

        private void SetRefreshTokenCookie(string token)
        {
            // Remove any root-scoped cookie issued by an earlier sandbox version.
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            Response.Cookies.Append("refreshToken", token, RefreshTokenCookieOptions());
        }

        private static CookieOptions MfaChallengeCookieOptions() => new()
        {
            HttpOnly = true, Secure = true, SameSite = SameSiteMode.None,
            Path = "/api/auth", MaxAge = TimeSpan.FromMinutes(5)
        };
        private void SetMfaChallengeCookie(string token)
            => Response.Cookies.Append("xqare_mfa_challenge", token, MfaChallengeCookieOptions());
        private void ClearMfaChallengeCookie()
            => Response.Cookies.Delete("xqare_mfa_challenge", new CookieOptions
            { HttpOnly = true, Secure = true, SameSite = SameSiteMode.None, Path = "/api/auth" });
        private Guid? CurrentUserId()
            => Guid.TryParse(User.FindFirst("uid")?.Value, out var userId) ? userId : null;

        private void ClearRefreshTokenCookie()
        {
            // Clear both the legacy default path (/api/auth) and root-path cookies
            // issued during the sandbox rollout, so duplicate cookie names cannot linger.
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            });
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });
        }

        private string FrontendLoginUrl() => _env.IsDevelopment()
            ? "https://localhost:7161/login"
            : "https://sandbox.xqare.in/login";

        private IActionResult ExternalLoginFailure(string message)
        {
            var url = QueryHelpers.AddQueryString(FrontendLoginUrl(), new Dictionary<string, string?>
            {
                ["externalLogin"] = "failed",
                ["message"] = message
            });
            return Redirect(url);
        }

        // CORS controls whether a browser can read a response; validate Origin as well
        // for cookie-authenticated POSTs to reduce cross-site request forgery risk.
        private bool HasTrustedBrowserOrigin()
        {
            var origin = Request.Headers["Origin"].ToString();
            if (string.IsNullOrWhiteSpace(origin))
                return true; // Non-browser clients do not normally send Origin.

            return string.Equals(origin, "https://sandbox.xqare.in", StringComparison.OrdinalIgnoreCase)
                || string.Equals(origin, "https://www.sandbox.xqare.in", StringComparison.OrdinalIgnoreCase)
                || string.Equals(origin, "https://localhost:7161", StringComparison.OrdinalIgnoreCase);
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var response = await _authService.RequestPasswordResetAsync(request);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var response = await _authService.ResetPasswordAsync(request);

            if (response.IsSuccess)
                ClearRefreshTokenCookie();

            return Ok(response);
        }

        [HttpPost("login")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var response = await _authService.LoginAsync(request);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.MfaChallengeToken))
            {
                SetMfaChallengeCookie(response.MfaChallengeToken);
                response.MfaChallengeToken = null;
            }
            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                ClearMfaChallengeCookie();
                SetRefreshTokenCookie(response.RefreshToken);
                response.RefreshToken = string.Empty;
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

            if (!result.Succeeded || result.Principal == null || result.Properties == null)
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return ExternalLoginFailure("External sign-in failed. Please try again.");
            }

            var oauthUser = _oauthUserMapper.Map(provider, result.Principal, result.Properties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // A provider ID is required for every sign-in. Email and its verification
            // status are evaluated by AuthService; an already-linked identity may not
            // need the provider to return an email on every sign-in.
            if (string.IsNullOrWhiteSpace(oauthUser.ProviderId))
            {
                return ExternalLoginFailure("The provider did not return a usable account identifier.");
            }

            var response = await _authService.ExternalLoginAsync(oauthUser);

            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
                // Never place access or refresh tokens in URL/query strings.
                return Redirect(QueryHelpers.AddQueryString(FrontendLoginUrl(), "externalLogin", "success"));
            }

            if (response.IsSuccess && response.RequiresMfa && !string.IsNullOrWhiteSpace(response.MfaChallengeToken))
            {
                SetMfaChallengeCookie(response.MfaChallengeToken);
                return Redirect(QueryHelpers.AddQueryString(FrontendLoginUrl(), new Dictionary<string, string?>
                {
                    ["mfa"] = "required",
                    ["email"] = response.Email ?? oauthUser.Email,
                    ["message"] = response.Message ?? "Enter your verification code to finish signing in."
                }));
            }

            return ExternalLoginFailure(response.Message ?? "External sign-in failed. Please try again.");
        }

        [HttpPost("register")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var response = await _authService.RegisterAsync(request);

            return Ok(response);
        }

        [HttpPost("resend-email-otp")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> ResendEmailOtp([FromBody] EmailOtpRequest request)
        {
            var response = await _authService.ResendEmailOtp(request);

            return Ok(response);
        }

        [HttpPost("verify-mfa-challenge")]
        [AllowAnonymous]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> VerifyMfaChallenge([FromBody] VerifyMfaChallengeRequest request)
        {
            var token = Request.Cookies["xqare_mfa_challenge"];
            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized(new LoginResponse { IsSuccess = false, Message = "The MFA challenge has expired. Please sign in again." });
            return await CompleteMfaVerificationAsync(request, token);
        }

        [HttpPost("verify-register-email-otp")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> VerifyRegisterEmailOtp([FromBody] VerifyEmailOtpRequest request)
        {
            var response = await _authService.VerifyRegisterEmailOtp(request);

            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.MfaChallengeToken))
            {
                SetMfaChallengeCookie(response.MfaChallengeToken);
                response.MfaChallengeToken = null;
            }

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
                // The refresh token is cookie-only; never expose it in the JSON body.
                response.RefreshToken = string.Empty;
            }

            return Ok(response);
        }

        [HttpPost("verify-email-otp")]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> VerifyEmailOtp([FromBody] VerifyEmailOtpRequest request)
        {
            var response = await _authService.VerifyEmailOtp(request);

            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.MfaChallengeToken))
            {
                SetMfaChallengeCookie(response.MfaChallengeToken);
                response.MfaChallengeToken = null;
            }

            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                SetRefreshTokenCookie(response.RefreshToken);
                // The refresh token is cookie-only; never expose it in the JSON body.
                response.RefreshToken = string.Empty;
            }

            return Ok(response);
        }

        private async Task<IActionResult> CompleteMfaVerificationAsync(VerifyMfaChallengeRequest request, string token)
        {
            var response = await _authService.VerifyMfaChallengeAsync(request, token);
            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                ClearMfaChallengeCookie();
                SetRefreshTokenCookie(response.RefreshToken);
                response.RefreshToken = string.Empty;
            }
            return Ok(response);
        }

        [HttpGet("totp/status")]
        [Authorize]
        public async Task<IActionResult> GetTotpStatus()
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.GetTotpStatusAsync(id.Value));
        }

        [HttpPost("totp/enrollment/start")]
        [Authorize]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> StartTotpEnrollment([FromBody] TotpEnrollmentStartRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.StartTotpEnrollmentAsync(id.Value, request));
        }

        [HttpPost("totp/enrollment/confirm")]
        [Authorize]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> ConfirmTotpEnrollment([FromBody] TotpEnrollmentConfirmRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.ConfirmTotpEnrollmentAsync(id.Value, request));
        }

        [HttpPost("totp/recovery-codes/regenerate")]
        [Authorize]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> RegenerateTotpRecoveryCodes([FromBody] TotpRecoveryCodesRegenerateRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.RegenerateTotpRecoveryCodesAsync(id.Value, request));
        }

        [HttpPost("totp/disable")]
        [Authorize]
        [EnableRateLimiting("otp-ip")]
        public async Task<IActionResult> DisableTotp([FromBody] TotpDisableRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.DisableTotpAsync(id.Value, request));
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            if (!HasTrustedBrowserOrigin())
                return StatusCode(StatusCodes.Status403Forbidden, new { isSuccess = false, message = "Untrusted request origin." });

            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                ClearRefreshTokenCookie();
                return Unauthorized(new { isSuccess = false, message = "Refresh token missing. Please sign in again." });
            }

            var result = await _authService.RefreshAsync(refreshToken);
            if (result.response.IsSuccess && !string.IsNullOrWhiteSpace(result.refreshToken))
            {
                SetRefreshTokenCookie(result.refreshToken);
                return Ok(result.response);
            }

            ClearRefreshTokenCookie();
            return Unauthorized(result.response);
        }

        [AllowAnonymous]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            if (!HasTrustedBrowserOrigin())
                return StatusCode(StatusCodes.Status403Forbidden, new { message = "Untrusted request origin." });

            var refreshToken = Request.Cookies["refreshToken"];
            if (!string.IsNullOrWhiteSpace(refreshToken))
                await _userSessionService.RevokeAsync(refreshToken);

            // Always clear the cookie, even when the access token/session has already expired.
            ClearRefreshTokenCookie();
            ClearMfaChallengeCookie();
            return Ok("Logged out successfully");
        }


    }
}