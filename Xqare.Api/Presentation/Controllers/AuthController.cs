using Xqare.Api.Constants.Messages;
using AspNet.Security.OAuth.GitHub;
using AspNet.Security.OAuth.LinkedIn;
using Xqare.Api.Application.DTO.Auth;
using Xqare.Api.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Twitter;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text.Json;

namespace Xqare.Api.Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private const string RefreshTokenCookieName = "xqare_refresh_v2";
        private const string MfaChallengeCookieName = "xqare_mfa_challenge_v2";
        private const string ExternalLinkTicketCookieName = "xqare_external_link_v2";
        private const string ExternalLinkIntentKey = "xqare:auth-intent";
        private const string ExternalLinkUserIdKey = "xqare:link-user-id";
        private const string ExternalLinkSessionIdKey = "xqare:link-session-id";
        private const string ExternalLinkNonceKey = "xqare:link-nonce";
        private const string ExternalLinkProviderKey = "xqare:link-provider";
        private const string MfaRecoveryIntentKey = "xqare:mfa-recovery-intent";
        private const string MfaRecoveryEmailProofKey = "xqare:mfa-recovery-email-proof";
        private const string MfaRecoveryTicketCookieName = "xqare_mfa_recovery_v2";
        private readonly IAuthService _authService;
        private readonly IUserSessionService _userSessionService;
        private readonly IOAuthUserMapper _oauthUserMapper;
        private readonly IWebHostEnvironment _env;
        private readonly IDataProtector _externalLinkTicketProtector;
        private readonly IDataProtector _mfaRecoveryTicketProtector;
        private readonly IConfiguration _configuration;

        public AuthController(
            IAuthService authService,
            IUserSessionService userSessionService,
            IOAuthUserMapper oauthUserMapper,
            IWebHostEnvironment env,
            IDataProtectionProvider dataProtectionProvider,
            IConfiguration configuration)
        {
            _authService = authService;
            _userSessionService = userSessionService;
            _oauthUserMapper = oauthUserMapper;
            _env = env;
            _configuration = configuration;
            _externalLinkTicketProtector = dataProtectionProvider.CreateProtector("XQARE.ExternalLoginLink.v2");
            _mfaRecoveryTicketProtector = dataProtectionProvider.CreateProtector("XQARE.MfaRecoveryOAuth.v2");
        }

        private static CookieOptions RefreshTokenCookieOptions()
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                // Scope the refresh cookie to authentication endpoints only.
                Path = "/api/auth",
                MaxAge = TimeSpan.FromDays(7)
            };

            // CHIPS: keep this cross-site API cookie available only within the
            // top-level XQARE site partition, without unrestricted third-party access.
            options.Extensions.Add("Partitioned");
            return options;
        }

        private void SetRefreshTokenCookie(string token)
        {
            // Remove the previous unpartitioned cookie during migration so the
            // browser cannot send duplicate refresh-cookie names.
            Response.Cookies.Delete(RefreshTokenCookieName, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            });

            Response.Cookies.Append(RefreshTokenCookieName, token, RefreshTokenCookieOptions());
        }

        private static CookieOptions MfaChallengeCookieOptions()
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth",
                MaxAge = TimeSpan.FromMinutes(5)
            };
            options.Extensions.Add("Partitioned");
            return options;
        }

        private void SetMfaChallengeCookie(string token)
        {
            // Remove any legacy unpartitioned challenge before setting the
            // frontend-partitioned cookie so duplicate cookie names cannot race.
            Response.Cookies.Delete(MfaChallengeCookieName, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            });
            Response.Cookies.Append(MfaChallengeCookieName, token, MfaChallengeCookieOptions());
        }

        private void ClearMfaChallengeCookie()
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            };
            Response.Cookies.Delete(MfaChallengeCookieName, options);
            options.Extensions.Add("Partitioned");
            Response.Cookies.Delete(MfaChallengeCookieName, options);
        }
        private Guid? CurrentUserId()
            => Guid.TryParse(User.FindFirst("uid")?.Value, out var userId) ? userId : null;

        private Guid? CurrentSessionId()
            => Guid.TryParse(User.FindFirst("sid")?.Value, out var sessionId) ? sessionId : null;

        private void ClearRefreshTokenCookie()
        {
            var options = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            };

            // Expire both the legacy unpartitioned cookie and the new CHIPS cookie.
            Response.Cookies.Delete(RefreshTokenCookieName, options);

            options.Extensions.Add("Partitioned");
            Response.Cookies.Delete(RefreshTokenCookieName, options);
        }

        private string FrontendBaseUrl()
        {
            var configuredUrl = _configuration["Frontend:BaseUrl"];
            if (!Uri.TryCreate(configuredUrl, UriKind.Absolute, out var frontendUri) ||
                frontendUri.AbsolutePath != "/" ||
                !string.IsNullOrEmpty(frontendUri.Query) ||
                !string.IsNullOrEmpty(frontendUri.Fragment))
            {
                throw new InvalidOperationException(
                    "Frontend:BaseUrl must be configured as an absolute frontend origin.");
            }

            if (!string.Equals(frontendUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                !(_env.IsDevelopment() && frontendUri.IsLoopback))
            {
                throw new InvalidOperationException(
                    "Frontend:BaseUrl must use HTTPS outside local development.");
            }

            return frontendUri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }

        private string FrontendLoginUrl() => $"{FrontendBaseUrl()}/login";

        private string FrontendSettingsUrl() => $"{FrontendBaseUrl()}/settings";

        private static CookieOptions ExternalLinkTicketCookieOptions() => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/api/auth",
            MaxAge = TimeSpan.FromMinutes(5)
        };

        private void ClearExternalLinkTicketCookie()
            => Response.Cookies.Delete(ExternalLinkTicketCookieName, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/api/auth"
            });

        private static string? ResolveExternalProvider(string provider)
        {
            var supported = new[]
            {
                GoogleDefaults.AuthenticationScheme,
                GitHubAuthenticationDefaults.AuthenticationScheme,
                LinkedInAuthenticationDefaults.AuthenticationScheme,
                TwitterDefaults.AuthenticationScheme
            };

            return supported.FirstOrDefault(x =>
                x.Equals(provider, StringComparison.OrdinalIgnoreCase));
        }

        private IActionResult ExternalLinkResult(bool succeeded, string message)
        {
            var url = QueryHelpers.AddQueryString(FrontendSettingsUrl(), new Dictionary<string, string?>
            {
                ["externalLink"] = succeeded ? "success" : "failed",
                ["message"] = message
            });
            return Redirect(url);
        }

        private sealed class MfaRecoveryOAuthTicket
        {
            public string Provider { get; set; } = string.Empty;
            public string EmailProof { get; set; } = string.Empty;
            public DateTime ExpiresAtUtc { get; set; }
        }

        private static CookieOptions MfaRecoveryTicketCookieOptions() => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/api/auth",
            MaxAge = TimeSpan.FromMinutes(5),
            Extensions = { "Partitioned" }
        };

        private void ClearMfaRecoveryTicketCookie()
            => Response.Cookies.Delete(MfaRecoveryTicketCookieName, new CookieOptions
            {
                HttpOnly = true, Secure = true, SameSite = SameSiteMode.None,
                Path = "/api/auth", Extensions = { "Partitioned" }
            });

        private sealed class ExternalLinkTicket
        {
            public Guid UserId { get; set; }
            public Guid SessionId { get; set; }
            public string Provider { get; set; } = string.Empty;
            public DateTime ExpiresAtUtc { get; set; }
            public string Nonce { get; set; } = string.Empty;
        }

        private IActionResult ExternalLoginFailure(string message)
        {
            var url = QueryHelpers.AddQueryString(FrontendLoginUrl(), new Dictionary<string, string?>
            {
                ["externalLogin"] = "failed",
                ["message"] = message
            });
            return Redirect(url);
        }

        // CORS controls whether a browser can read a response; validate the request
        // source independently for endpoints that authenticate with ambient cookies.
        // Origin is preferred. Referer is an exact-origin fallback for legitimate clients
        // where browsers or intermediaries omit Origin.
        private bool HasTrustedBrowserOrigin(bool requireSource = false)
        {
            var trustedOrigins = _configuration
                .GetSection("Security:TrustedBrowserOrigins")
                .Get<string[]>()?
                .Select(value => value.Trim())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray() ?? Array.Empty<string>();

            var origin = Request.Headers["Origin"].ToString();
            if (!string.IsNullOrWhiteSpace(origin))
                return trustedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase);

            var referer = Request.Headers["Referer"].ToString();
            if (!string.IsNullOrWhiteSpace(referer))
            {
                if (!Uri.TryCreate(referer, UriKind.Absolute, out var refererUri))
                    return false;

                var refererOrigin = refererUri.GetLeftPart(UriPartial.Authority);
                return trustedOrigins.Contains(refererOrigin, StringComparer.OrdinalIgnoreCase);
            }

            // Preserve non-browser, bearer-token callers only where the endpoint does
            // not depend on an ambient cookie for authentication.
            return !requireSource;
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var response = await _authService.RequestPasswordResetAsync(request);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var response = await _authService.ResetPasswordAsync(request);

            if (response.IsSuccess)
                ClearRefreshTokenCookie();

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        [EnableRateLimiting("auth-login-ip")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var response = await _authService.LoginAsync(request);

            if (response.IsSuccess && !string.IsNullOrEmpty(response.MfaChallengeToken))
            {
                SetMfaChallengeCookie(response.MfaChallengeToken);
            }
            if (response.IsSuccess && !string.IsNullOrEmpty(response.RefreshToken))
            {
                ClearMfaChallengeCookie();
                SetRefreshTokenCookie(response.RefreshToken);
                response.RefreshToken = string.Empty;
            }
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpGet("{provider}-login")]
                public IActionResult ExternalLogin(string provider, string deviceId, string deviceName)
        {
            var scheme = ResolveExternalProvider(provider);
            if (scheme == null)
                return BadRequest(ExternalLoginMessages.ProviderInvalidBare);

            var redirectUrl = Url.Action("ExternalResponse", "Auth", new { provider = scheme });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items["deviceId"] = deviceId;
            properties.Items["deviceName"] = deviceName;
            return Challenge(properties, scheme);
        }

        // The authenticated UI first calls this endpoint to obtain a short-lived,
        // protected, HttpOnly browser ticket bound to its current XQARE user/session.
        [Authorize]
        [HttpPost("external-links/{provider}/begin")]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> BeginExternalLink(string provider)
        {
            var scheme = ResolveExternalProvider(provider);
            var userId = CurrentUserId();
            var sessionId = CurrentSessionId();

            if (scheme == null)
                return BadRequest(new { isSuccess = false, message = ExternalLoginMessages.ProviderInvalid });

            if (!userId.HasValue || !sessionId.HasValue)
                return Unauthorized();

            var nonce = await _authService.CreateExternalLinkChallengeAsync(userId.Value, sessionId.Value);
            if (string.IsNullOrWhiteSpace(nonce))
                return Unauthorized(new { isSuccess = false, message = ExternalLoginMessages.SessionInactiveConnect });

            var ticket = new ExternalLinkTicket
            {
                UserId = userId.Value,
                SessionId = sessionId.Value,
                Provider = scheme,
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5),
                Nonce = nonce
            };

            var protectedTicket = _externalLinkTicketProtector.Protect(JsonSerializer.Serialize(ticket));
            Response.Cookies.Append(ExternalLinkTicketCookieName, protectedTicket, ExternalLinkTicketCookieOptions());

            return Ok(new Xqare.Api.Application.DTO.Common.ResponseDTO
            {
                IsSuccess = true,
                Message = ExternalLoginMessages.ContinueConnect
            });
        }

        // This endpoint is reached through full browser navigation after the
        // authenticated begin request. The linking ticket is HttpOnly and Data-Protected.
        [AllowAnonymous]
        [HttpGet("{provider}-link")]
                public IActionResult ExternalLink(string provider)
        {
            var scheme = ResolveExternalProvider(provider);
            var protectedTicket = Request.Cookies[ExternalLinkTicketCookieName];
            ClearExternalLinkTicketCookie();

            if (scheme == null || string.IsNullOrWhiteSpace(protectedTicket))
                return ExternalLinkResult(false, ExternalLoginMessages.LinkExpired);

            ExternalLinkTicket? ticket;
            try
            {
                var json = _externalLinkTicketProtector.Unprotect(protectedTicket);
                ticket = JsonSerializer.Deserialize<ExternalLinkTicket>(json);
            }
            catch
            {
                ticket = null;
            }

            if (ticket == null ||
                ticket.UserId == Guid.Empty ||
                ticket.SessionId == Guid.Empty ||
                string.IsNullOrWhiteSpace(ticket.Nonce) ||
                !string.Equals(ticket.Provider, scheme, StringComparison.OrdinalIgnoreCase) ||
                ticket.ExpiresAtUtc <= DateTime.UtcNow)
            {
                return ExternalLinkResult(false, ExternalLoginMessages.LinkInvalidOrExpired);
            }

            var redirectUrl = Url.Action("ExternalResponse", "Auth", new { provider = scheme });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items[ExternalLinkIntentKey] = "link";
            properties.Items[ExternalLinkUserIdKey] = ticket.UserId.ToString("D");
            properties.Items[ExternalLinkSessionIdKey] = ticket.SessionId.ToString("D");
            properties.Items[ExternalLinkNonceKey] = ticket.Nonce;
            properties.Items[ExternalLinkProviderKey] = scheme;
            properties.Items["deviceId"] = string.Empty;
            properties.Items["deviceName"] = string.Empty;

            return Challenge(properties, scheme);
        }

        [AllowAnonymous]
        [HttpGet("{provider}-response")]
        public async Task<IActionResult> ExternalResponse(string provider)
        {
            var result = await HttpContext.AuthenticateAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            if (!result.Succeeded || result.Principal == null || result.Properties == null)
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return ExternalLoginFailure(ExternalLoginMessages.SignInFailed);
            }

            var oauthUser = _oauthUserMapper.Map(provider, result.Principal, result.Properties);
            var isLinkIntent =
                result.Properties.Items.TryGetValue(ExternalLinkIntentKey, out var intent) &&
                string.Equals(intent, "link", StringComparison.Ordinal);
            var isMfaRecoveryIntent =
                result.Properties.Items.TryGetValue(MfaRecoveryIntentKey, out var recoveryIntent) &&
                string.Equals(recoveryIntent, "recover", StringComparison.Ordinal);
            var recoveryEmailProof = result.Properties.Items.TryGetValue(MfaRecoveryEmailProofKey, out var storedEmailProof)
                ? storedEmailProof
                : null;

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (isLinkIntent)
            {
                var linkUserIdValue = result.Properties.Items.TryGetValue(ExternalLinkUserIdKey, out var storedUserId)
                    ? storedUserId
                    : null;
                var linkSessionIdValue = result.Properties.Items.TryGetValue(ExternalLinkSessionIdKey, out var storedSessionId)
                    ? storedSessionId
                    : null;
                var linkNonce = result.Properties.Items.TryGetValue(ExternalLinkNonceKey, out var storedNonce)
                    ? storedNonce
                    : null;
                var expectedProvider = result.Properties.Items.TryGetValue(ExternalLinkProviderKey, out var storedProvider)
                    ? storedProvider
                    : null;
                var callbackProvider = ResolveExternalProvider(provider);

                if (!Guid.TryParse(linkUserIdValue, out var linkUserId) ||
                    !Guid.TryParse(linkSessionIdValue, out var linkSessionId) ||
                    string.IsNullOrWhiteSpace(linkNonce) ||
                    string.IsNullOrWhiteSpace(expectedProvider) ||
                    !string.Equals(callbackProvider, expectedProvider, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(oauthUser.Provider, expectedProvider, StringComparison.OrdinalIgnoreCase) ||
                    string.IsNullOrWhiteSpace(oauthUser.ProviderId))
                {
                    return ExternalLinkResult(false, ExternalLoginMessages.LinkCouldNotValidate);
                }

                // Consume the server-side nonce before performing the account link.
                // The database row lock makes concurrent/replayed callbacks single-use.
                var challengeConsumed = await _authService.ConsumeExternalLinkChallengeAsync(linkUserId, linkNonce);
                if (!challengeConsumed)
                    return ExternalLinkResult(false, ExternalLoginMessages.LinkAlreadyUsed);

                var linkResponse = await _authService.LinkExternalLoginAsync(linkUserId, linkSessionId, oauthUser);
                return ExternalLinkResult(linkResponse.IsSuccess, linkResponse.Message);
            }

            if (isMfaRecoveryIntent)
            {
                if (string.IsNullOrWhiteSpace(recoveryEmailProof) || string.IsNullOrWhiteSpace(oauthUser.ProviderId))
                    return ExternalLoginFailure(ExternalLoginMessages.RecoveryCouldNotComplete);

                var recovery = await _authService.CompleteExternalMfaRecoveryAsync(recoveryEmailProof, oauthUser);
                if (!recovery.IsSuccess || string.IsNullOrWhiteSpace(recovery.RecoveryGrant))
                    return ExternalLoginFailure(recovery.Message ?? ExternalLoginMessages.ProviderCouldNotBeVerified);

                Response.Headers["Referrer-Policy"] = "no-referrer";
                return Redirect($"{FrontendLoginUrl()}#mfaRecovery=success&grant={Uri.EscapeDataString(recovery.RecoveryGrant)}");
            }

            // A provider ID is required for every sign-in. Email and its verification
            // status are evaluated by AuthService; an already-linked identity may not
            // need the provider to return an email on every sign-in.
            if (string.IsNullOrWhiteSpace(oauthUser.ProviderId))
            {
                return ExternalLoginFailure(ExternalLoginMessages.ProviderIdentifierMissing);
            }

            var response = await _authService.ExternalLoginAsync(oauthUser);

            if (response.IsSuccess && !string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                // The OAuth callback runs with the API as the top-level site. Do not
                // issue the CHIPS refresh cookie here: it would be stored in the API
                // partition rather than the XQARE top-level-site partition.
                var exchangeCode = await _authService.CreateExternalLoginExchangeChallengeAsync(response.RefreshToken);
                if (string.IsNullOrWhiteSpace(exchangeCode))
                {
                    await _userSessionService.RevokeAsync(response.RefreshToken);
                    return ExternalLoginFailure(ExternalLoginMessages.SignInCouldNotComplete);
                }

                Response.Headers["Referrer-Policy"] = "no-referrer";
                // Put the short-lived code in the URL fragment: fragments are
                // not sent to the API, HTTP access logs, or Referer headers.
                return Redirect($"{FrontendLoginUrl()}#externalLogin=success&code={Uri.EscapeDataString(exchangeCode)}");
            }

            if (response.IsSuccess && response.RequiresMfa && !string.IsNullOrWhiteSpace(response.MfaChallengeToken))
            {
                // Transfer the short-lived MFA challenge into the XQARE cookie
                // partition through the same top-level frontend exchange flow.
                var exchangeCode = await _authService.CreateExternalMfaLoginExchangeChallengeAsync(response.MfaChallengeToken);
                if (string.IsNullOrWhiteSpace(exchangeCode))
                    return ExternalLoginFailure(ExternalLoginMessages.VerificationCouldNotComplete);

                Response.Headers["Referrer-Policy"] = "no-referrer";
                var mfaMessage = Uri.EscapeDataString(
                    response.Message ?? "Enter your verification code to finish signing in.");
                return Redirect($"{FrontendLoginUrl()}#mfa=required&code={Uri.EscapeDataString(exchangeCode)}&message={mfaMessage}");
            }

            return ExternalLoginFailure(response.Message ?? ExternalLoginMessages.SignInFailed);
        }

        [AllowAnonymous]
        [HttpPost("register")]
        [EnableRateLimiting("auth-otp-ip")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var response = await _authService.RegisterAsync(request);

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("resend-email-otp")]
        [EnableRateLimiting("auth-otp-ip")]
        public async Task<IActionResult> ResendEmailOtp([FromBody] EmailOtpRequest request)
        {
            var response = await _authService.ResendEmailOtp(request);

            return Ok(response);
        }

        [HttpPost("mfa-recovery/external/{provider}/begin")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-recovery-ip")]
        public IActionResult BeginExternalMfaRecovery(string provider, [FromBody] MfaAccountRecoveryExternalStartRequest request)
        {
            var scheme = ResolveExternalProvider(provider);
            if (scheme == null || request == null || string.IsNullOrWhiteSpace(request.EmailProof) ||
                request.EmailProof.Length > 128)
                return BadRequest(new { isSuccess = false, message = ExternalLoginMessages.RecoveryInvalidOrExpired });

            var ticket = new MfaRecoveryOAuthTicket
            {
                Provider = scheme,
                EmailProof = request.EmailProof.Trim(),
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5)
            };
            var protectedTicket = _mfaRecoveryTicketProtector.Protect(JsonSerializer.Serialize(ticket));
            Response.Cookies.Append(MfaRecoveryTicketCookieName, protectedTicket, MfaRecoveryTicketCookieOptions());
            return Ok(new { isSuccess = true, message = ExternalLoginMessages.ContinueLinkedProvider });
        }

        [HttpGet("mfa-recovery/{provider}-login")]
        [AllowAnonymous]
                public IActionResult ExternalMfaRecoveryLogin(string provider)
        {
            var scheme = ResolveExternalProvider(provider);
            var protectedTicket = Request.Cookies[MfaRecoveryTicketCookieName];
            ClearMfaRecoveryTicketCookie();
            if (scheme == null || string.IsNullOrWhiteSpace(protectedTicket))
                return ExternalLoginFailure(ExternalLoginMessages.RecoveryExpired);

            MfaRecoveryOAuthTicket? ticket;
            try
            {
                ticket = JsonSerializer.Deserialize<MfaRecoveryOAuthTicket>(
                    _mfaRecoveryTicketProtector.Unprotect(protectedTicket));
            }
            catch
            {
                ticket = null;
            }

            if (ticket == null || ticket.ExpiresAtUtc <= DateTime.UtcNow ||
                !string.Equals(ticket.Provider, scheme, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(ticket.EmailProof))
                return ExternalLoginFailure(ExternalLoginMessages.RecoveryExpired);

            var redirectUrl = Url.Action("ExternalResponse", "Auth", new { provider = scheme });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items[MfaRecoveryIntentKey] = "recover";
            properties.Items[MfaRecoveryEmailProofKey] = ticket.EmailProof;
            properties.Items["deviceId"] = string.Empty;
            properties.Items["deviceName"] = string.Empty;
            return Challenge(properties, scheme);
        }

        [HttpPost("mfa-recovery/request")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> RequestMfaAccountRecovery([FromBody] MfaAccountRecoveryRequest request)
        {
            var response = await _authService.RequestMfaAccountRecoveryAsync(request);
            return Ok(response);
        }

        [HttpPost("mfa-recovery/verify-otp")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> VerifyMfaAccountRecoveryOtp([FromBody] MfaAccountRecoveryVerifyRequest request)
        {
            var response = await _authService.VerifyMfaAccountRecoveryOtpAsync(request);
            return Ok(response);
        }

        [HttpPost("mfa-recovery/start-enrollment")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> StartMfaRecoveryEnrollment([FromBody] MfaAccountRecoveryEnrollmentStartRequest request)
        {
            var response = await _authService.StartMfaRecoveryEnrollmentAsync(request);
            return Ok(response);
        }

        [HttpPost("mfa-recovery/complete")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-recovery-ip")]
        public async Task<IActionResult> CompleteMfaAccountRecovery([FromBody] MfaAccountRecoveryCompleteRequest request)
        {
            var response = await _authService.CompleteMfaAccountRecoveryAsync(request);
            if (response.IsSuccess)
            {
                // The recovery operation revokes every session, including any stale
                // browser session cookies that may still be present on this device.
                ClearRefreshTokenCookie();
                ClearMfaChallengeCookie();
            }
            return Ok(response);
        }

        [HttpPost("verify-mfa-challenge")]
        [AllowAnonymous]
        [EnableRateLimiting("auth-otp-ip")]
        public async Task<IActionResult> VerifyMfaChallenge([FromBody] VerifyMfaChallengeRequest request)
        {
            // Prefer the short-lived challenge token explicitly returned to the
            // UI for password sign-in. Keep the HttpOnly cookie as a fallback for
            // external OAuth redirects that cannot carry a request body token.
            var usesCookieChallenge = string.IsNullOrWhiteSpace(request?.ChallengeToken);
            var token = usesCookieChallenge
                ? Request.Cookies[MfaChallengeCookieName]
                : request!.ChallengeToken;

            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized(new LoginResponse { IsSuccess = false, Message = SessionMessages.MfaChallengeExpired });

            if (usesCookieChallenge && !HasTrustedBrowserOrigin(requireSource: true))
                return StatusCode(StatusCodes.Status403Forbidden,
                    new { isSuccess = false, message = ExternalLoginMessages.TrustedCookieMfaOriginRequired });

            return await CompleteMfaVerificationAsync(request, token);
        }

        [AllowAnonymous]
        [HttpPost("verify-register-email-otp")]
        [EnableRateLimiting("auth-otp-ip")]
        public async Task<IActionResult> VerifyRegisterEmailOtp([FromBody] VerifyRegisterEmailOtpRequest request)
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

        [HttpGet("sessions")]
        [Authorize]
        public async Task<IActionResult> GetActiveSessions()
        {
            var userId = CurrentUserId();
            var currentSessionId = CurrentSessionId();
            if (!userId.HasValue || !currentSessionId.HasValue)
                return Unauthorized();

            var sessions = await _userSessionService.GetActiveSessionsAsync(userId.Value, currentSessionId.Value);
            return Ok(new ActiveSessionsResponse
            {
                IsSuccess = true,
                Message = SessionMessages.ActiveSessionsRetrieved,
                Sessions = sessions.Select(x => new ActiveSessionDto
                {
                    SessionId = x.Id,
                    DeviceName = string.IsNullOrWhiteSpace(x.DeviceName) ? "Unknown device" : x.DeviceName,
                    IpAddress = x.IpAddress ?? string.Empty,
                    CreatedAt = x.CreatedAt,
                    LastActivityAt = x.LastActivityAt,
                    ExpiresAt = x.ExpiresAt,
                    IsCurrentSession = x.Id == currentSessionId.Value
                }).ToList()
            });
        }

        [HttpPost("sessions/{sessionId:guid}/revoke")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> RevokeSession(Guid sessionId)
        {
            var userId = CurrentUserId();
            var currentSessionId = CurrentSessionId();
            if (!userId.HasValue || !currentSessionId.HasValue)
                return Unauthorized();

            var revoked = await _userSessionService.RevokeSessionAsync(userId.Value, sessionId);
            if (!revoked)
                return NotFound(new SessionActionResponse
                {
                    IsSuccess = false,
                    Message = SessionMessages.SessionNotFoundOrRevoked
                });

            var isCurrentSession = sessionId == currentSessionId.Value;
            if (isCurrentSession)
            {
                ClearRefreshTokenCookie();
                ClearMfaChallengeCookie();
            }

            return Ok(new SessionActionResponse
            {
                IsSuccess = true,
                Message = isCurrentSession
                    ? SessionMessages.CurrentSessionRevoked
                    : SessionMessages.SelectedSessionRevoked,
                AffectedSessions = 1,
                IsCurrentSession = isCurrentSession
            });
        }

        [HttpPost("sessions/revoke-others")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> RevokeOtherSessions()
        {
            var userId = CurrentUserId();
            var currentSessionId = CurrentSessionId();
            if (!userId.HasValue || !currentSessionId.HasValue)
                return Unauthorized();

            var revokedCount = await _userSessionService.RevokeOtherSessionsAsync(userId.Value, currentSessionId.Value);
            return Ok(new SessionActionResponse
            {
                IsSuccess = true,
                Message = revokedCount == 0
                    ? SessionMessages.NoOtherActiveSessions
                    : string.Format(SessionMessages.OtherSessionsSignedOut, revokedCount),
                AffectedSessions = revokedCount,
                IsCurrentSession = false
            });
        }

        [Authorize]
        [HttpGet("connected-accounts")]
        public async Task<IActionResult> GetConnectedAccounts()
        {
            var userId = CurrentUserId();
            if (!userId.HasValue)
                return Unauthorized();

            var response = await _authService.GetConnectedAccountsAsync(userId.Value);
            return response.IsSuccess ? Ok(response) : NotFound(response);
        }

        [HttpPost("external-links/{provider}/disconnect")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> DisconnectExternalLogin(
            string provider,
            [FromBody] DisconnectExternalLoginRequest request)
        {
            if (!HasTrustedBrowserOrigin())
                return StatusCode(StatusCodes.Status403Forbidden,
                    new { isSuccess = false, message = ExternalLoginMessages.UntrustedOrigin });

            var userId = CurrentUserId();
            var currentSessionId = CurrentSessionId();
            if (!userId.HasValue || !currentSessionId.HasValue)
                return Unauthorized();

            return Ok(await _authService.DisconnectExternalLoginAsync(
                userId.Value,
                currentSessionId.Value,
                provider,
                request?.CurrentPassword ?? string.Empty));
        }

        [HttpPost("change-password")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var userId = CurrentUserId();
            var currentSessionId = CurrentSessionId();
            if (!userId.HasValue || !currentSessionId.HasValue)
                return Unauthorized();

            return Ok(await _authService.ChangePasswordAsync(userId.Value, currentSessionId.Value, request));
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
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> StartTotpEnrollment([FromBody] TotpEnrollmentStartRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.StartTotpEnrollmentAsync(id.Value, request));
        }

        [HttpPost("totp/enrollment/confirm")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> ConfirmTotpEnrollment([FromBody] TotpEnrollmentConfirmRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.ConfirmTotpEnrollmentAsync(id.Value, request));
        }

        [HttpPost("totp/recovery-codes/regenerate")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> RegenerateTotpRecoveryCodes([FromBody] TotpRecoveryCodesRegenerateRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.RegenerateTotpRecoveryCodesAsync(id.Value, request));
        }

        [HttpPost("totp/disable")]
        [Authorize]
        [EnableRateLimiting("auth-security-ip")]
        public async Task<IActionResult> DisableTotp([FromBody] TotpDisableRequest request)
        {
            var id = CurrentUserId();
            if (!id.HasValue) return Unauthorized();
            return Ok(await _authService.DisableTotpAsync(id.Value, request));
        }

        [AllowAnonymous]
        [HttpPost("external-login/exchange")]
        [EnableRateLimiting("auth-login-ip")]
        public async Task<IActionResult> ExchangeExternalLogin([FromBody] string code)
        {
            if (!HasTrustedBrowserOrigin(requireSource: true))
                return StatusCode(StatusCodes.Status403Forbidden,
                    new { isSuccess = false, message = ExternalLoginMessages.TrustedOriginRequired });

            var result = await _authService.ExchangeExternalLoginChallengeAsync(code);
            if (!result.IsSuccess)
                return Unauthorized(result);

            if (result.RequiresMfa && !string.IsNullOrWhiteSpace(result.MfaChallengeToken))
            {
                SetMfaChallengeCookie(result.MfaChallengeToken);
                result.MfaChallengeToken = null;
                return Ok(result);
            }

            if (string.IsNullOrWhiteSpace(result.RefreshToken))
                return Unauthorized(new { isSuccess = false, message = SessionMessages.SignInExchangeExpired });

            SetRefreshTokenCookie(result.RefreshToken);
            result.RefreshToken = string.Empty;
            return Ok(result);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            // Refresh authentication is exclusively cookie-based, so a trusted
            // Origin or Referer is mandatory; missing source headers must not bypass CSRF validation.
            if (!HasTrustedBrowserOrigin(requireSource: true))
                return StatusCode(StatusCodes.Status403Forbidden, new { isSuccess = false, message = ExternalLoginMessages.TrustedOriginRequired });

            var refreshToken = Request.Cookies[RefreshTokenCookieName];
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return Unauthorized(new { isSuccess = false, message = SessionMessages.RefreshTokenMissingSignIn });
            }

            var result = await _authService.RefreshAsync(refreshToken);
            if (result.response.IsSuccess && !string.IsNullOrWhiteSpace(result.refreshToken))
            {
                SetRefreshTokenCookie(result.refreshToken);
                return Ok(result.response);
            }

            // Do not expire the browser cookie on a failed rotation. Another tab may
            // already have rotated the shared cookie successfully; a late 401 response
            // must not delete that newer cookie. Invalid cookies are overwritten on the
            // next successful sign-in or removed by explicit logout.
            return Unauthorized(result.response);
        }

        [AllowAnonymous]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // Logout can be called with a bearer access token alone by non-browser
            // clients. When the ambient refresh cookie is present, require a trusted
            // Origin or Referer before revoking the cookie-backed session.
            var hasRefreshCookie = !string.IsNullOrWhiteSpace(Request.Cookies[RefreshTokenCookieName]);
            if (!HasTrustedBrowserOrigin(requireSource: hasRefreshCookie))
                return StatusCode(StatusCodes.Status403Forbidden, new { message = ExternalLoginMessages.TrustedOriginRequired });

            // Revoke the session identified by the current access token as well as
            // the refresh-cookie session. This covers browsers where the refresh cookie
            // is missing or stale while a still-valid access token identifies the session.
            var userId = CurrentUserId();
            var sessionId = CurrentSessionId();
            if (userId.HasValue && sessionId.HasValue)
                await _userSessionService.RevokeSessionAsync(userId.Value, sessionId.Value);

            var refreshToken = Request.Cookies[RefreshTokenCookieName];
            if (!string.IsNullOrWhiteSpace(refreshToken))
                await _userSessionService.RevokeAsync(refreshToken);

            // Always clear the cookie, even when the access token/session has already expired.
            ClearRefreshTokenCookie();
            ClearMfaChallengeCookie();
            return Ok(ExternalLoginMessages.LogoutSuccess);
        }


    }
}