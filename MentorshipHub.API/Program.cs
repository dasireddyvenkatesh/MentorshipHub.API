using FluentValidation;
using MentorshipHub.API.Application.Classes.Auth;
using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.DTO.ContactUs;
using MentorshipHub.API.Application.DTO.Profile;
using MentorshipHub.API.Application.Validators;
using MentorshipHub.API.Presentation.Filters;
using MentorshipHub.API.Presentation.ExceptionHandling;
using MentorshipHub.API.Application.Classes.Common;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Commom;
using MentorshipHub.API.Application.Interfaces.Contact;
using MentorshipHub.API.Application.Interfaces.Profile;
using MentorshipHub.API.Application.Interfaces.Email;
using MentorshipHub.API.Application.Services.Auth;
using MentorshipHub.API.Application.Services.Contact;
using MentorshipHub.API.Application.Services.Profile;
using MentorshipHub.API.Application.Services.Email;
using MentorshipHub.API.Enities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

// Process only the proxy headers needed for the original client address and scheme.
// ASP.NET Core's hosting integration supplies the trusted local proxy configuration;
// do not clear KnownProxies/KnownNetworks or trust arbitrary forwarded headers.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;

    // Azure App Service forwards the original client IP through its private
    // platform networks. Trust only these documented private ranges, never
    // arbitrary X-Forwarded-For senders.
    options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("10.0.0.0/8"));
    options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("192.168.0.0/16"));
    options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("172.16.0.0/12"));
});

// ASP.NET Core Data Protection remains enabled for OAuth authentication cookies.
// TOTP secrets use only versioned AES-256-GCM keys from Totp:EncryptionKeys.
var dataProtectionBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("XQARE.MentorshipHub.API.v2");

var appServiceHome = Environment.GetEnvironmentVariable("HOME");
if (!string.IsNullOrWhiteSpace(appServiceHome))
{
    var keyRingDirectory = new DirectoryInfo(
        Path.Combine(appServiceHome, "ASP.NET", "DataProtection-Keys-v2"));
    Directory.CreateDirectory(keyRingDirectory.FullName);
    dataProtectionBuilder.PersistKeysToFileSystem(keyRingDirectory);
}

// Add services to the container.

builder.Services.AddDbContext<AppDbContext>(options =>
    
options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddCookie()
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],

        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
    };

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var principal = context.Principal;
            if (!Guid.TryParse(principal?.FindFirst("uid")?.Value, out var userId) ||
                !Guid.TryParse(principal?.FindFirst("sid")?.Value, out var sessionId))
            {
                context.Fail("The access token is missing a valid user or session identity.");
                return;
            }

            var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
            var now = DateTime.UtcNow;
            var active = await db.UserSessions.AsNoTracking().AnyAsync(x =>
                x.Id == sessionId &&
                x.UserId == userId &&
                !x.IsRevoked &&
                x.RevokedAt == null &&
                x.ExpiresAt > now,
                context.HttpContext.RequestAborted);

            if (!active)
                context.Fail("This login session is no longer active.");
        }
    };
})
.AddGoogle(options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ClientId = builder.Configuration["Google:ClientId"]!;
    options.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
    options.ClaimActions.MapJsonKey("picture", "picture", "url");
    options.ClaimActions.MapJsonKey("email_verified", "email_verified");
})
.AddGitHub(options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ClientId = builder.Configuration["GitHub:ClientId"]!;
    options.ClientSecret = builder.Configuration["GitHub:ClientSecret"]!;
    options.Scope.Add("user:email");
    options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
    options.ClaimActions.MapJsonKey("avatar_url", "avatar_url");

    // GitHub's profile endpoint does not reliably expose whether its email is verified.
    // Read the user's authorized email list and select a verified address explicitly.
    options.Events.OnCreatingTicket += async context =>
    {
        using var emailRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
        emailRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        emailRequest.Headers.UserAgent.ParseAdd("XQARE");
        emailRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

        using var emailResponse = await context.Backchannel.SendAsync(
            emailRequest, context.HttpContext.RequestAborted);
        emailResponse.EnsureSuccessStatusCode();

        await using var emailStream = await emailResponse.Content.ReadAsStreamAsync(
            context.HttpContext.RequestAborted);
        using var emailDocument = await JsonDocument.ParseAsync(
            emailStream, cancellationToken: context.HttpContext.RequestAborted);

        string? verifiedEmail = null;
        foreach (var item in emailDocument.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !item.TryGetProperty("verified", out var verified) ||
                verified.ValueKind != JsonValueKind.True ||
                !item.TryGetProperty("email", out var emailElement) ||
                string.IsNullOrWhiteSpace(emailElement.GetString()))
            {
                continue;
            }

            verifiedEmail = emailElement.GetString();
            if (item.TryGetProperty("primary", out var primary) &&
                primary.ValueKind == JsonValueKind.True)
            {
                break;
            }
        }

        if (!string.IsNullOrWhiteSpace(verifiedEmail) &&
            context.Principal?.Identity is ClaimsIdentity identity)
        {
            foreach (var existingEmailClaim in identity.FindAll(ClaimTypes.Email).ToList())
                identity.RemoveClaim(existingEmailClaim);

            identity.AddClaim(new Claim(ClaimTypes.Email, verifiedEmail));
            identity.AddClaim(new Claim("email_verified", "true"));
        }
    };

})
.AddTwitter(options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ConsumerKey = builder.Configuration["Twitter:ClientId"]!;
    options.ConsumerSecret = builder.Configuration["Twitter:ClientSecret"]!;
    options.RetrieveUserDetails = true;
    options.ClaimActions.MapJsonKey("urn:twitter:profile_image", "profile_image_url_https");
    options.ClaimActions.MapJsonKey("email_verified", "email_verified");

})
.AddLinkedIn(options =>
{
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ClientId = builder.Configuration["LinkedIn:ClientId"]!;
    options.ClientSecret = builder.Configuration["LinkedIn:ClientSecret"]!;
    options.ClaimActions.MapJsonKey("email_verified", "email_verified");

});

// Keep CORS and the cookie-authenticated Origin/CSRF check on the same
// environment-specific allow-list. Production App Service settings must override
// the sandbox defaults with the two production UI origins.
var trustedBrowserOrigins = builder.Configuration
    .GetSection("Security:TrustedBrowserOrigins")
    .Get<string[]>()?
    .Select(origin => origin.Trim())
    .Where(origin => !string.IsNullOrWhiteSpace(origin))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray() ?? Array.Empty<string>();

if (trustedBrowserOrigins.Length == 0)
{
    throw new InvalidOperationException(
        "Security:TrustedBrowserOrigins must contain at least one trusted UI origin.");
}

foreach (var origin in trustedBrowserOrigins)
{
    if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
        originUri.AbsolutePath != "/" ||
        !string.IsNullOrEmpty(originUri.Query) ||
        !string.IsNullOrEmpty(originUri.Fragment) ||
        !string.Equals(origin, originUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase) ||
        !string.Equals(originUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            $"Invalid trusted browser origin '{origin}'. Configure an HTTPS origin without a path, query, or fragment.");
    }
}

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowUI", policy =>
    {
        policy.WithOrigins(trustedBrowserOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();
builder.Services.AddSingleton<ITotpSecretProtector, TotpSecretProtector>();
builder.Services.AddScoped<ITotpService, TotpService>();
builder.Services.AddScoped<IUserSessionService, UserSessionService>();
builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IEmailTemplateService, EmailTemplateService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IProfileService, ProfileService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IPublicIdService, SqidsService>();
builder.Services.AddScoped<IOAuthUserMapper, OAuthUserMapper>();
builder.Services.AddScoped<IContactService, ContactService>();

// Enforce request validation at the API boundary. UI validation is only a convenience;
// every HTTP client receives the same server-side field checks.
builder.Services.AddScoped<FluentValidationActionFilter>();
builder.Services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();
builder.Services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddScoped<IValidator<ChangePasswordRequest>, ChangePasswordRequestValidator>();
builder.Services.AddScoped<IValidator<ResetPasswordRequest>, ResetPasswordRequestValidator>();
builder.Services.AddScoped<IValidator<ForgotPasswordRequest>, ForgotPasswordRequestValidator>();
builder.Services.AddScoped<IValidator<EmailOtpRequest>, EmailOtpRequestValidator>();
builder.Services.AddScoped<IValidator<VerifyEmailOtpRequest>, VerifyEmailOtpRequestValidator>();
builder.Services.AddScoped<IValidator<VerifyRegisterEmailOtpRequest>, VerifyRegisterEmailOtpRequestValidator>();
builder.Services.AddScoped<IValidator<VerifyMfaChallengeRequest>, VerifyMfaChallengeRequestValidator>();
builder.Services.AddScoped<IValidator<TotpEnrollmentStartRequest>, TotpEnrollmentStartRequestValidator>();
builder.Services.AddScoped<IValidator<TotpEnrollmentConfirmRequest>, TotpEnrollmentConfirmRequestValidator>();
builder.Services.AddScoped<IValidator<TotpDisableRequest>, TotpDisableRequestValidator>();
builder.Services.AddScoped<IValidator<TotpRecoveryCodesRegenerateRequest>, TotpRecoveryCodesRegenerateRequestValidator>();
builder.Services.AddScoped<IValidator<UpdateMyProfileRequest>, UpdateMyProfileRequestValidator>();
builder.Services.AddScoped<IValidator<ContactUsRequest>, ContactUsRequestValidator>();

builder.Services.AddHttpContextAccessor();

builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("otp-ip", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }));

    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { isSuccess = false, message = "Too many authentication requests from this network. Please try again later." },
            cancellationToken);
    };
});

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddControllers(options => options.Filters.AddService<FluentValidationActionFilter>());

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();
app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseCors("AllowUI");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
}

app.Run();
