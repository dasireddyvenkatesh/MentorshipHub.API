using MentorshipHub.API.Application.Classes.Auth;
using MentorshipHub.API.Application.Classes.Common;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Commom;
using MentorshipHub.API.Application.Interfaces.Contact;
//using MentorshipHub.API.Application.Interfaces.Dashboard;
using MentorshipHub.API.Application.Interfaces.Email;
using MentorshipHub.API.Application.Services.Auth;
using MentorshipHub.API.Application.Services.Contact;
//using MentorshipHub.API.Application.Services.Dashboard;
using MentorshipHub.API.Application.Services.Email;
using MentorshipHub.API.Enities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Keep the Data Protection key ring available only for reading secrets encrypted
// by the previous TOTP implementation. New TOTP secrets use AES-256-GCM with keys
// supplied through Totp:ActiveKeyVersion and Totp:EncryptionKeys:{version}.
var dataProtectionBuilder = builder.Services.AddDataProtection()
    .SetApplicationName("XQARE.MentorshipHub.API");

var appServiceHome = Environment.GetEnvironmentVariable("HOME");
if (!string.IsNullOrWhiteSpace(appServiceHome))
{
    var keyRingDirectory = new DirectoryInfo(
        Path.Combine(appServiceHome, "ASP.NET", "DataProtection-Keys"));
    Directory.CreateDirectory(keyRingDirectory.FullName);
    dataProtectionBuilder.PersistKeysToFileSystem(keyRingDirectory);
}

 // Optional compatibility path: if the old Data Protection key ring was protected
 // with a certificate, retain that certificate setting so legacy TOTP ciphertext
 // can still be decrypted. New TOTP secrets use AES-GCM and do not require this.
var legacyDataProtectionThumbprint = builder.Configuration["DataProtection:CertificateThumbprint"];
if (!string.IsNullOrWhiteSpace(legacyDataProtectionThumbprint))
{
    using var certificateStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    certificateStore.Open(OpenFlags.ReadOnly);
    var legacyCertificate = certificateStore.Certificates
        .Find(
            X509FindType.FindByThumbprint,
            legacyDataProtectionThumbprint.Replace(" ", string.Empty, StringComparison.Ordinal),
            validOnly: false)
        .OfType<X509Certificate2>()
        .FirstOrDefault();

    if (legacyCertificate == null || !legacyCertificate.HasPrivateKey)
    {
        throw new InvalidOperationException(
            "The configured legacy Data Protection certificate was not found with a private key.");
    }

    dataProtectionBuilder.ProtectKeysWithCertificate(legacyCertificate);
}

// Add services to the container.

builder.Services.AddDbContext<AppDbContext>(options =>
    
options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

//builder.Services.AddDbContext<AppDbContext>(options =>
//    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

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
            var sessionValue = principal?.FindFirst("sid")?.Value;

            // Legacy access tokens without sid are allowed to expire naturally.
            // Newly issued tokens always carry sid and are checked against UserSessions.
            if (string.IsNullOrWhiteSpace(sessionValue))
                return;

            if (!Guid.TryParse(sessionValue, out var sessionId) ||
                !Guid.TryParse(principal?.FindFirst("uid")?.Value, out var userId))
            {
                context.Fail("The access token session is invalid.");
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

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowUI", policy =>
    {
        policy.WithOrigins(
                "https://localhost:7161",
                "https://sandbox.xqare.in",
                "https://www.sandbox.xqare.in")
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
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IPublicIdService, SqidsService>();
builder.Services.AddScoped<IOAuthUserMapper, OAuthUserMapper>();
builder.Services.AddScoped<IContactService, ContactService>();
//builder.Services.AddScoped<IGetDashboardService, GetDashboardService>();
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

builder.Services.AddControllers();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseForwardedHeaders();
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
