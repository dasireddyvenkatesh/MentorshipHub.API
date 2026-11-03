using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.DTO.Common;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Email;
using MentorshipHub.API.Application.Interfaces.Commom;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using MentorshipHub.API.Infrastructure.EntityModels.Profile;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _db;
        private readonly IJwtTokenService _jwt;
        private readonly IPasswordHasher _hasher;
        private readonly IUserSessionService _sessions;
        private readonly IOtpService _otp;
        private readonly IPublicIdService _publicIdService;
        private readonly IEmailService _emailService;
        private readonly IEmailTemplateService _emailTemplateService;
        private readonly IConfiguration _configuration;
        private readonly ITotpService _totp;

        public AuthService(AppDbContext db, IJwtTokenService jwt, IPasswordHasher hasher,
                            IUserSessionService sessions, IOtpService otp, IPublicIdService publicIdService,
                            IEmailService emailService, IEmailTemplateService emailTemplateService,
                            IConfiguration configuration, ITotpService totp)
        {
            _db = db;
            _jwt = jwt;
            _hasher = hasher;
            _sessions = sessions;
            _otp = otp;
            _publicIdService = publicIdService;
            _emailService = emailService;
            _emailTemplateService = emailTemplateService;
            _configuration = configuration;
            _totp = totp;
        }

        private const string PasswordResetGenericMessage =
            "If an account with that email exists, we'll send a password reset link shortly.";

        public async Task<ResponseDTO> RequestPasswordResetAsync(ForgotPasswordRequest request)
        {
            var email = request?.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
            {
                // Keep the same outward response for malformed, unknown and known addresses.
                return new ResponseDTO { IsSuccess = true, Message = PasswordResetGenericMessage };
            }

            string? rawToken = null;
            PasswordResetToken? resetToken = null;
            User? user = null;

            await using (var transaction = await _db.Database.BeginTransactionAsync())
            {
                // Serialize concurrent reset requests for the same email address.
                await _db.Database.ExecuteSqlInterpolatedAsync(
                    $"SELECT pg_advisory_xact_lock(hashtext({email}))");

                user = await _db.Users.FirstOrDefaultAsync(x =>
                    x.Email.ToLower() == email && x.IsActive && x.IsEmailConfirmed);

                if (user == null)
                {
                    await transaction.CommitAsync();
                    return new ResponseDTO { IsSuccess = true, Message = PasswordResetGenericMessage };
                }

                var now = DateTime.UtcNow;
                var recentRequests = await _db.PasswordResetTokens.CountAsync(x =>
                    x.UserId == user.Id && x.CreatedAt >= now.AddHours(-1));

                // Three reset emails per account in a rolling hour.
                if (recentRequests >= 3)
                {
                    await transaction.CommitAsync();
                    return new ResponseDTO { IsSuccess = true, Message = PasswordResetGenericMessage };
                }

                var outstandingTokens = await _db.PasswordResetTokens
                    .Where(x => x.UserId == user.Id && !x.Used)
                    .ToListAsync();

                foreach (var outstandingToken in outstandingTokens)
                    outstandingToken.Used = true;

                rawToken = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
                var tokenHash = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

                resetToken = new PasswordResetToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    TokenHash = tokenHash,
                    ExpiresAt = now.AddMinutes(15),
                    Used = false,
                    CreatedAt = now
                };

                await _db.PasswordResetTokens.AddAsync(resetToken);
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
            }

            try
            {
                var resetPageUrl = _configuration["Frontend:PasswordResetUrl"];
                if (!Uri.TryCreate(resetPageUrl, UriKind.Absolute, out var resetUri) ||
                    resetUri.Scheme != Uri.UriSchemeHttps &&
                    !_configuration.GetValue<bool>("Frontend:AllowInsecurePasswordResetUrl"))
                {
                    // Never construct a reset link from an untrusted Host header.
                    await InvalidatePasswordResetTokenAsync(resetToken!.Id);
                    return new ResponseDTO { IsSuccess = true, Message = PasswordResetGenericMessage };
                }

                var resetUrl = QueryHelpers.AddQueryString(resetUri.ToString(), "token", rawToken!);
                var template = _emailTemplateService.BuildPasswordReset(user!.Username, resetUrl);
                var sent = await _emailService.SendEmail(user.Email, template.subject, template.body);

                if (!sent)
                    await InvalidatePasswordResetTokenAsync(resetToken!.Id);
            }
            catch
            {
                if (resetToken != null)
                    await InvalidatePasswordResetTokenAsync(resetToken.Id);
            }

            return new ResponseDTO { IsSuccess = true, Message = PasswordResetGenericMessage };
        }

        public async Task<ResponseDTO> ChangePasswordAsync(Guid userId, Guid currentSessionId, ChangePasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.CurrentPassword))
                return new ResponseDTO { IsSuccess = false, Message = "Enter your current password." };

            var passwordValidation = ValidateRegistrationPassword(request.NewPassword, request.ConfirmPassword);
            if (passwordValidation != null)
                return new ResponseDTO { IsSuccess = false, Message = passwordValidation };

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == userId && x.IsActive);
            if (user == null)
                return new ResponseDTO { IsSuccess = false, Message = "The account could not be verified." };

            // External-provider-only accounts must use the account recovery flow to establish
            // local password sign-in. This endpoint never silently creates a password.
            if (string.IsNullOrWhiteSpace(user.PasswordHash))
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = "Password sign-in is not enabled for this account. Use the password recovery process to establish a password."
                };

            if (!_hasher.Verify(user.PasswordHash, request.CurrentPassword))
                return new ResponseDTO { IsSuccess = false, Message = "Your current password is incorrect." };

            if (_hasher.Verify(user.PasswordHash, request.NewPassword!))
                return new ResponseDTO { IsSuccess = false, Message = "Choose a new password that is different from your current password." };

            await using var transaction = await _db.Database.BeginTransactionAsync();
            user.PasswordHash = _hasher.Hash(request.NewPassword!);

            // Keep this authenticated device signed in; revoke every other active device.
            await _sessions.RevokeOtherSessionsAsync(userId, currentSessionId);

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return new ResponseDTO
            {
                IsSuccess = true,
                Message = "Your password has been changed. Other active sessions have been signed out."
            };
        }

        public async Task<ResponseDTO> ResetPasswordAsync(ResetPasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Token))
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = "This password reset link is invalid or has expired. Request a new one."
                };

            var passwordValidation = ValidateRegistrationPassword(request.Password, request.ConfirmPassword);
            if (passwordValidation != null)
                return new ResponseDTO { IsSuccess = false, Message = passwordValidation };

            var tokenHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(request.Token.Trim())));
            var now = DateTime.UtcNow;

            await using var transaction = await _db.Database.BeginTransactionAsync();

            // FOR UPDATE ensures simultaneous submissions cannot consume one token twice.
            var resetToken = await _db.PasswordResetTokens
                .FromSqlInterpolated($@"SELECT * FROM ""PasswordResetTokens"" WHERE ""TokenHash"" = {tokenHash} FOR UPDATE")
                .FirstOrDefaultAsync();

            if (resetToken == null || resetToken.Used || resetToken.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = "This password reset link is invalid or has expired. Request a new one."
                };
            }

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == resetToken.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed)
            {
                await transaction.RollbackAsync();
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = "This password reset link is invalid or has expired. Request a new one."
                };
            }

            resetToken.Used = true;
            user.PasswordHash = _hasher.Hash(request.Password!);

            // Invalidate every other outstanding reset link for this account.
            var otherTokens = await _db.PasswordResetTokens
                .Where(x => x.UserId == user.Id && x.Id != resetToken.Id && !x.Used)
                .ToListAsync();
            foreach (var otherToken in otherTokens)
                otherToken.Used = true;

            // Revoke every active refresh-token session after a password change.
            await _db.UserSessions
                .Where(x => x.UserId == user.Id && !x.IsRevoked)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(x => x.IsRevoked, true)
                    .SetProperty(x => x.RevokedAt, now)
                    .SetProperty(x => x.LastActivityAt, now));

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return new ResponseDTO
            {
                IsSuccess = true,
                Message = "Your password has been reset successfully. Please sign in again."
            };
        }

        private async Task InvalidatePasswordResetTokenAsync(Guid tokenId)
        {
            try
            {
                var token = await _db.PasswordResetTokens.FirstOrDefaultAsync(x => x.Id == tokenId);
                if (token != null && !token.Used)
                {
                    token.Used = true;
                    await _db.SaveChangesAsync();
                }
            }
            catch
            {
                // The outward forgot-password response remains generic.
            }
        }

        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
                return new LoginResponse { IsSuccess = false, Message = "Email and password are required." };

            var email = request.Email.Trim().ToLowerInvariant();

            var passwordValidation = await ValidatePasswordWithLockoutAsync(email, request.Password);
            var user = passwordValidation.User;
            if (!passwordValidation.IsValid || user == null)
                return new LoginResponse { IsSuccess = false, Message = "Invalid email or password." };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = "Account is inactive." };

            var relatedRecordsError = await EnsureUserRelatedRecordsAsync(user);
            if (relatedRecordsError != null)
                return new LoginResponse { IsSuccess = false, Message = relatedRecordsError };

            // Pending registrations must be completed through Register so the person
            // proving mailbox ownership can choose the final password. Do not let the
            // login OTP endpoint confirm an account created by an unverified registrant.
            if (!user.IsEmailConfirmed)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    RequiresEmailVerification = false,
                    Email = user.Email,
                    Message = "Your registration is not complete. Choose Create one free to verify your email and set your password."
                };
            }

            if (user.SecuritySetting?.MfaEnabled == true)
                return await CreateMfaChallengeAsync(user, new LoginRequest { DeviceId = request.DeviceId, DeviceName = request.DeviceName });

            return await CreateSession(user, request);
        }


        private async Task<(User? User, bool IsValid)> ValidatePasswordWithLockoutAsync(string email, string password)
        {
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var lockKey = "login:" + email;
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            // Unknown addresses remain indistinguishable from invalid passwords.
            // The existing IP rate limiter remains the coarse control for unknown accounts.
            if (user == null || string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                await transaction.CommitAsync();
                return (null, false);
            }

            var security = user.SecuritySetting;
            if (security == null)
            {
                security = new UserSecuritySetting { UserId = user.Id, MfaEnabled = false };
                _db.UserSecuritySettings.Add(security);
                user.SecuritySetting = security;
            }

            var now = DateTime.UtcNow;
            if (security.LockoutEnd.HasValue && security.LockoutEnd.Value > now)
            {
                await transaction.CommitAsync();
                return (null, false);
            }

            if (!_hasher.Verify(user.PasswordHash, password))
            {
                if (!security.FailedLoginWindowStartedAt.HasValue ||
                    security.FailedLoginWindowStartedAt.Value.AddMinutes(15) <= now)
                {
                    security.FailedLoginWindowStartedAt = now;
                    security.AccessFailedCount = 0;
                }

                security.AccessFailedCount++;
                if (security.AccessFailedCount >= 5)
                {
                    security.LockoutLevel = Math.Min(3, security.LockoutLevel + 1);
                    var lockoutMinutes = security.LockoutLevel switch
                    {
                        1 => 15,
                        2 => 30,
                        _ => 60
                    };
                    security.LockoutEnd = now.AddMinutes(lockoutMinutes);
                    security.AccessFailedCount = 0;
                    security.FailedLoginWindowStartedAt = now;
                }

                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return (null, false);
            }

            // A successful primary factor resets consecutive password failures.
            security.AccessFailedCount = 0;
            security.LockoutEnd = null;
            security.FailedLoginWindowStartedAt = null;
            security.LockoutLevel = 0;
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return (user, true);
        }

        public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            var validationMessage = ValidateRegistrationRequest(request);
            if (validationMessage != null)
                return new RegisterResponse { IsSuccess = false, Message = validationMessage };

            request.FullName = request.FullName.Trim();
            var email = request.Email.Trim().ToLowerInvariant();

            // Match historical email casing as well as newly normalized addresses.
            var existingUser = await _db.Users
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (existingUser != null)
                return await ContinueExistingRegistrationAsync(existingUser);

            // Do not create accounts without the required default role.
            var memberRole = await _db.Roles.FirstOrDefaultAsync(x => x.Code == "MEMBER");
            if (memberRole == null)
            {
                return new RegisterResponse
                {
                    IsSuccess = false,
                    Message = "The default Member role is not configured. Please contact support."
                };
            }

            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = request.FullName,
                Email = email,
                // Do not store a usable password until the mailbox owner completes OTP verification.
                PasswordHash = null,
                IsEmailConfirmed = false,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
            };

            await _db.Users.AddAsync(user);
            await _db.UserProfiles.AddAsync(new UserProfile
            {
                UserId = user.Id,
                FirstName = string.Empty,
                LastName = string.Empty,
            });
            await _db.UserSecuritySettings.AddAsync(new UserSecuritySetting
            {
                UserId = user.Id,
                MfaEnabled = false
            });
            await _db.UserRoles.AddAsync(new UserRole
            {
                UserId = user.Id,
                RoleId = memberRole.Id
            });

            try
            {
                // SaveChanges wraps these inserts in one transaction.
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
            {
                // A concurrent request may have registered this email after the first lookup.
                _db.ChangeTracker.Clear();
                var racedUser = await _db.Users
                    .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

                if (racedUser == null)
                    throw;

                return await ContinueExistingRegistrationAsync(racedUser);
            }

            var response = await _otp.GenerateEmailVerificationOtp(user.Username, user.Email);
            return new RegisterResponse
            {
                IsSuccess = response.IsSuccess,
                Email = user.Email,
                Message = response.Message,
                RequiresEmailVerification = true
            };
        }

                public async Task<LoginResponse> ExternalLoginAsync(ExternalLoginRequest request)
        {
            if (request == null ||
                string.IsNullOrWhiteSpace(request.Provider) ||
                string.IsNullOrWhiteSpace(request.ProviderId))
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "The external identity provider did not return a valid account identifier."
                };
            }

            // An already-linked provider identity is sufficient to locate its XQARE account.
            // This preserves existing social sign-ins even if the provider no longer returns email.
            var externalLogin = await _db.ExternalLogins
                .Include(x => x.User)
                .ThenInclude(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x =>
                    x.Provider == request.Provider &&
                    x.ProviderUserId == request.ProviderId);

            User user;
            if (externalLogin != null)
            {
                user = externalLogin.User;
            }
            else
            {
                var email = request.Email?.Trim().ToLowerInvariant() ?? string.Empty;
                if (!request.EmailVerified ||
                    string.IsNullOrWhiteSpace(email) ||
                    !new EmailAddressAttribute().IsValid(email))
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Message = "This provider did not supply a verified email address. Use email registration or an already-linked provider."
                    };
                }

                // Never silently attach an unlinked social identity to an existing account.
                // A separate flow must first authenticate the existing account before linking.
                var existingUser = await _db.Users
                    .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

                if (existingUser != null)
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Email = existingUser.Email,
                        Message = "An account already exists with this email. Sign in using your existing method before linking another provider."
                    };
                }

                var memberRole = await _db.Roles.FirstOrDefaultAsync(x => x.Code == "MEMBER");
                if (memberRole == null)
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Message = "The default Member role is not configured. Please contact support."
                    };
                }

                // Create the account and provider link in one transaction. This prevents
                // a confirmed-but-unlinked orphan account if the provider link cannot be saved.
                await using var transaction = await _db.Database.BeginTransactionAsync();
                try
                {
                    var externalRequest = new ExternalLoginRequest
                    {
                        Provider = request.Provider,
                        ProviderId = request.ProviderId,
                        Email = email,
                        EmailVerified = true,
                        Name = string.IsNullOrWhiteSpace(request.Name)
                            ? email.Split('@')[0]
                            : request.Name.Trim(),
                        Avatar = request.Avatar,
                        DeviceId = request.DeviceId,
                        DeviceName = request.DeviceName
                    };

                    user = await CreateNewUserAsync(externalRequest, email, memberRole);

                    await _db.ExternalLogins.AddAsync(new ExternalLogin
                    {
                        Id = Guid.NewGuid(),
                        UserId = user.Id,
                        Provider = request.Provider,
                        ProviderUserId = request.ProviderId,
                        CreatedAt = DateTime.UtcNow
                    });

                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();
                }
                catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
                {
                    await transaction.RollbackAsync();
                    _db.ChangeTracker.Clear();

                    // If another callback linked this exact provider identity first,
                    // continue with that account. Never link by email as a fallback.
                    externalLogin = await _db.ExternalLogins
                        .Include(x => x.User)
                        .ThenInclude(x => x.SecuritySetting)
                        .FirstOrDefaultAsync(x =>
                            x.Provider == request.Provider &&
                            x.ProviderUserId == request.ProviderId);

                    if (externalLogin != null)
                    {
                        user = externalLogin.User;
                    }
                    else
                    {
                        var emailOwner = await _db.Users
                            .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

                        if (emailOwner != null)
                        {
                            return new LoginResponse
                            {
                                IsSuccess = false,
                                Email = emailOwner.Email,
                                Message = "An account already exists with this email. Sign in using your existing method before linking another provider."
                            };
                        }

                        throw;
                    }
                }
            }

            if (!user.IsActive)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "Account is inactive."
                };
            }

            // Older provider links may have been created before verified-email checks existed.
            // Do not let those legacy links bypass registration email verification.
            if (!user.IsEmailConfirmed)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "This account's email is not verified. Complete registration from the Register page first."
                };
            }

            var relatedRecordsError = await EnsureUserRelatedRecordsAsync(user);
            if (relatedRecordsError != null)
                return new LoginResponse { IsSuccess = false, Message = relatedRecordsError };

            var loginRequest = new LoginRequest { DeviceId = request.DeviceId, DeviceName = request.DeviceName };
            if (user.SecuritySetting?.MfaEnabled == true)
                return await CreateMfaChallengeAsync(user, loginRequest);
            return await CreateSession(user, loginRequest);
        }

        public async Task<EmailOtpResponse> ResendEmailOtp(EmailOtpRequest request)
        {
            var email = request?.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email))
                return new EmailOtpResponse { IsSuccess = false, Message = "Enter a valid email address." };

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (user == null)
            {
                return new EmailOtpResponse
                {
                    IsSuccess = true,
                    Message = "If the account exists, a verification code has been sent."
                };
            }

            var response = await _otp.GenerateEmailVerificationOtp(user.Username, user.Email, true);

            return response;

        }

        private async Task<LoginResponse> CreateMfaChallengeAsync(User user, LoginRequest loginRequest)
        {
            if (!await _totp.IsEnabledAsync(user.Id))
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "Authenticator setup is required for this account. Use the account recovery process before signing in."
                };
            }

            var token = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = user.Id,
                TokenHash = hash,
                Purpose = "totp",
                DeviceId = loginRequest.DeviceId,
                DeviceName = loginRequest.DeviceName,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                AttemptCount = 0
            });
            await _db.SaveChangesAsync();

            return new LoginResponse
            {
                IsSuccess = true,
                RequiresMfa = true,
                MfaChallengeToken = token,
                UserId = user.Id,
                Email = user.Email,
                Message = "Enter the six-digit code from your authenticator app."
            };
        }

        public async Task<LoginResponse> VerifyMfaChallengeAsync(VerifyMfaChallengeRequest request, string challengeToken)
        {
            if (request == null || string.IsNullOrWhiteSpace(challengeToken) || string.IsNullOrWhiteSpace(request.Code))
                return new LoginResponse { IsSuccess = false, Message = "The MFA verification request is invalid." };
            var factor = (request.Factor ?? "auto").Trim().ToLowerInvariant();
            if (factor != "auto" && factor != "totp" && factor != "recovery")
                return new LoginResponse { IsSuccess = false, Message = "Unsupported MFA verification method." };

            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(challengeToken)));
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var challenge = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges"" WHERE ""TokenHash"" = {hash} FOR UPDATE")
                .FirstOrDefaultAsync();
            var now = DateTime.UtcNow;
            if (challenge == null || challenge.ConsumedAt != null || challenge.ExpiresAt <= now || challenge.AttemptCount >= 5)
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = "The MFA challenge has expired or is no longer valid. Please sign in again." };
            }

            if (!string.Equals(challenge.Purpose, "totp", StringComparison.Ordinal))
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = "This authenticator challenge is no longer supported. Sign in again." };
            }

            var user = await _db.Users.Include(x => x.SecuritySetting).FirstOrDefaultAsync(x => x.Id == challenge.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed || user.SecuritySetting?.MfaEnabled != true)
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = "The MFA challenge is no longer valid." };
            }

            var valid = false;
            var failure = "The verification code is invalid.";
            if (challenge.Purpose == "totp" && (factor == "auto" || factor == "totp"))
            {
                var result = await _totp.VerifyCodeAndConsumeAsync(user.Id, request.Code);
                valid = result.IsValid;
                failure = result.Message;
            }
            else if (challenge.Purpose == "totp" && factor == "recovery")
            {
                valid = await _totp.ConsumeRecoveryCodeAsync(user.Id, request.Code);
                failure = "The recovery code is invalid or has already been used.";
            }
            if (!valid)
            {
                challenge.AttemptCount++;
                if (challenge.AttemptCount >= 5) challenge.ConsumedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = challenge.ConsumedAt.HasValue ? "Too many incorrect verification attempts. Sign in again to restart." : failure
                };
            }

            challenge.ConsumedAt = now;
            var loginRequest = new LoginRequest { DeviceId = challenge.DeviceId ?? string.Empty, DeviceName = challenge.DeviceName };
            var response = await CreateSession(user, loginRequest);
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return response;
        }

        public async Task<TotpEnrollmentStartResponse> StartTotpEnrollmentAsync(Guid userId, TotpEnrollmentStartRequest request)
        {
            var user = await _db.Users.FindAsync(userId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed)
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = "The account is not eligible for authenticator setup." };
            if (string.IsNullOrWhiteSpace(user.PasswordHash) || !_hasher.Verify(user.PasswordHash, request.CurrentPassword ?? string.Empty))
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = "Confirm your current account password before setting up an authenticator." };
            var enabled = await _totp.IsEnabledAsync(userId);
            if (enabled)
            {
                var current = await _totp.VerifyCodeAndConsumeAsync(userId, request.CurrentTotpCode ?? string.Empty);
                if (!current.IsValid)
                    return new TotpEnrollmentStartResponse { IsSuccess = false, Message = "Enter a valid current authenticator code before replacing it." };
            }
            return await _totp.StartEnrollmentAsync(userId, user.Email, allowReplace: enabled);
        }

        public Task<TotpEnrollmentConfirmResponse> ConfirmTotpEnrollmentAsync(Guid userId, TotpEnrollmentConfirmRequest request)
            => _totp.ConfirmEnrollmentAsync(userId, request.Code);
        public Task<TotpStatusResponse> GetTotpStatusAsync(Guid userId) => _totp.GetStatusAsync(userId);
        public Task<TotpEnrollmentConfirmResponse> RegenerateTotpRecoveryCodesAsync(Guid userId, TotpRecoveryCodesRegenerateRequest request)
            => _totp.RegenerateRecoveryCodesAsync(userId, request.Code);

        public async Task<ResponseDTO> DisableTotpAsync(Guid userId, TotpDisableRequest request)
        {
            var user = await _db.Users.FindAsync(userId);
            if (user == null || string.IsNullOrWhiteSpace(user.PasswordHash) || !_hasher.Verify(user.PasswordHash, request.CurrentPassword ?? string.Empty))
                return new ResponseDTO { IsSuccess = false, Message = "Current password is incorrect." };
            var verification = await _totp.VerifyCodeAndConsumeAsync(userId, request.Code);
            if (!verification.IsValid) return new ResponseDTO { IsSuccess = false, Message = verification.Message };
            await _totp.DisableAsync(userId);
            return new ResponseDTO { IsSuccess = true, Message = "Authenticator disabled successfully." };
        }

        public async Task<LoginResponse> VerifyRegisterEmailOtp(VerifyEmailOtpRequest request)
        {
            if (request == null)
                return new LoginResponse { IsSuccess = false, Message = "Registration verification details are required." };

            var email = request.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(request.OtpCode))
                return new LoginResponse { IsSuccess = false, Message = "Email and verification code are required." };

            var passwordValidation = ValidateRegistrationPassword(request.Password, request.ConfirmPassword);
            if (passwordValidation != null)
                return new LoginResponse { IsSuccess = false, Message = passwordValidation };

            // Serialize OTP consumption and OTP regeneration for this email.
            // GenerateEmailVerificationOtp uses the same PostgreSQL advisory lock.
            await using var transaction = await _db.Database.BeginTransactionAsync();
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({email}))");

            var now = DateTime.UtcNow;
            var otp = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (otp == null)
                return new LoginResponse { IsSuccess = false, Message = "OTP not found. Request a new verification code." };

            if (otp.IsUsed)
                return new LoginResponse { IsSuccess = false, Message = "This OTP has already been used. Request a new verification code." };

            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil.Value > now)
                {
                    var remainingMinutes = Math.Ceiling((otp.LockedUntil.Value - now).TotalMinutes);
                    return new LoginResponse { IsSuccess = false, Message = $"Too many incorrect attempts. Try again in {remainingMinutes} minutes." };
                }

                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt <= now)
                return new LoginResponse { IsSuccess = false, Message = "OTP expired. Request a new verification code." };

            if (!_hasher.Verify(otp.CodeHash, request.OtpCode))
            {
                otp.AttemptCount++;
                var remainingAttempts = Math.Max(0, otp.MaxAttempts - otp.AttemptCount);

                if (otp.AttemptCount >= otp.MaxAttempts)
                {
                    otp.LockedUntil = now.AddHours(24);
                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();
                    return new LoginResponse { IsSuccess = false, Message = "Too many incorrect attempts. Try again in 24 hours." };
                }

                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new LoginResponse { IsSuccess = false, Message = $"Invalid OTP. {remainingAttempts} attempt(s) remaining." };
            }

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (user == null)
                return new LoginResponse { IsSuccess = false, Message = "User not found." };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = "Account is inactive." };

            if (user.IsEmailConfirmed)
                return new LoginResponse { IsSuccess = false, Message = "Email is already verified. Please sign in." };

            // The person proving control of the mailbox chooses the final password.
            // This replaces any password stored by an earlier unverified registration attempt.
            user.PasswordHash = _hasher.Hash(request.Password!);
            user.IsEmailConfirmed = true;
            otp.IsUsed = true;

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                return await CreateMfaChallengeAsync(user, new LoginRequest
                {
                    DeviceId = request.DeviceId ?? string.Empty,
                    DeviceName = request.DeviceName
                });
            }

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId ?? string.Empty,
                DeviceName = request.DeviceName
            };

            var sessionResponse = await CreateSession(user, loginRequest);
            sessionResponse.Message = "Email verified successfully. " + sessionResponse.Message;
            return sessionResponse;
        }

        public async Task<LoginResponse> VerifyEmailOtp(VerifyEmailOtpRequest request)
        {
            var email = request.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(request.OtpCode))
                return new LoginResponse { IsSuccess = false, Message = "Email and verification code are required." };

            var now = DateTime.UtcNow;
            var otp = await _db.EmailVerificationOtps.FirstOrDefaultAsync(x => x.Email == email);

            if (otp == null)
                return new LoginResponse { IsSuccess = false, Message = "OTP not found." };

            if (otp.IsUsed)
                return new LoginResponse { IsSuccess = false, Message = "This OTP has already been used. Request a new verification code." };

            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil.Value > now)
                {
                    var remainingMinutes = Math.Ceiling((otp.LockedUntil.Value - now).TotalMinutes);
                    return new LoginResponse { IsSuccess = false, Message = $"Too many incorrect attempts. Try again in {remainingMinutes} minutes." };
                }

                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt <= now)
                return new LoginResponse { IsSuccess = false, Message = "OTP expired. Request a new verification code." };

            if (!_hasher.Verify(otp.CodeHash, request.OtpCode))
            {
                otp.AttemptCount++;
                var remainingAttempts = Math.Max(0, otp.MaxAttempts - otp.AttemptCount);

                if (otp.AttemptCount >= otp.MaxAttempts)
                {
                    otp.LockedUntil = now.AddHours(24);
                    await _db.SaveChangesAsync();
                    return new LoginResponse { IsSuccess = false, Message = "Too many incorrect attempts. Try again in 24 hours." };
                }

                await _db.SaveChangesAsync();
                return new LoginResponse { IsSuccess = false, Message = $"Invalid OTP. {remainingAttempts} attempt(s) remaining." };
            }

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email == email);

            if (user == null)
                return new LoginResponse { IsSuccess = false, Message = "User not found." };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = "Account is inactive." };

            if (!user.IsEmailConfirmed)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "This account is still awaiting registration. Complete verification from the Register page to set your password."
                };
            }

            otp.IsUsed = true;
            user.IsEmailConfirmed = true;
            await _db.SaveChangesAsync();

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                return await CreateMfaChallengeAsync(user, new LoginRequest
                {
                    DeviceId = request.DeviceId ?? string.Empty,
                    DeviceName = request.DeviceName
                });
            }

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId ?? string.Empty,
                DeviceName = request.DeviceName
            };

            return await CreateSession(user, loginRequest);
        }

        public async Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return (new RefreshTokenResponse { IsSuccess = false, Message = "Refresh token missing" }, default!);

            var session = await _sessions.GetByTokenAsync(refreshToken);
            var now = DateTime.UtcNow;

            if (session == null || session.IsRevoked || session.ExpiresAt <= now)
                return (new RefreshTokenResponse { IsSuccess = false, Message = "Login expired. Please sign in again." }, default!);

            // Enforce a maximum session lifetime in addition to the sliding seven-day window.
            if (session.CreatedAt.AddDays(30) <= now)
            {
                session.IsRevoked = true;
                session.RevokedAt = now;
                await _db.SaveChangesAsync();
                return (new RefreshTokenResponse { IsSuccess = false, Message = "Maximum session age reached. Please sign in again." }, default!);
            }

            var user = await _db.Users.FindAsync(session.UserId);

            if (user == null || !user.IsActive)
                return (new RefreshTokenResponse { IsSuccess = false, Message = "Account is inactive. Please sign in again." }, default!);

            var roles = await GetRoles(user.Id);
            var permissions = await GetPermissions(user.Id);

            var newRefresh = _jwt.GenerateRefreshToken();

            await _sessions.RotateAsync(session, newRefresh);

            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions, session.Id);

            var response = new RefreshTokenResponse
            {
                AccessToken = accessToken,
                IsSuccess = true,
                Message = "Refresh Token Updated"
            };

            return (response, newRefresh);
        }

        private async Task<RegisterResponse> ContinueExistingRegistrationAsync(User existingUser)
        {
            if (existingUser.IsEmailConfirmed)
            {
                return new RegisterResponse
                {
                    IsSuccess = false,
                    Email = existingUser.Email,
                    Message = "Email already registered"
                };
            }

            var repairError = await EnsureUserRelatedRecordsAsync(existingUser);
            if (repairError != null)
                return new RegisterResponse { IsSuccess = false, Email = existingUser.Email, Message = repairError };

            // Remove any password captured by an earlier unverified registration attempt.
            // The mailbox owner will choose the final password when they verify the OTP.
            if (existingUser.PasswordHash != null)
            {
                existingUser.PasswordHash = null;
                await _db.SaveChangesAsync();
            }

            var otpResponse = await _otp.GenerateEmailVerificationOtp(
                existingUser.Username, existingUser.Email, true);
            return new RegisterResponse
            {
                IsSuccess = otpResponse.IsSuccess,
                Email = existingUser.Email,
                Message = otpResponse.Message,
                RequiresEmailVerification = true
            };
        }

        // Repairs missing child rows when development/test data cleanup left Users behind.
        // Existing roles are preserved; only role-less users receive Member.
        private async Task<string?> EnsureUserRelatedRecordsAsync(User user)
        {
            if (!await _db.UserRoles.AnyAsync(x => x.UserId == user.Id))
            {
                var memberRole = await _db.Roles.FirstOrDefaultAsync(x => x.Code == "MEMBER");
                if (memberRole == null)
                    return "The default Member role is not configured. Please contact support.";

                _db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = memberRole.Id });
            }

            if (!await _db.UserProfiles.AnyAsync(x => x.UserId == user.Id))
            {
                var profile = new UserProfile
                {
                    UserId = user.Id,
                    FirstName = string.Empty,
                    LastName = string.Empty
                };
                _db.UserProfiles.Add(profile);
                user.Profile = profile;
            }

            if (!await _db.UserSecuritySettings.AnyAsync(x => x.UserId == user.Id))
            {
                var setting = new UserSecuritySetting { UserId = user.Id, MfaEnabled = false };
                _db.UserSecuritySettings.Add(setting);
                user.SecuritySetting = setting;
            }
            else if (user.SecuritySetting == null)
            {
                user.SecuritySetting = await _db.UserSecuritySettings
                    .FirstOrDefaultAsync(x => x.UserId == user.Id);
            }

            if (_db.ChangeTracker.HasChanges())
                await _db.SaveChangesAsync();

            return null;
        }

        private static bool IsUniqueConstraintViolation(DbUpdateException exception)
        {
            for (var current = exception.InnerException; current != null; current = current.InnerException)
            {
                if (current is PostgresException postgresException &&
                    postgresException.SqlState == PostgresErrorCodes.UniqueViolation)
                    return true;
            }

            return false;
        }


        private static string? ValidateRegistrationPassword(string? password, string? confirmPassword)
        {
            if (string.IsNullOrWhiteSpace(password))
                return "Password is required.";

            if (password.Length < 8 ||
                !password.Any(char.IsUpper) ||
                !password.Any(char.IsLower) ||
                !password.Any(char.IsDigit) ||
                !password.Any(c => !char.IsLetterOrDigit(c)))
            {
                return "Password must be at least 8 characters and include uppercase, lowercase, a number, and a symbol.";
            }

            if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
                return "Passwords do not match.";

            return null;
        }

        private static string? ValidateRegistrationRequest(RegisterRequest request)
        {
            if (request == null)
                return "Registration details are required.";

            if (string.IsNullOrWhiteSpace(request.FullName))
                return "Full name is required.";

            if (request.FullName.Trim().Length > 100)
                return "Full name must be 100 characters or fewer.";

            var email = request.Email?.Trim();
            if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
                return "Enter a valid email address.";

            var password = request.Password ?? string.Empty;
            if (password.Length < 8 ||
                !password.Any(char.IsUpper) ||
                !password.Any(char.IsLower) ||
                !password.Any(char.IsDigit) ||
                !password.Any(c => !char.IsLetterOrDigit(c)))
            {
                return "Password must be at least 8 characters and include uppercase, lowercase, a number, and a symbol.";
            }

            return null;
        }

        private async Task<User> CreateNewUserAsync(ExternalLoginRequest request, string email, Role memberRole)
        {
            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = request.Name,
                Email = email,
                IsEmailConfirmed = true,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            await _db.Users.AddAsync(user);

            await _db.UserProfiles.AddAsync(new UserProfile
            {
                UserId = user.Id,
                FirstName = string.Empty,
                LastName = string.Empty,
                ProfileImageUrl = request.Avatar ?? string.Empty,
                
            });

            await _db.UserSecuritySettings.AddAsync(new UserSecuritySetting
            {
                UserId = user.Id,
                MfaEnabled = false
            });

            await _db.UserRoles.AddAsync(new UserRole
            {
                UserId = user.Id,
                RoleId = memberRole.Id
            });

            await _db.SaveChangesAsync();

            return user;
        }

        private async Task<LoginResponse> CreateSession(User user, LoginRequest request)
        {
            var roles = await GetRoles(user.Id);
            var permissions = await GetPermissions(user.Id);

            var refreshToken = _jwt.GenerateRefreshToken();
            var sessionId = await _sessions.HandleLoginSessionAsync(user.Id, request, refreshToken);
            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions, sessionId);

            return new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Email = user.Email,
                UserId = user.Id,
                UserPublicId = _publicIdService.Encode(user.Id),
                IsSuccess = true,
                Message = "Login successful",

            };
        }

        private async Task<List<string>> GetRoles(Guid userId)
        {
            return await _db.UserRoles
                .Where(x => x.UserId == userId)
                .Select(x => x.Role.Name)
                .ToListAsync();
        }

        private async Task<List<string>> GetPermissions(Guid userId)
        {
            return await _db.UserRoles
                .Where(x => x.UserId == userId)
                .SelectMany(x => x.Role.RolePermissions)
                .Select(x => x.Permission.Name)
                .Distinct()
                .ToListAsync();
        }

    }
}
