using MentorshipHub.API.Constants.Messages;
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

        

        public async Task<ResponseDTO> RequestPasswordResetAsync(ForgotPasswordRequest request)
        {
            var email = request?.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
            {
                // Keep the same outward response for malformed, unknown and known addresses.
                return new ResponseDTO { IsSuccess = true, Message = PasswordMessages.ResetRequestGeneric };
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
                    return new ResponseDTO { IsSuccess = true, Message = PasswordMessages.ResetRequestGeneric };
                }

                var now = DateTime.UtcNow;
                var recentRequests = await _db.PasswordResetTokens.CountAsync(x =>
                    x.UserId == user.Id && x.CreatedAt >= now.AddHours(-1));

                // Three reset emails per account in a rolling hour.
                if (recentRequests >= 3)
                {
                    await transaction.CommitAsync();
                    return new ResponseDTO { IsSuccess = true, Message = PasswordMessages.ResetRequestGeneric };
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
                // All authentication redirects and reset links share one configured
                // frontend origin so sandbox and production cannot cross-link.
                var frontendBaseUrl = _configuration["Frontend:BaseUrl"];
                if (!Uri.TryCreate(frontendBaseUrl, UriKind.Absolute, out var frontendUri) ||
                    !string.Equals(frontendUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                    frontendUri.AbsolutePath != "/" ||
                    !string.IsNullOrEmpty(frontendUri.Query) ||
                    !string.IsNullOrEmpty(frontendUri.Fragment))
                {
                    // Never construct a reset link from an untrusted Host header or
                    // an unvalidated environment URL.
                    await InvalidatePasswordResetTokenAsync(resetToken!.Id);
                    return new ResponseDTO { IsSuccess = true, Message = PasswordMessages.ResetRequestGeneric };
                }

                var resetUri = new Uri(frontendUri, "/reset-password");
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

            return new ResponseDTO { IsSuccess = true, Message = PasswordMessages.ResetRequestGeneric };
        }

        public async Task<ResponseDTO> ChangePasswordAsync(Guid userId, Guid currentSessionId, ChangePasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.CurrentPassword))
                return new ResponseDTO { IsSuccess = false, Message = PasswordMessages.CurrentPasswordRequired };

            var passwordValidation = ValidateRegistrationPassword(request.NewPassword, request.ConfirmPassword);
            if (passwordValidation != null)
                return new ResponseDTO { IsSuccess = false, Message = passwordValidation };

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == userId && x.IsActive);
            if (user == null)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.AccountCouldNotBeVerified };

            // External-provider-only accounts must use the account recovery flow to establish
            // local password sign-in. This endpoint never silently creates a password.
            if (string.IsNullOrWhiteSpace(user.PasswordHash))
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = PasswordMessages.PasswordSignInNotEnabled
                };

            if (!_hasher.Verify(user.PasswordHash, request.CurrentPassword))
                return new ResponseDTO { IsSuccess = false, Message = PasswordMessages.CurrentPasswordIncorrect };

            if (_hasher.Verify(user.PasswordHash, request.NewPassword!))
                return new ResponseDTO { IsSuccess = false, Message = PasswordMessages.NewPasswordMustDiffer };

            await using var transaction = await _db.Database.BeginTransactionAsync();
            user.PasswordHash = _hasher.Hash(request.NewPassword!);

            // Keep this authenticated device signed in; revoke every other active device.
            await _sessions.RevokeOtherSessionsAsync(userId, currentSessionId);

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return new ResponseDTO
            {
                IsSuccess = true,
                Message = PasswordMessages.ChangedOtherSessionsSignedOut
            };
        }

        public async Task<ResponseDTO> ResetPasswordAsync(ResetPasswordRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Token))
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = PasswordMessages.ResetLinkInvalidOrExpired
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
                    Message = PasswordMessages.ResetLinkInvalidOrExpired
                };
            }

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Id == resetToken.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed)
            {
                await transaction.RollbackAsync();
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = PasswordMessages.ResetLinkInvalidOrExpired
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
                Message = PasswordMessages.ResetSuccessful
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

        private const string MfaRecoveryOtpPurpose = "mfa-recovery-otp";
        private const string MfaRecoveryGrantPurpose = "mfa-recovery-grant";
        private const string MfaRecoveryEmailProofPurpose = "mfa-recovery-email-proof";
        private const string MfaRecoveryGenericMessage = MfaMessages.RecoveryRequestGeneric;

        public async Task<ResponseDTO> RequestMfaAccountRecoveryAsync(MfaAccountRecoveryRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Email))
                return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };

            var email = request.Email.Trim().ToLowerInvariant();
            if (!new EmailAddressAttribute().IsValid(email))
                return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };

            User? user;
            if (!string.IsNullOrWhiteSpace(request.Password))
            {
                // Password-based recovery reuses the normal lockout-protected validator.
                var validation = await ValidatePasswordWithLockoutAsync(email, request.Password);
                user = validation.User;
                if (!validation.IsValid)
                    return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };
            }
            else
            {
                // Passwordless accounts must prove control of a previously linked
                // external identity after email verification; email alone is insufficient.
                user = await _db.Users.Include(x => x.SecuritySetting)
                    .FirstOrDefaultAsync(x => x.Email.ToLower() == email);
                if (user == null || !string.IsNullOrWhiteSpace(user.PasswordHash) ||
                    !await _db.ExternalLogins.AnyAsync(x => x.UserId == user.Id))
                    return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };
            }

            if (user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true || !await _totp.IsEnabledAsync(user.Id))
                return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };

            var now = DateTime.UtcNow;
            string? otp = null;
            MfaLoginChallenge? challenge = null;

            await using (var transaction = await _db.Database.BeginTransactionAsync())
            {
                var lockKey = "mfa-recovery:" + user.Id.ToString("N");
                await _db.Database.ExecuteSqlInterpolatedAsync(
                    $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

                var recentRequests = await _db.MfaLoginChallenges.CountAsync(x =>
                    x.UserId == user.Id &&
                    x.Purpose == MfaRecoveryOtpPurpose &&
                    x.CreatedAt >= now.AddHours(-1));
                var lastRequest = await _db.MfaLoginChallenges
                    .Where(x => x.UserId == user.Id && x.Purpose == MfaRecoveryOtpPurpose)
                    .OrderByDescending(x => x.CreatedAt)
                    .Select(x => (DateTime?)x.CreatedAt)
                    .FirstOrDefaultAsync();
                if (recentRequests >= 3 || (lastRequest.HasValue && lastRequest.Value > now.AddSeconds(-60)))
                {
                    await transaction.CommitAsync();
                    return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };
                }

                var outstanding = await _db.MfaLoginChallenges
                    .Where(x => x.UserId == user.Id &&
                                (x.Purpose == MfaRecoveryOtpPurpose ||
                                 x.Purpose == MfaRecoveryGrantPurpose ||
                                 x.Purpose == MfaRecoveryEmailProofPurpose) &&
                                x.ConsumedAt == null)
                    .ToListAsync();
                foreach (var item in outstanding)
                    item.ConsumedAt = now;

                otp = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
                var challengeId = Guid.NewGuid();
                challenge = new MfaLoginChallenge
                {
                    Id = challengeId,
                    UserId = user.Id,
                    Purpose = MfaRecoveryOtpPurpose,
                    TokenHash = HashMfaRecoveryOtp(user.Id, otp, challengeId),
                    ExpiresAt = now.AddMinutes(10),
                    AttemptCount = 0,
                    ConsumedAt = null
                };
                _db.MfaLoginChallenges.Add(challenge);
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
            }

            try
            {
                var firstName = await _db.UserProfiles
                    .Where(x => x.UserId == user.Id)
                    .Select(x => x.FirstName)
                    .FirstOrDefaultAsync();
                var template = _emailTemplateService.BuildMfaAccountRecoveryOtp(
                    string.IsNullOrWhiteSpace(firstName) ? user.Username : firstName, otp!);
                var sent = await _emailService.SendEmail(user.Email, template.subject, template.body);
                if (!sent)
                    await ConsumeMfaRecoveryChallengeAsync(challenge!.Id);
            }
            catch
            {
                await ConsumeMfaRecoveryChallengeAsync(challenge!.Id);
                // Keep the response generic and do not expose email delivery details.
            }

            return new ResponseDTO { IsSuccess = true, Message = MfaRecoveryGenericMessage };
        }

        public async Task<MfaAccountRecoveryVerifyResponse> VerifyMfaAccountRecoveryOtpAsync(MfaAccountRecoveryVerifyRequest request)
        {
            const string genericFailure = MfaMessages.RecoveryVerificationGenericFailure;
            if (request == null || string.IsNullOrWhiteSpace(request.Email) ||
                string.IsNullOrWhiteSpace(request.OtpCode) ||
                !System.Text.RegularExpressions.Regex.IsMatch(request.OtpCode, @"^\d{6}$"))
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = genericFailure };

            var email = request.Email.Trim().ToLowerInvariant();
            var now = DateTime.UtcNow;
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email && x.IsActive && x.IsEmailConfirmed);
            if (user == null || user.SecuritySetting?.MfaEnabled != true || !await _totp.IsEnabledAsync(user.Id))
            {
                await transaction.CommitAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = genericFailure };
            }

            var lockKey = "mfa-recovery:" + user.Id.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

            var challenge = await _db.MfaLoginChallenges
                .Where(x => x.UserId == user.Id &&
                            x.Purpose == MfaRecoveryOtpPurpose &&
                            x.ConsumedAt == null)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync();

            if (challenge == null || challenge.ExpiresAt <= now || challenge.AttemptCount >= 5)
            {
                if (challenge != null && challenge.ConsumedAt == null)
                    challenge.ConsumedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = genericFailure };
            }

            var expected = Convert.FromHexString(challenge.TokenHash);
            var supplied = Convert.FromHexString(HashMfaRecoveryOtp(user.Id, request.OtpCode, challenge.Id));
            if (!CryptographicOperations.FixedTimeEquals(expected, supplied))
            {
                challenge.AttemptCount++;
                if (challenge.AttemptCount >= 5)
                    challenge.ConsumedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = genericFailure };
            }

            challenge.ConsumedAt = now;
            var isPasswordless = string.IsNullOrWhiteSpace(user.PasswordHash);
            if (isPasswordless && !await _db.ExternalLogins.AnyAsync(x => x.UserId == user.Id))
            {
                await transaction.CommitAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = genericFailure };
            }

            var proof = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = user.Id,
                Purpose = isPasswordless ? MfaRecoveryEmailProofPurpose : MfaRecoveryGrantPurpose,
                TokenHash = _jwt.Hash(proof),
                ExpiresAt = now.AddMinutes(10),
                AttemptCount = 0,
                ConsumedAt = null
            });
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            return new MfaAccountRecoveryVerifyResponse
            {
                IsSuccess = true,
                Message = isPasswordless
                    ? MfaMessages.RecoveryEmailVerifiedPasswordless
                    : MfaMessages.RecoveryVerificationSucceeded,
                RecoveryGrant = isPasswordless ? null : proof,
                EmailProof = isPasswordless ? proof : null,
                RequiresExternalVerification = isPasswordless
            };
        }

        public async Task<MfaAccountRecoveryVerifyResponse> CompleteExternalMfaRecoveryAsync(
            string emailProof, ExternalLoginRequest externalIdentity)
        {
            const string failure = MfaMessages.RecoveryCouldNotComplete;
            if (string.IsNullOrWhiteSpace(emailProof) || emailProof.Length > 128 ||
                externalIdentity == null || string.IsNullOrWhiteSpace(externalIdentity.Provider) ||
                string.IsNullOrWhiteSpace(externalIdentity.ProviderId))
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = failure };

            var provider = new[] { "Google", "GitHub", "LinkedIn", "Twitter" }
                .FirstOrDefault(x => string.Equals(x, externalIdentity.Provider, StringComparison.OrdinalIgnoreCase));
            if (provider == null || externalIdentity.ProviderId.Length > 256)
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = failure };

            var proofHash = _jwt.Hash(emailProof.Trim());
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var now = DateTime.UtcNow;
            var proofOwner = await _db.MfaLoginChallenges.AsNoTracking()
                .Where(x => x.TokenHash == proofHash && x.Purpose == MfaRecoveryEmailProofPurpose)
                .Select(x => new { x.UserId, x.ExpiresAt, x.ConsumedAt })
                .FirstOrDefaultAsync();
            if (proofOwner == null || proofOwner.ConsumedAt.HasValue || proofOwner.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = failure };
            }

            var lockKey = "mfa-recovery:" + proofOwner.UserId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var proof = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                    WHERE ""TokenHash"" = {proofHash} AND ""Purpose"" = {MfaRecoveryEmailProofPurpose}
                    FOR UPDATE")
                .FirstOrDefaultAsync();
            if (proof == null || proof.UserId != proofOwner.UserId || proof.ConsumedAt.HasValue || proof.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = failure };
            }

            // The provider ID must already be linked to this exact XQARE user.
            // Never auto-link identities or trust an email match as provider proof.
            var linked = await _db.ExternalLogins.AnyAsync(x =>
                x.UserId == proof.UserId && x.Provider == provider &&
                x.ProviderUserId == externalIdentity.ProviderId);
            var user = await _db.Users.Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Id == proof.UserId);
            if (!linked || user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true || !await _totp.IsEnabledAsync(user.Id))
            {
                await transaction.RollbackAsync();
                return new MfaAccountRecoveryVerifyResponse { IsSuccess = false, Message = failure };
            }

            proof.ConsumedAt = now;
            var grant = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = user.Id, Purpose = MfaRecoveryGrantPurpose, TokenHash = _jwt.Hash(grant),
                ExpiresAt = now.AddMinutes(10), AttemptCount = 0, ConsumedAt = null
            });
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return new MfaAccountRecoveryVerifyResponse
            {
                IsSuccess = true,
                Message = MfaMessages.RecoveryExternalIdentityVerified,
                RecoveryGrant = grant
            };
        }

        private string HashMfaRecoveryOtp(Guid userId, string otp, Guid challengeId)
        {
            var jwtKey = _configuration["Jwt:Key"];
            if (string.IsNullOrWhiteSpace(jwtKey))
                throw new InvalidOperationException("The recovery OTP hash key is not configured.");
            var purposeKey = HMACSHA256.HashData(
                Encoding.UTF8.GetBytes(jwtKey),
                Encoding.UTF8.GetBytes("XQARE.MfaRecoveryOtp.v1"));
            var hash = HMACSHA256.HashData(
                purposeKey,
                Encoding.UTF8.GetBytes(userId.ToString("N") + ":" + challengeId.ToString("N") + ":" + otp));
            return Convert.ToHexString(hash);
        }

        private async Task ConsumeMfaRecoveryChallengeAsync(Guid challengeId)
        {
            var challenge = await _db.MfaLoginChallenges.FirstOrDefaultAsync(x => x.Id == challengeId);
            if (challenge != null && challenge.ConsumedAt == null)
            {
                challenge.ConsumedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }
        }

        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
                return new LoginResponse { IsSuccess = false, ErrorCode = "validation_error", Message = AuthMessages.CredentialsRequired };

            var email = request.Email.Trim().ToLowerInvariant();

            var passwordValidation = await ValidatePasswordWithLockoutAsync(email, request.Password);
            var user = passwordValidation.User;
            if (passwordValidation.RetryAfterSeconds.HasValue)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    ErrorCode = "account_locked",
                    RetryAfterSeconds = passwordValidation.RetryAfterSeconds,
                    Message = AuthMessages.AccountLockedFor(passwordValidation.RetryAfterSeconds.Value)
                };
            }

            if (!passwordValidation.IsValid || user == null)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    ErrorCode = "invalid_credentials",
                    Message = AuthMessages.InvalidCredentials
                };
            }

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, ErrorCode = "account_inactive", Message = AuthMessages.AccountInactive };

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
                    ErrorCode = "email_verification_required",
                    RequiresEmailVerification = true,
                    Email = user.Email,
                    Message = AuthMessages.EmailVerificationRequired
                };
            }

            if (user.SecuritySetting?.MfaEnabled == true)
                return await CreateMfaChallengeAsync(user, new LoginRequest { DeviceId = request.DeviceId, DeviceName = request.DeviceName });

            return await CreateSession(user, request);
        }


        private async Task<(User? User, bool IsValid, int? RetryAfterSeconds)> ValidatePasswordWithLockoutAsync(string email, string password)
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
                return (null, false, null);
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
                var remainingSeconds = Math.Max(1, (int)Math.Ceiling((security.LockoutEnd.Value - now).TotalSeconds));
                await transaction.CommitAsync();
                return (null, false, remainingSeconds);
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
                var retryAfterSeconds = security.LockoutEnd.HasValue && security.LockoutEnd.Value > now
                    ? Math.Max(1, (int)Math.Ceiling((security.LockoutEnd.Value - now).TotalSeconds))
                    : (int?)null;
                await transaction.CommitAsync();
                return (null, false, retryAfterSeconds);
            }

            // Upgrade legacy raw BCrypt hashes after a successful password check.
            // New hashes use the versioned SHA384-enhanced scheme and support the full
            // password input instead of BCrypt's 72-byte raw-input limit.
            if (_hasher.NeedsRehash(user.PasswordHash))
                user.PasswordHash = _hasher.Hash(password);

            // A successful primary factor resets consecutive password failures.
            security.AccessFailedCount = 0;
            security.LockoutEnd = null;
            security.FailedLoginWindowStartedAt = null;
            security.LockoutLevel = 0;
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return (user, true, null);
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
                    Message = ExternalLoginMessages.DefaultMemberRoleMissing
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
                RequiresEmailVerification = response.CanVerifyExistingOtp,
                CanVerifyExistingOtp = response.CanVerifyExistingOtp,
                RetryAfterSeconds = response.RetryAfterSeconds
            };
        }

                public async Task<ConnectedAccountsResponse> GetConnectedAccountsAsync(Guid userId)
        {
            var account = await _db.Users.AsNoTracking()
                .Where(x => x.Id == userId && x.IsActive && x.IsEmailConfirmed)
                .Select(x => new { x.Email, HasPassword = !string.IsNullOrWhiteSpace(x.PasswordHash) })
                .FirstOrDefaultAsync();

            if (account == null)
            {
                return new ConnectedAccountsResponse
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.AccountCouldNotBeVerified
                };
            }

            var providers = await _db.ExternalLogins.AsNoTracking()
                .Where(x => x.UserId == userId)
                .OrderBy(x => x.Provider)
                .Select(x => x.Provider)
                .Distinct()
                .ToListAsync();

            return new ConnectedAccountsResponse
            {
                IsSuccess = true,
                Email = account.Email,
                HasPassword = account.HasPassword,
                ConnectedProviders = providers,
                Message = ExternalLoginMessages.ConnectedMethodsRetrieved
            };
        }

        public async Task<string?> CreateExternalLinkChallengeAsync(Guid userId, Guid sessionId)
        {
            var now = DateTime.UtcNow;

            await using var transaction = await _db.Database.BeginTransactionAsync();

            // Serialize challenge creation for this account and cap concurrent,
            // unexpired OAuth link attempts so repeated starts cannot grow the table
            // without bound during the five-minute validity window.
            var lockKey = "external-link:" + userId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");

            var eligibleUser = await _db.Users.AsNoTracking().AnyAsync(x =>
                x.Id == userId && x.IsActive && x.IsEmailConfirmed);
            var activeSession = await _db.UserSessions.AsNoTracking().AnyAsync(x =>
                x.Id == sessionId &&
                x.UserId == userId &&
                !x.IsRevoked &&
                x.RevokedAt == null &&
                x.ExpiresAt > now);

            if (!eligibleUser || !activeSession)
            {
                await transaction.RollbackAsync();
                return null;
            }

            var outstandingCount = await _db.MfaLoginChallenges.CountAsync(x =>
                x.UserId == userId &&
                x.Purpose == "external-link" &&
                x.ConsumedAt == null &&
                x.ExpiresAt > now);

            if (outstandingCount >= 5)
            {
                await transaction.RollbackAsync();
                return null;
            }

            // The raw nonce is returned only to the controller so it can be placed
            // inside the existing Data-Protected, HttpOnly OAuth linking ticket.
            // Only its SHA-256 hash is persisted.
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var tokenHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));

            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = userId,
                TokenHash = tokenHash,
                Purpose = "external-link",
                ExpiresAt = now.AddMinutes(5),
                AttemptCount = 0
            });

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return nonce;
        }

        public async Task<bool> ConsumeExternalLinkChallengeAsync(Guid userId, string nonce)
        {
            if (userId == Guid.Empty ||
                string.IsNullOrWhiteSpace(nonce) ||
                nonce.Length != 64 ||
                nonce.Any(character => !Uri.IsHexDigit(character)))
            {
                return false;
            }

            var tokenHash = Convert.ToHexString(
                SHA256.HashData(Encoding.UTF8.GetBytes(nonce)));

            await using var transaction = await _db.Database.BeginTransactionAsync();

            // The unique token-hash index locates one row. FOR UPDATE serializes
            // concurrent callbacks so only one can consume this OAuth challenge.
            var challenge = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                    WHERE ""TokenHash"" = {tokenHash}
                    FOR UPDATE")
                .FirstOrDefaultAsync();

            var now = DateTime.UtcNow;
            if (challenge == null ||
                challenge.UserId != userId ||
                !string.Equals(challenge.Purpose, "external-link", StringComparison.Ordinal) ||
                challenge.ConsumedAt.HasValue ||
                challenge.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return false;
            }

            challenge.ConsumedAt = now;
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return true;
        }

        public async Task<ResponseDTO> LinkExternalLoginAsync(Guid userId, Guid sessionId, ExternalLoginRequest request)
        {
            if (request == null ||
                string.IsNullOrWhiteSpace(request.Provider) ||
                string.IsNullOrWhiteSpace(request.ProviderId))
            {
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.ProviderIdentifierInvalid
                };
            }

            var provider = request.Provider.Trim();
            var supportedProviders = new[] { "Google", "GitHub", "LinkedIn", "Twitter" };
            provider = supportedProviders.FirstOrDefault(
                x => string.Equals(x, provider, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

            if (string.IsNullOrEmpty(provider))
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.InvalidProviderService };

            var providerId = request.ProviderId.Trim();
            if (providerId.Length > 256)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.ProviderAccountIdentifierInvalid };

            var now = DateTime.UtcNow;
            var activeSession = await _db.UserSessions.AsNoTracking().AnyAsync(x =>
                x.Id == sessionId &&
                x.UserId == userId &&
                !x.IsRevoked &&
                x.RevokedAt == null &&
                x.ExpiresAt > now);

            if (!activeSession)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.SessionInactiveConnect };

            var user = await _db.Users.FirstOrDefaultAsync(x =>
                x.Id == userId && x.IsActive && x.IsEmailConfirmed);

            if (user == null)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.AccountCouldNotVerify };

            // A provider link must represent the same verified email identity as the
            // authenticated XQARE account. Authentication to two unrelated identities
            // must never implicitly combine them under one XQARE user.
            var providerEmail = request.Email?.Trim();
            if (!request.EmailVerified ||
                string.IsNullOrWhiteSpace(providerEmail) ||
                !new EmailAddressAttribute().IsValid(providerEmail))
            {
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.ProviderEmailUnverified
                };
            }

            if (!string.Equals(user.Email?.Trim(), providerEmail, StringComparison.OrdinalIgnoreCase))
            {
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.ProviderEmailMismatch
                };
            }

            var identityOwner = await _db.ExternalLogins.FirstOrDefaultAsync(x =>
                x.Provider == provider && x.ProviderUserId == providerId);

            if (identityOwner != null)
            {
                return identityOwner.UserId == userId
                    ? new ResponseDTO { IsSuccess = true, Message = string.Format(ExternalLoginMessages.ProviderAlreadyConnectedFormat, provider) }
                    : new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.ProviderAlreadyConnected };
            }

            var existingProvider = await _db.ExternalLogins.AnyAsync(x =>
                x.UserId == userId && x.Provider == provider);

            if (existingProvider)
                return new ResponseDTO { IsSuccess = false, Message = string.Format(ExternalLoginMessages.DifferentProviderAccountAlreadyConnectedFormat, provider) };

            _db.ExternalLogins.Add(new ExternalLogin
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Provider = provider,
                ProviderUserId = providerId,
                CreatedAt = now
            });

            try
            {
                await _db.SaveChangesAsync();
                return new ResponseDTO { IsSuccess = true, Message = string.Format(ExternalLoginMessages.ProviderConnectedSuccessfullyFormat, provider) };
            }
            catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
            {
                _db.ChangeTracker.Clear();

                var racedIdentity = await _db.ExternalLogins.AsNoTracking().FirstOrDefaultAsync(x =>
                    x.Provider == provider && x.ProviderUserId == providerId);

                if (racedIdentity?.UserId == userId)
                    return new ResponseDTO { IsSuccess = true, Message = string.Format(ExternalLoginMessages.ProviderAlreadyConnectedFormat, provider) };

                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = racedIdentity != null
                        ? ExternalLoginMessages.ProviderAlreadyConnected
                        : string.Format(ExternalLoginMessages.ProviderAlreadyConnectedToXqareFormat, provider)
                };
            }
        }

        public async Task<ResponseDTO> DisconnectExternalLoginAsync(
            Guid userId, Guid sessionId, string provider, string currentPassword)
        {
            var supportedProviders = new[] { "Google", "GitHub", "LinkedIn", "Twitter" };
            provider = supportedProviders.FirstOrDefault(x =>
                string.Equals(x, provider?.Trim(), StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

            if (string.IsNullOrEmpty(provider))
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.InvalidProviderService };

            var now = DateTime.UtcNow;
            var activeSession = await _db.UserSessions.AsNoTracking().AnyAsync(x =>
                x.Id == sessionId &&
                x.UserId == userId &&
                !x.IsRevoked &&
                x.RevokedAt == null &&
                x.ExpiresAt > now);

            if (!activeSession)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.SessionInactiveChange };

            var user = await _db.Users.FirstOrDefaultAsync(x =>
                x.Id == userId && x.IsActive && x.IsEmailConfirmed);

            if (user == null)
                return new ResponseDTO { IsSuccess = false, Message = ExternalLoginMessages.AccountCouldNotVerify };

            // Disconnect is a security-sensitive action. Require the local password
            // as step-up verification and keep at least one independent local login path.
            if (string.IsNullOrWhiteSpace(user.PasswordHash))
            {
                return new ResponseDTO
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.SetPasswordBeforeDisconnect
                };
            }

            if (string.IsNullOrWhiteSpace(currentPassword) ||
                !_hasher.Verify(user.PasswordHash, currentPassword))
            {
                return new ResponseDTO { IsSuccess = false, Message = PasswordMessages.CurrentPasswordIncorrect };
            }

            var externalLogin = await _db.ExternalLogins.FirstOrDefaultAsync(x =>
                x.UserId == userId && x.Provider == provider);

            if (externalLogin == null)
                return new ResponseDTO { IsSuccess = false, Message = string.Format(ExternalLoginMessages.ProviderNotConnectedFormat, provider) };

            _db.ExternalLogins.Remove(externalLogin);
            await _db.SaveChangesAsync();

            return new ResponseDTO
            {
                IsSuccess = true,
                Message = string.Format(ExternalLoginMessages.ProviderDisconnectedFormat, provider)
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
                    Message = ExternalLoginMessages.ProviderIdentityInvalid
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
                // For providers whose integrations supply a verified email, require
                // that evidence on every login. This also blocks old mismatched links
                // created before the verified-email check was introduced.
                var returnedEmail = request.Email?.Trim();
                var requiresVerifiedEmail = new[] { "Google", "GitHub", "LinkedIn" }
                    .Contains(request.Provider, StringComparer.OrdinalIgnoreCase);

                if (requiresVerifiedEmail &&
                    (!request.EmailVerified ||
                     string.IsNullOrWhiteSpace(returnedEmail) ||
                     !new EmailAddressAttribute().IsValid(returnedEmail)))
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Message = ExternalLoginMessages.ProviderEmailMissingForSignIn
                    };
                }

                if (!string.IsNullOrWhiteSpace(returnedEmail) &&
                    !string.Equals(
                        externalLogin.User.Email?.Trim(),
                        returnedEmail,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Message = ExternalLoginMessages.ProviderEmailNoLongerMatches
                    };
                }

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
                        Message = ExternalLoginMessages.ProviderEmailMissingForRegistration
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
                        Message = ExternalLoginMessages.ExistingAccountForEmail
                    };
                }

                var memberRole = await _db.Roles.FirstOrDefaultAsync(x => x.Code == "MEMBER");
                if (memberRole == null)
                {
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        Message = ExternalLoginMessages.DefaultMemberRoleMissing
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
                                Message = ExternalLoginMessages.ExistingAccountForEmail
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
                    Message = OtpMessages.AccountInactive
                };
            }

            // Older provider links may have been created before verified-email checks existed.
            // Do not let those legacy links bypass registration email verification.
            if (!user.IsEmailConfirmed)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = ExternalLoginMessages.EmailNotVerified
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

        public async Task<string?> CreateExternalLoginExchangeChallengeAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return null;

            var session = await _sessions.GetByTokenAsync(refreshToken);
            var now = DateTime.UtcNow;
            if (session == null ||
                session.IsRevoked ||
                session.RevokedAt.HasValue ||
                session.ExpiresAt <= now ||
                session.User == null ||
                !session.User.IsActive)
            {
                return null;
            }

            await using var transaction = await _db.Database.BeginTransactionAsync();

            var lockedSession = await _db.UserSessions
                .FromSqlInterpolated($@"SELECT * FROM ""UserSessions""
                    WHERE ""Id"" = {session.Id}
                    FOR UPDATE")
                .AsNoTracking()
                .FirstOrDefaultAsync();

            if (lockedSession == null ||
                lockedSession.UserId != session.UserId ||
                lockedSession.IsRevoked ||
                lockedSession.RevokedAt.HasValue ||
                lockedSession.ExpiresAt <= now ||
                !string.Equals(lockedSession.RefreshTokenHash, _jwt.Hash(refreshToken), StringComparison.Ordinal))
            {
                await transaction.RollbackAsync();
                return null;
            }

            var outstanding = await _db.MfaLoginChallenges.CountAsync(x =>
                x.UserId == session.UserId &&
                x.Purpose == "external-login" &&
                x.ConsumedAt == null &&
                x.ExpiresAt > now);
            if (outstanding >= 5)
            {
                await transaction.RollbackAsync();
                return null;
            }

            var code = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var codeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = session.UserId,
                TokenHash = codeHash,
                Purpose = "external-login",
                DeviceId = session.Id.ToString("D"),
                ExpiresAt = now.AddMinutes(2),
                AttemptCount = 0
            });

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return code;
        }

        public async Task<string?> CreateExternalMfaLoginExchangeChallengeAsync(string mfaChallengeToken)
        {
            if (string.IsNullOrWhiteSpace(mfaChallengeToken) || mfaChallengeToken.Length > 128)
                return null;

            var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(mfaChallengeToken)));
            var now = DateTime.UtcNow;
            var mfaChallenge = await _db.MfaLoginChallenges.AsNoTracking().FirstOrDefaultAsync(x =>
                x.TokenHash == tokenHash &&
                x.Purpose == "totp" &&
                x.ConsumedAt == null &&
                x.ExpiresAt > now);
            if (mfaChallenge == null)
                return null;

            await using var transaction = await _db.Database.BeginTransactionAsync();
            var outstanding = await _db.MfaLoginChallenges.CountAsync(x =>
                x.UserId == mfaChallenge.UserId &&
                x.Purpose == "external-mfa" &&
                x.ConsumedAt == null &&
                x.ExpiresAt > now);
            if (outstanding >= 5)
            {
                await transaction.RollbackAsync();
                return null;
            }

            var code = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var codeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
            _db.MfaLoginChallenges.Add(new MfaLoginChallenge
            {
                UserId = mfaChallenge.UserId,
                TokenHash = codeHash,
                Purpose = "external-mfa",
                DeviceId = mfaChallenge.Id.ToString("D"),
                ExpiresAt = mfaChallenge.ExpiresAt < now.AddMinutes(2)
                    ? mfaChallenge.ExpiresAt
                    : now.AddMinutes(2),
                AttemptCount = 0
            });

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return code;
        }

        public async Task<LoginResponse> ExchangeExternalLoginChallengeAsync(string code)
        {
            if (string.IsNullOrWhiteSpace(code) || code.Length > 128)
                return new LoginResponse { IsSuccess = false, Message = AuthMessages.SignInExchangeExpired };

            var codeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
            await using var transaction = await _db.Database.BeginTransactionAsync();

            var challenge = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                    WHERE ""TokenHash"" = {codeHash}
                    FOR UPDATE")
                .FirstOrDefaultAsync();

            var now = DateTime.UtcNow;
            if (challenge == null ||
                (challenge.Purpose != "external-login" && challenge.Purpose != "external-mfa") ||
                challenge.ConsumedAt.HasValue ||
                challenge.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = AuthMessages.SignInExchangeExpired };
            }

            if (string.Equals(challenge.Purpose, "external-mfa", StringComparison.Ordinal))
            {
                if (!Guid.TryParse(challenge.DeviceId, out var mfaChallengeId))
                {
                    challenge.ConsumedAt = now;
                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();
                    return new LoginResponse { IsSuccess = false, Message = AuthMessages.MfaVerificationExpired };
                }

                var mfaChallenge = await _db.MfaLoginChallenges
                    .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                        WHERE ""Id"" = {mfaChallengeId}
                        FOR UPDATE")
                    .FirstOrDefaultAsync();
                var mfaUser = await _db.Users.FindAsync(challenge.UserId);

                if (mfaChallenge == null ||
                    mfaChallenge.UserId != challenge.UserId ||
                    mfaChallenge.Purpose != "totp" ||
                    mfaChallenge.ConsumedAt.HasValue ||
                    mfaChallenge.ExpiresAt <= now ||
                    mfaUser == null ||
                    !mfaUser.IsActive ||
                    !mfaUser.IsEmailConfirmed)
                {
                    challenge.ConsumedAt = now;
                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();
                    return new LoginResponse { IsSuccess = false, Message = AuthMessages.MfaVerificationExpired };
                }

                // Rotate the MFA challenge token during exchange. Only its hash
                // remains in the database; the new raw token is returned to the
                // controller solely so it can be placed in the HttpOnly cookie.
                var mfaToken = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
                mfaChallenge.TokenHash = Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(mfaToken)));
                challenge.ConsumedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new LoginResponse
                {
                    IsSuccess = true,
                    RequiresMfa = true,
                    MfaChallengeToken = mfaToken,
                    UserId = mfaUser.Id,
                    Email = mfaUser.Email,
                    Message = MfaMessages.EnterSixDigitCode
                };
            }

            if (!Guid.TryParse(challenge.DeviceId, out var sessionId))
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = AuthMessages.SignInExchangeExpired };
            }

            var session = await _db.UserSessions
                .FromSqlInterpolated($@"SELECT * FROM ""UserSessions""
                    WHERE ""Id"" = {sessionId}
                    FOR UPDATE")
                .FirstOrDefaultAsync();

            var user = session == null ? null : await _db.Users.FindAsync(session.UserId);
            if (session == null ||
                session.UserId != challenge.UserId ||
                session.IsRevoked ||
                session.RevokedAt.HasValue ||
                session.ExpiresAt <= now ||
                user == null ||
                !user.IsActive ||
                !user.IsEmailConfirmed)
            {
                challenge.ConsumedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new LoginResponse { IsSuccess = false, Message = AuthMessages.SignInSessionInvalid };
            }

            challenge.ConsumedAt = now;
            var newRefreshToken = _jwt.GenerateRefreshToken();
            await _sessions.RotateAsync(session, newRefreshToken);

            var roles = await GetRoles(user.Id);
            var permissions = await GetPermissions(user.Id);
            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions, session.Id);

            var response = new LoginResponse
            {
                IsSuccess = true,
                AccessToken = accessToken,
                RefreshToken = newRefreshToken,
                Email = user.Email,
                UserId = user.Id,
                UserPublicId = _publicIdService.Encode(user.Id),
                Message = AuthMessages.LoginSuccessful
            };

            await transaction.CommitAsync();
            return response;
        }

        public async Task<EmailOtpResponse> ResendEmailOtp(EmailOtpRequest request)
        {
            var email = request?.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
            {
                return new EmailOtpResponse
                {
                    IsSuccess = true,
                    Message = OtpMessages.PendingRegistrationGeneric
                };
            }

            // Registration OTPs are not a passwordless sign-in method. Only active,
            // unconfirmed registrations can request another registration code.
            var user = await _db.Users.FirstOrDefaultAsync(x =>
                x.Email.ToLower() == email &&
                x.IsActive &&
                !x.IsEmailConfirmed);

            if (user == null)
            {
                return new EmailOtpResponse
                {
                    IsSuccess = true,
                    Message = OtpMessages.PendingRegistrationGeneric
                };
            }

            return await _otp.GenerateEmailVerificationOtp(user.Username, user.Email, true);
        }

        private async Task<LoginResponse> CreateMfaChallengeAsync(User user, LoginRequest loginRequest)
        {
            if (!await _totp.IsEnabledAsync(user.Id))
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = MfaMessages.SetupRequired
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
                Message = MfaMessages.EnterSixDigitCode
            };
        }

        public async Task<LoginResponse> VerifyMfaChallengeAsync(VerifyMfaChallengeRequest request, string challengeToken)
        {
            if (request == null || string.IsNullOrWhiteSpace(challengeToken) || string.IsNullOrWhiteSpace(request.Code))
                return new LoginResponse { IsSuccess = false, Message = MfaMessages.InvalidVerificationRequest };
            var factor = (request.Factor ?? "auto").Trim().ToLowerInvariant();
            if (factor != "auto" && factor != "totp" && factor != "recovery")
                return new LoginResponse { IsSuccess = false, Message = MfaMessages.UnsupportedVerificationMethod };

            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(challengeToken)));
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var challenge = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges"" WHERE ""TokenHash"" = {hash} FOR UPDATE")
                .FirstOrDefaultAsync();
            var now = DateTime.UtcNow;
            if (challenge == null || challenge.ConsumedAt != null || challenge.ExpiresAt <= now || challenge.AttemptCount >= 5)
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = MfaMessages.ChallengeExpired };
            }

            if (!string.Equals(challenge.Purpose, "totp", StringComparison.Ordinal))
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = MfaMessages.ChallengeUnsupported };
            }

            var user = await _db.Users.Include(x => x.SecuritySetting).FirstOrDefaultAsync(x => x.Id == challenge.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed || user.SecuritySetting?.MfaEnabled != true)
            {
                await transaction.RollbackAsync();
                return new LoginResponse { IsSuccess = false, Message = MfaMessages.ChallengeInvalid };
            }

            var valid = false;
            var failure = MfaMessages.InvalidVerificationCode;
            int? retryAfterSeconds = null;
            if (challenge.Purpose == "totp" && (factor == "auto" || factor == "totp"))
            {
                var result = await _totp.VerifyCodeAndConsumeAsync(user.Id, request.Code);
                valid = result.IsValid;
                failure = result.Message;
                retryAfterSeconds = result.RetryAfterSeconds;
            }
            else if (challenge.Purpose == "totp" && factor == "recovery")
            {
                valid = await _totp.ConsumeRecoveryCodeAsync(user.Id, request.Code);
                failure = MfaMessages.InvalidOrUsedRecoveryCode;
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
                    RetryAfterSeconds = retryAfterSeconds,
                    Message = retryAfterSeconds.HasValue
                        ? failure
                        : challenge.ConsumedAt.HasValue ? MfaMessages.TooManyChallengeAttempts : failure
                };
            }

            challenge.ConsumedAt = now;
            var loginRequest = new LoginRequest { DeviceId = challenge.DeviceId ?? string.Empty, DeviceName = challenge.DeviceName };
            var response = await CreateSession(user, loginRequest);
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();
            return response;
        }

        public async Task<TotpEnrollmentStartResponse> StartMfaRecoveryEnrollmentAsync(MfaAccountRecoveryEnrollmentStartRequest request)
        {
            const string failure = MfaMessages.RecoverySessionInvalidOrExpired;
            if (request == null || string.IsNullOrWhiteSpace(request.RecoveryGrant) || request.RecoveryGrant.Length > 128)
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = failure };

            var grantHash = _jwt.Hash(request.RecoveryGrant.Trim());
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var now = DateTime.UtcNow;
            // Read the owner first, then take the per-user advisory lock before locking
            // the grant row. This keeps lock ordering consistent with OTP request/verify.
            var grantOwner = await _db.MfaLoginChallenges.AsNoTracking()
                .Where(x => x.TokenHash == grantHash && x.Purpose == MfaRecoveryGrantPurpose)
                .Select(x => new { x.UserId, x.ExpiresAt, x.ConsumedAt })
                .FirstOrDefaultAsync();
            if (grantOwner == null || grantOwner.ConsumedAt.HasValue || grantOwner.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = failure };
            }

            var lockKey = "mfa-recovery:" + grantOwner.UserId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var grant = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                    WHERE ""TokenHash"" = {grantHash} AND ""Purpose"" = {MfaRecoveryGrantPurpose}
                    FOR UPDATE")
                .FirstOrDefaultAsync();
            if (grant == null || grant.UserId != grantOwner.UserId ||
                grant.ConsumedAt.HasValue || grant.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = failure };
            }

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Id == grant.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true || !await _totp.IsEnabledAsync(user.Id))
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = failure };
            }

            // The per-user recovery lock is already held for this transaction.
            // The existing authenticator remains active until the replacement code is confirmed.
            var response = await _totp.StartEnrollmentAsync(user.Id, user.Email, allowReplace: true);
            if (!response.IsSuccess)
            {
                await transaction.RollbackAsync();
                return response;
            }

            await transaction.CommitAsync();
            return response;
        }

        public async Task<TotpEnrollmentConfirmResponse> CompleteMfaAccountRecoveryAsync(MfaAccountRecoveryCompleteRequest request)
        {
            const string failure = MfaMessages.RecoverySessionInvalidOrExpired;
            if (request == null || string.IsNullOrWhiteSpace(request.RecoveryGrant) ||
                request.RecoveryGrant.Length > 128 || string.IsNullOrWhiteSpace(request.Code) ||
                !System.Text.RegularExpressions.Regex.IsMatch(request.Code, @"^\d{6}$"))
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = MfaMessages.RecoverySessionCodeRequired };

            var grantHash = _jwt.Hash(request.RecoveryGrant.Trim());
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var now = DateTime.UtcNow;
            var grantOwner = await _db.MfaLoginChallenges.AsNoTracking()
                .Where(x => x.TokenHash == grantHash && x.Purpose == MfaRecoveryGrantPurpose)
                .Select(x => new { x.UserId, x.ExpiresAt, x.ConsumedAt })
                .FirstOrDefaultAsync();
            if (grantOwner == null || grantOwner.ConsumedAt.HasValue || grantOwner.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = failure };
            }

            var lockKey = "mfa-recovery:" + grantOwner.UserId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync(
                $"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var grant = await _db.MfaLoginChallenges
                .FromSqlInterpolated($@"SELECT * FROM ""MfaLoginChallenges""
                    WHERE ""TokenHash"" = {grantHash} AND ""Purpose"" = {MfaRecoveryGrantPurpose}
                    FOR UPDATE")
                .FirstOrDefaultAsync();
            if (grant == null || grant.UserId != grantOwner.UserId ||
                grant.ConsumedAt.HasValue || grant.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = failure };
            }

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Id == grant.UserId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true || !await _totp.IsEnabledAsync(user.Id))
            {
                await transaction.RollbackAsync();
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = failure };
            }

            // The per-user recovery lock is already held for this transaction.
            // ConfirmEnrollmentAsync joins this transaction. The active secret and old
            // recovery codes are changed only after the new authenticator code is valid.
            var response = await _totp.ConfirmEnrollmentAsync(user.Id, request.Code);
            if (!response.IsSuccess)
            {
                // Persist the TOTP failed-attempt counter while leaving the grant available
                // for a retry until its own expiry or the TOTP lockout is reached.
                await transaction.CommitAsync();
                return response;
            }

            grant.ConsumedAt = now;
            await _db.UserSessions
                .Where(x => x.UserId == user.Id && !x.IsRevoked)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(x => x.IsRevoked, true)
                    .SetProperty(x => x.RevokedAt, now)
                    .SetProperty(x => x.LastActivityAt, now));

            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            try
            {
                var firstName = await _db.UserProfiles
                    .Where(x => x.UserId == user.Id)
                    .Select(x => x.FirstName)
                    .FirstOrDefaultAsync();
                var template = _emailTemplateService.BuildMfaAccountRecoveryCompleted(
                    string.IsNullOrWhiteSpace(firstName) ? user.Username : firstName);
                await _emailService.SendEmail(user.Email, template.subject, template.body);
            }
            catch
            {
                // Recovery is already committed. A notification failure must not undo it.
            }

            response.Message = MfaMessages.AuthenticatorRecoveryCompleted;
            return response;
        }

        public async Task<TotpEnrollmentStartResponse> StartTotpEnrollmentAsync(Guid userId, TotpEnrollmentStartRequest request)
        {
            var user = await _db.Users.FindAsync(userId);
            if (user == null || !user.IsActive || !user.IsEmailConfirmed)
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = MfaMessages.AccountNotEligibleForAuthenticator };
            if (string.IsNullOrWhiteSpace(user.PasswordHash) || !_hasher.Verify(user.PasswordHash, request.CurrentPassword ?? string.Empty))
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = MfaMessages.ConfirmCurrentAccountPassword };
            var enabled = await _totp.IsEnabledAsync(userId);
            if (enabled)
            {
                var current = await _totp.VerifyCodeAndConsumeAsync(userId, request.CurrentTotpCode ?? string.Empty);
                if (!current.IsValid)
                    return new TotpEnrollmentStartResponse { IsSuccess = false, Message = MfaMessages.CurrentAuthenticatorCodeRequired };
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
                return new ResponseDTO { IsSuccess = false, Message = MfaMessages.CurrentPasswordIncorrectForDisable };
            var verification = await _totp.VerifyCodeAndConsumeAsync(userId, request.Code);
            if (!verification.IsValid) return new ResponseDTO { IsSuccess = false, Message = verification.Message };
            await _totp.DisableAsync(userId);
            return new ResponseDTO { IsSuccess = true, Message = MfaMessages.AuthenticatorDisabledSuccessfully };
        }

        public async Task<LoginResponse> VerifyRegisterEmailOtp(VerifyRegisterEmailOtpRequest request)
        {
            if (request == null)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.RegistrationDetailsRequired };

            var email = request.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(request.OtpCode))
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.EmailAndCodeRequired };

            // Serialize OTP consumption and OTP regeneration for this email.
            // GenerateEmailVerificationOtp uses the same PostgreSQL advisory lock.
            await using var transaction = await _db.Database.BeginTransactionAsync();
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({email}))");

            var now = DateTime.UtcNow;
            var otp = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (otp == null)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.NotFound };

            if (otp.IsUsed)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.AlreadyUsed };

            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil.Value > now)
                {
                    var retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((otp.LockedUntil.Value - now).TotalSeconds));
                    var remainingMinutes = Math.Ceiling(retryAfterSeconds / 60d);
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        RetryAfterSeconds = retryAfterSeconds,
                        Message = string.Format(OtpMessages.LockedForMinutes, remainingMinutes)
                    };
                }

                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt <= now)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.Expired };

            if (!_hasher.Verify(otp.CodeHash, request.OtpCode))
            {
                otp.AttemptCount++;
                var remainingAttempts = Math.Max(0, otp.MaxAttempts - otp.AttemptCount);

                if (otp.AttemptCount >= otp.MaxAttempts)
                {
                    otp.LockedUntil = now.AddHours(24);
                    await _db.SaveChangesAsync();
                    await transaction.CommitAsync();
                    return new LoginResponse
                    {
                        IsSuccess = false,
                        RetryAfterSeconds = 24 * 60 * 60,
                        Message = OtpMessages.LockedFor24Hours
                    };
                }

                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return new LoginResponse { IsSuccess = false, Message = string.Format(OtpMessages.InvalidAttemptsRemaining, remainingAttempts) };
            }

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (user == null)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.UserNotFound };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.AccountInactive };

            if (user.IsEmailConfirmed)
                return new LoginResponse { IsSuccess = false, Message = OtpMessages.EmailAlreadyVerified };

            // The OTP must be checked before password validation so malformed
            // password submissions cannot bypass the OTP attempt counter.
            var passwordValidation = ValidateRegistrationPassword(request.Password, request.ConfirmPassword);
            if (passwordValidation != null)
                return new LoginResponse { IsSuccess = false, Message = passwordValidation };

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
            sessionResponse.Message = OtpMessages.EmailVerifiedPrefix + sessionResponse.Message;
            return sessionResponse;
        }

        public async Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
                return (new RefreshTokenResponse { IsSuccess = false, Message = SessionMessages.RefreshTokenMissing }, default!);

            // Lock the current token row before validating and rotating it. A second tab
            // presenting the same cookie waits for the first transaction, then finds that
            // the old hash no longer exists instead of rotating it a second time.
            await using var transaction = await _db.Database.BeginTransactionAsync();
            var tokenHash = _jwt.Hash(refreshToken);
            var session = await _db.UserSessions
                .FromSqlInterpolated($@"SELECT * FROM ""UserSessions""
                    WHERE ""RefreshTokenHash"" = {tokenHash}
                    FOR UPDATE")
                .FirstOrDefaultAsync();

            var now = DateTime.UtcNow;
            if (session == null || session.IsRevoked || session.RevokedAt != null || session.ExpiresAt <= now)
            {
                await transaction.RollbackAsync();
                return (new RefreshTokenResponse { IsSuccess = false, Message = SessionMessages.LoginExpired }, default!);
            }

            // Enforce a maximum session lifetime in addition to the sliding seven-day window.
            if (session.CreatedAt.AddDays(30) <= now)
            {
                session.IsRevoked = true;
                session.RevokedAt = now;
                await _db.SaveChangesAsync();
                await transaction.CommitAsync();
                return (new RefreshTokenResponse { IsSuccess = false, Message = SessionMessages.MaximumAgeReached }, default!);
            }

            var user = await _db.Users.FindAsync(session.UserId);
            if (user == null || !user.IsActive)
            {
                await transaction.RollbackAsync();
                return (new RefreshTokenResponse { IsSuccess = false, Message = SessionMessages.AccountInactive }, default!);
            }

            var roles = await GetRoles(user.Id);
            var permissions = await GetPermissions(user.Id);
            var newRefresh = _jwt.GenerateRefreshToken();

            await _sessions.RotateAsync(session, newRefresh);

            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions, session.Id);
            var response = new RefreshTokenResponse
            {
                AccessToken = accessToken,
                IsSuccess = true,
                Message = SessionMessages.RefreshTokenUpdated
            };

            await transaction.CommitAsync();
            return (response, newRefresh);
        }

        private async Task<RegisterResponse> ContinueExistingRegistrationAsync(User existingUser)
        {
            if (existingUser.IsEmailConfirmed)
            {
                return new RegisterResponse
                {
                    IsSuccess = false,
                    Message = RegistrationMessages.ExistingAccountGeneric
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
                RequiresEmailVerification = otpResponse.CanVerifyExistingOtp,
                CanVerifyExistingOtp = otpResponse.CanVerifyExistingOtp,
                RetryAfterSeconds = otpResponse.RetryAfterSeconds
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
                    return ExternalLoginMessages.DefaultMemberRoleMissing;

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
                return PasswordMessages.PasswordRequired;

            if (password.Length > 128)
                return PasswordMessages.PasswordTooLong;

            if (password.Length < 8 ||
                !password.Any(char.IsUpper) ||
                !password.Any(char.IsLower) ||
                !password.Any(char.IsDigit) ||
                !password.Any(c => !char.IsLetterOrDigit(c)))
            {
                return PasswordMessages.PasswordPolicy;
            }

            if (!string.Equals(password, confirmPassword, StringComparison.Ordinal))
                return PasswordMessages.PasswordsDoNotMatch;

            return null;
        }

        private static string? ValidateRegistrationRequest(RegisterRequest request)
        {
            if (request == null)
                return RegistrationMessages.DetailsRequired;

            if (string.IsNullOrWhiteSpace(request.FullName))
                return ValidationMessages.FullNameRequired;

            if (request.FullName.Trim().Length > 100)
                return ValidationMessages.FullNameMaxLength;

            var email = request.Email?.Trim();
            if (string.IsNullOrWhiteSpace(email) || !new EmailAddressAttribute().IsValid(email))
                return ValidationMessages.InvalidEmail;

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
                Message = AuthMessages.LoginSuccessful,

            };
        }

        private async Task<List<string>> GetRoles(Guid userId)
        {
            // JWT role claims are authorization identifiers, so use the immutable
            // role code (for example SUPERADMIN), not the display name (SuperAdmin).
            return await _db.UserRoles
                .Where(x => x.UserId == userId)
                .Select(x => x.Role.Code)
                .ToListAsync();
        }

        private async Task<List<string>> GetPermissions(Guid userId)
        {
            return await _db.UserRoles
                .Where(x => x.UserId == userId)
                .SelectMany(x => x.Role.RolePermissions)
                .Select(x => x.Permission.Code)
                .Distinct()
                .ToListAsync();
        }

    }
}
