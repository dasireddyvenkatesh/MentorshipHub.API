using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Email;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class OtpService : IOtpService
    {
        private readonly IPasswordHasher _hasher;
        private readonly AppDbContext _db;
        private readonly IEmailService _emailService;
        private readonly IEmailTemplateService _emailTemplateService;
        private readonly ILogger<OtpService> _logger;

        public OtpService(
            IPasswordHasher hasher,
            AppDbContext db,
            IEmailService emailService,
            IEmailTemplateService emailTemplateService,
            ILogger<OtpService> logger)
        {
            _hasher = hasher;
            _db = db;
            _emailService = emailService;
            _emailTemplateService = emailTemplateService;
            _logger = logger;
        }

        public async Task<EmailOtpResponse> GenerateEmailVerificationOtp(string name, string email, bool isResend = false)
        {
            email = email.Trim().ToLowerInvariant();
            await using var transaction = await _db.Database.BeginTransactionAsync();
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({email}))");
            var now = DateTime.UtcNow;

            // Keep counters on the latest record even after an OTP has been consumed,
            // so successful verification cannot reset the email's sending quota.
            var existing = await _db.EmailVerificationOtps
                .Where(x => x.Email == email)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync();

            if (existing?.LockedUntil is DateTime lockedUntil && lockedUntil > now)
            {
                var minutes = Math.Ceiling((lockedUntil - now).TotalMinutes);
                return new EmailOtpResponse
                {
                    IsSuccess = false,
                    CanVerifyExistingOtp = false,
                    RetryAfterSeconds = GetRetryAfterSeconds(lockedUntil, now),
                    Message = $"Too many failed attempts. Try again in {minutes} minutes."
                };
            }

            if (existing != null && existing.CreatedAt.AddSeconds(60) > now)
            {
                var retryAt = existing.CreatedAt.AddSeconds(60);
                var seconds = GetRetryAfterSeconds(retryAt, now);
                var canVerify = CanVerifyExistingOtp(existing, now);

                return new EmailOtpResponse
                {
                    IsSuccess = false,
                    CanVerifyExistingOtp = canVerify,
                    RetryAfterSeconds = seconds,
                    Message = $"Please wait {seconds} seconds before requesting another code."
                };
            }

            if (existing != null)
            {
                if (existing.HourlyWindowStartedAt == null || existing.HourlyWindowStartedAt.Value.AddHours(1) <= now)
                {
                    existing.HourlyWindowStartedAt = now;
                    existing.HourlySendCount = 0;
                }

                if (existing.DailyWindowStartedAt == null || existing.DailyWindowStartedAt.Value.AddHours(24) <= now)
                {
                    existing.DailyWindowStartedAt = now;
                    existing.DailySendCount = 0;
                }

                if (existing.HourlySendCount >= 5)
                {
                    var retryAt = existing.HourlyWindowStartedAt!.Value.AddHours(1);
                    var seconds = GetRetryAfterSeconds(retryAt, now);
                    return new EmailOtpResponse
                    {
                        IsSuccess = false,
                        CanVerifyExistingOtp = CanVerifyExistingOtp(existing, now),
                        RetryAfterSeconds = seconds,
                        Message = $"Hourly OTP limit reached. Please try again in {Math.Ceiling(seconds / 60d)} minutes."
                    };
                }

                if (existing.DailySendCount >= 10)
                {
                    var retryAt = existing.DailyWindowStartedAt!.Value.AddHours(24);
                    var seconds = GetRetryAfterSeconds(retryAt, now);
                    return new EmailOtpResponse
                    {
                        IsSuccess = false,
                        CanVerifyExistingOtp = CanVerifyExistingOtp(existing, now),
                        RetryAfterSeconds = seconds,
                        Message = $"Daily OTP limit reached. Please try again in {Math.Ceiling(seconds / 3600d)} hours."
                    };
                }

                existing.HourlySendCount++;
                existing.DailySendCount++;
            }

            string code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
            string hash = _hasher.Hash(code);

            if (existing != null)
            {
                existing.CodeHash = hash;
                existing.AttemptCount = 0;
                existing.MaxAttempts = 5;
                existing.ExpiresAt = now.AddMinutes(10);
                existing.CreatedAt = now;
                existing.IsUsed = false;
                existing.LockedUntil = null;
            }
            else
            {
                existing = new EmailVerificationOtp
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    CodeHash = hash,
                    AttemptCount = 0,
                    MaxAttempts = 5,
                    ExpiresAt = now.AddMinutes(10),
                    CreatedAt = now,
                    HourlySendCount = 1,
                    HourlyWindowStartedAt = now,
                    DailySendCount = 1,
                    DailyWindowStartedAt = now
                };
                _db.EmailVerificationOtps.Add(existing);
            }

            // Persist the quota before calling the email provider to prevent rapid retries
            // from bypassing limits when the provider is unavailable.
            await _db.SaveChangesAsync();
            await transaction.CommitAsync();

            var template = isResend
                ? _emailTemplateService.BuildResendOtp(name, code)
                : _emailTemplateService.BuildRegistrationOtp(name, code);

            bool sent;
            try
            {
                sent = await _emailService.SendEmail(email, template.subject, template.body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email verification OTP to {Email}.", email);
                sent = false;
            }

            if (!sent)
            {
                // The OTP was persisted before contacting the provider so the send quota
                // cannot be bypassed. Invalidate only this exact code, not a newer resend
                // that may have been created concurrently.
                await _db.EmailVerificationOtps
                    .Where(x => x.Email == email && x.CodeHash == hash && !x.IsUsed)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.IsUsed, true));

                return new EmailOtpResponse
                {
                    IsSuccess = false,
                    CanVerifyExistingOtp = false,
                    RetryAfterSeconds = 60,
                    Message = "We couldn't send the verification email. Please try again in 60 seconds."
                };
            }

            return new EmailOtpResponse
            {
                IsSuccess = true,
                CanVerifyExistingOtp = true,
                RetryAfterSeconds = 60,
                Message = "Verification code sent to your email."
            };
        }

        private static bool CanVerifyExistingOtp(EmailVerificationOtp? otp, DateTime now)
            => otp != null &&
               !otp.IsUsed &&
               otp.ExpiresAt > now &&
               (!otp.LockedUntil.HasValue || otp.LockedUntil.Value <= now);

        private static int GetRetryAfterSeconds(DateTime retryAt, DateTime now)
            => Math.Max(1, (int)Math.Ceiling((retryAt - now).TotalSeconds));

    }
}