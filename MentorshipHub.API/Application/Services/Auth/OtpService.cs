using Azure;
using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Email;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class OtpService : IOtpService
    {
        private readonly IPasswordHasher _hasher;
        private readonly AppDbContext _db;
        private readonly IEmailService _emailService;
        private readonly IEmailTemplateService _emailTemplateService;

        public OtpService(
            IPasswordHasher hasher,
            AppDbContext db,
            IEmailService emailService,
            IEmailTemplateService emailTemplateService)
        {
            _hasher = hasher;
            _db = db;
            _emailService = emailService;
            _emailTemplateService = emailTemplateService;
        }

        public async Task<EmailOtpResponse> GenerateEmailVerificationOtp(string name, string email, bool isResend = false)
        {
            email = email.Trim().ToLowerInvariant();
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
                return new EmailOtpResponse { IsSuccess = false, Message = $"Too many failed attempts. Try again in {minutes} minutes." };
            }

            if (existing != null && existing.CreatedAt.AddSeconds(60) > now)
            {
                var seconds = Math.Ceiling((existing.CreatedAt.AddSeconds(60) - now).TotalSeconds);
                return new EmailOtpResponse { IsSuccess = false, Message = $"Please wait {seconds} seconds before requesting another code." };
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
                    return new EmailOtpResponse { IsSuccess = false, Message = "Hourly OTP limit reached. Please try again later." };

                if (existing.DailySendCount >= 10)
                    return new EmailOtpResponse { IsSuccess = false, Message = "Daily OTP limit reached. Try again tomorrow." };

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

            var template = isResend
                ? _emailTemplateService.BuildResendOtp(name, code)
                : _emailTemplateService.BuildRegistrationOtp(name, code);

            var sent = await _emailService.SendEmail(email, template.subject, template.body);
            if (!sent)
            {
                return new EmailOtpResponse { IsSuccess = false, Message = "We couldn't send the verification email. Please try again later." };
            }

            return new EmailOtpResponse { IsSuccess = true, Message = "Verification code sent to your email." };
        }

        public async Task<MfaOtpResponse> GenerateMfaOtp(Guid userId)
        {
            var user = await _db.Users.FindAsync(userId);

            if (user == null)
            {
                return new MfaOtpResponse
                {
                    IsSuccess = false,
                    Message = "User not found."
                };
            }

            var existing = await _db.MfaOtps
                .FirstOrDefaultAsync(x => x.UserId == userId && !x.IsUsed);

            if (existing != null)
            {
                if (existing.LockedUntil.HasValue && existing.LockedUntil > DateTime.UtcNow)
                {
                    var minutes = (existing.LockedUntil.Value - DateTime.UtcNow).TotalMinutes;

                    return new MfaOtpResponse
                    {
                        IsSuccess = false,
                        Message = $"Too many failed attempts. Try again in {Math.Ceiling(minutes)} minutes."
                    };
                }

                if (existing.CreatedAt.AddSeconds(60) > DateTime.UtcNow)
                {
                    return new MfaOtpResponse
                    {
                        IsSuccess = false,
                        Message = "Please wait before requesting another OTP."
                    };
                }
            }

            string code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
            string hash = _hasher.Hash(code);

            if (existing != null)
            {
                existing.CodeHash = hash;
                existing.ExpiresAt = DateTime.UtcNow.AddMinutes(10);
                existing.CreatedAt = DateTime.UtcNow;
            }
            else
            {
                _db.MfaOtps.Add(new MfaOtp
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    CodeHash = hash,
                    AttemptCount = 0,
                    MaxAttempts = 5,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                    CreatedAt = DateTime.UtcNow
                });
            }

            await _db.SaveChangesAsync();

            var template = _emailTemplateService.BuildMfaOtp(user.Username, code);

            var response = await _emailService.SendEmail(user.Email, template.subject, template.body);

            if (!response)
            {
                return new MfaOtpResponse
                {
                    IsSuccess = false,
                    Message = "Failed to send OTP email. Please try again later."
                };
            }

            return new MfaOtpResponse
            {
                IsSuccess = true,
                Message = "Verification code sent to your email."
            };
        }
    }
}