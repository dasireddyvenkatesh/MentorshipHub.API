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
            var existing = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email == email && !x.IsUsed);

            if (existing != null)
            {
                if (existing.LockedUntil.HasValue && existing.LockedUntil > DateTime.UtcNow)
                {
                    var minutes = (existing.LockedUntil.Value - DateTime.UtcNow).TotalMinutes;

                    return new EmailOtpResponse
                    {
                        IsSuccess = false,
                        Message = $"Too many failed attempts. Try again in {Math.Ceiling(minutes)} minutes."
                    };
                }

                if (existing.CreatedAt.AddSeconds(60) > DateTime.UtcNow)
                {
                    return new EmailOtpResponse
                    {
                        IsSuccess = true,
                        Message = "OTP already sent. Please check your email."
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
                _db.EmailVerificationOtps.Add(new EmailVerificationOtp
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    CodeHash = hash,
                    AttemptCount = 0,
                    MaxAttempts = 5,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                    CreatedAt = DateTime.UtcNow
                });
            }

            await _db.SaveChangesAsync();

            var template = isResend
                ? _emailTemplateService.BuildResendOtp(name, code)
                : _emailTemplateService.BuildRegistrationOtp(name, code);

            var response = await _emailService.SendEmail(email, template.subject, template.body);

            if(!response)
            {
                return new EmailOtpResponse
                {
                    IsSuccess = false,
                    Message = "Failed to send OTP email. Please try again later."
                };
            }

            return new EmailOtpResponse
            {
                IsSuccess = true,
                Message = "Verification code sent to your email."
            };
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