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

        public OtpService(IPasswordHasher hasher, AppDbContext db, IEmailService emailService, IEmailTemplateService emailTemplateService)
        {
            _hasher = hasher;
            _db = db;
            _emailService = emailService;
            _emailTemplateService = emailTemplateService;
        }

        public async Task<EmailOtpResponse> GenerateEmailVerificationOtp(string name, string email, bool isResend= false)
        {
            string code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();

            string hash = _hasher.Hash(code);

            var existing = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email == email);

            if (existing != null)
            {
                // Resend cooldown protection
                if (isResend && existing.CreatedAt.AddSeconds(60) > DateTime.UtcNow)
                {
                    return new EmailOtpResponse
                    {
                        Message = "Please wait before requesting another OTP."
                    };
                }

                existing.CodeHash = hash;
                existing.AttemptCount = 0;
                existing.ExpiresAt = DateTime.UtcNow.AddMinutes(10);
                existing.LockedUntil = null;
                existing.CreatedAt = DateTime.UtcNow;
            }
            else
            {
                var otp = new EmailVerificationOtp
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    CodeHash = hash,
                    AttemptCount = 0,
                    MaxAttempts = 5,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                    CreatedAt = DateTime.UtcNow
                };

                _db.EmailVerificationOtps.Add(otp);
            }

            await _db.SaveChangesAsync();

            var template = isResend
                ? _emailTemplateService.BuildResendOtp(name, code)
                : _emailTemplateService.BuildRegistrationOtp(name, code);

            await _emailService.SendEmail(email, template.subject, template.body);

            return new EmailOtpResponse
            {
                IsSuccess = true,
                Message = "Verification code sent successfully."
            };
        }
        public async Task<MfaOtpResponse> GenerateMfaOtp(Guid id)
        {

            string code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();

            string hash = _hasher.Hash(code);

            var existing = await _db.MfaOtps
                .FirstOrDefaultAsync(x => x.Id == id);

            if (existing != null)
            {
                existing.CodeHash = hash;
                existing.AttemptCount = 0;
                existing.ExpiresAt = DateTime.UtcNow.AddMinutes(10);
                existing.LockedUntil = null;
            }
            else
            {
                var otp = new MfaOtp
                {
                    Id = Guid.NewGuid(),
                    UserId = id,
                    CodeHash = hash,
                    AttemptCount = 0,
                    MaxAttempts = 5,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10),
                    CreatedAt = DateTime.UtcNow
                };

                _db.MfaOtps.Add(otp);
            }

            await _db.SaveChangesAsync();

            var user = await _db.Users.FindAsync(id);

            if(user == null)
            {
                return new MfaOtpResponse
                {
                    IsSuccess = false,
                    Message = "User not found"
                };
            }

            var template = _emailTemplateService.BuildRegistrationOtp(user.Username, code);

            await _emailService.SendEmail(user.Email, template.subject, template.body);

            return new MfaOtpResponse
            {
                IsSuccess = true,
                Message = "MFA OTP resent successfully"
            };
        }

    }
}
