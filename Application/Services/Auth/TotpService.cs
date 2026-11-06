using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QRCoder;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public sealed class TotpService : ITotpService
    {
        private const string Issuer = "XQARE";
        private const int PeriodSeconds = 30;
        private const int MaxFailedAttempts = 5;
        private static readonly TimeSpan FailedWindow = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
        private static readonly char[] Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();
        private readonly AppDbContext _db;
        private readonly ITotpSecretProtector _protector;

        public TotpService(AppDbContext db, ITotpSecretProtector protector)
        {
            _db = db;
            _protector = protector;
        }

        public Task<bool> IsEnabledAsync(Guid userId)
            => _db.TotpCredentials.AnyAsync(x => x.UserId == userId && x.IsEnabled);

        public async Task<TotpEnrollmentStartResponse> StartEnrollmentAsync(Guid userId, string email, bool allowReplace = false)
        {
            if (!_protector.IsProtectionConfigured)
            {
                return new TotpEnrollmentStartResponse
                {
                    IsSuccess = false,
                    Message = "Authenticator enrollment is unavailable until a valid AES-256 TOTP encryption key is configured in the API application settings."
                };
            }

            await using var transaction = await BeginTransactionIfNeededAsync();
            var lockKey = "totp:" + userId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var credential = await _db.TotpCredentials
                .FromSqlInterpolated($@"SELECT * FROM ""TotpCredentials"" WHERE ""UserId"" = {userId} FOR UPDATE")
                .FirstOrDefaultAsync();

            if (credential?.IsEnabled == true && !allowReplace)
                return new TotpEnrollmentStartResponse { IsSuccess = false, Message = "An authenticator is already enabled." };

            var secret = Base32Encode(RandomNumberGenerator.GetBytes(20));
            var now = DateTime.UtcNow;
            if (credential == null)
            {
                credential = new TotpCredential
                {
                    UserId = userId, IsEnabled = false,
                    PendingEncryptedSecret = _protector.Protect(secret, userId),
                    PendingEnrollmentExpiresAt = now.AddMinutes(10)
                };
                _db.TotpCredentials.Add(credential);
            }
            else
            {
                credential.PendingEncryptedSecret = _protector.Protect(secret, userId);
                credential.PendingEnrollmentExpiresAt = now.AddMinutes(10);
            }

            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();

            var label = Uri.EscapeDataString($"{Issuer}:{email.Trim()}");
            var issuer = Uri.EscapeDataString(Issuer);
            var uri = $"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
            var qrGenerator = new QRCodeGenerator();
            var qrData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            var qrBytes = new PngByteQRCode(qrData).GetGraphic(8);
            var qrDataUri = "data:image/png;base64," + Convert.ToBase64String(qrBytes);
            return new TotpEnrollmentStartResponse
            {
                IsSuccess = true, Message = "Scan the QR code with your authenticator app, then enter the current six-digit code to finish setup.",
                Secret = secret, ProvisioningUri = uri, QrCodeDataUri = qrDataUri
            };
        }

        public async Task<TotpEnrollmentConfirmResponse> ConfirmEnrollmentAsync(Guid userId, string code)
        {
            if (!IsSixDigitCode(code))
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = "Enter the six-digit code from your authenticator app." };

            await using var transaction = await BeginTransactionIfNeededAsync();
            var lockKey = "totp:" + userId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var credential = await _db.TotpCredentials
                .FromSqlInterpolated($@"SELECT * FROM ""TotpCredentials"" WHERE ""UserId"" = {userId} FOR UPDATE")
                .FirstOrDefaultAsync();

            var now = DateTime.UtcNow;
            if (credential?.PendingEncryptedSecret == null || credential.PendingEnrollmentExpiresAt == null ||
                credential.PendingEnrollmentExpiresAt <= now)
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = "Your authenticator setup has expired. Start enrollment again." };
            if (credential.LockoutEnd.HasValue && credential.LockoutEnd.Value > now)
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = "Authenticator setup is temporarily locked. Try again later." };

            var pendingSecret = _protector.Unprotect(credential.PendingEncryptedSecret, userId);
            var matchedStep = FindMatchingTimeStep(pendingSecret, code, now);
            if (matchedStep == null)
            {
                RegisterFailedAttempt(credential, now);
                await _db.SaveChangesAsync();
                if (transaction != null) await transaction.CommitAsync();
                return new TotpEnrollmentConfirmResponse
                {
                    IsSuccess = false,
                    Message = credential.LockoutEnd.HasValue && credential.LockoutEnd.Value > now
                        ? "Too many incorrect codes. Authenticator setup is temporarily locked."
                        : "The authenticator code is incorrect. Check your device time and try again."
                };
            }

            credential.EncryptedSecret = _protector.Protect(pendingSecret, userId);
            credential.PendingEncryptedSecret = null;
            credential.PendingEnrollmentExpiresAt = null;
            credential.IsEnabled = true;
            credential.EnabledAt = now;
            credential.DisabledAt = null;
            credential.LastAcceptedTimeStep = matchedStep.Value;
            credential.FailedAttemptCount = 0;
            credential.FailedAttemptWindowStartedAt = null;
            credential.LockoutEnd = null;

            var settings = await _db.UserSecuritySettings.FirstOrDefaultAsync(x => x.UserId == userId);
            if (settings == null) _db.UserSecuritySettings.Add(new UserSecuritySetting { UserId = userId, MfaEnabled = true });
            else settings.MfaEnabled = true;

            var codes = await ReplaceRecoveryCodesAsync(userId, now);
            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();
            return new TotpEnrollmentConfirmResponse
            {
                IsSuccess = true, Message = "Authenticator enabled successfully. Save these recovery codes now; they will only be displayed once.",
                RecoveryCodes = codes
            };
        }

        public async Task<TotpStatusResponse> GetStatusAsync(Guid userId)
        {
            var credential = await _db.TotpCredentials.AsNoTracking().FirstOrDefaultAsync(x => x.UserId == userId);
            var remaining = await _db.MfaRecoveryCodes.CountAsync(x =>
                x.UserId == userId && x.UsedAt == null && x.InvalidatedAt == null);
            return new TotpStatusResponse
            {
                IsSuccess = true, Message = "Authenticator status retrieved.",
                IsEnabled = credential?.IsEnabled == true, CanEnroll = _protector.IsProtectionConfigured,
                EnabledAt = credential?.EnabledAt,
                RecoveryCodesRemaining = remaining
            };
        }

        public async Task<TotpEnrollmentConfirmResponse> RegenerateRecoveryCodesAsync(Guid userId, string code)
        {
            if (!IsSixDigitCode(code))
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = "Enter the current six-digit authenticator code." };
            await using var transaction = await BeginTransactionIfNeededAsync();
            var verification = await VerifyCodeAndConsumeAsync(userId, code);
            if (!verification.IsValid)
                return new TotpEnrollmentConfirmResponse { IsSuccess = false, Message = verification.Message };
            var codes = await ReplaceRecoveryCodesAsync(userId, DateTime.UtcNow);
            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();
            return new TotpEnrollmentConfirmResponse
            {
                IsSuccess = true, Message = "New recovery codes generated. Previous unused codes are no longer valid.",
                RecoveryCodes = codes
            };
        }

        public async Task<TotpVerificationResult> VerifyCodeAndConsumeAsync(Guid userId, string code)
        {
            if (!IsSixDigitCode(code)) return new TotpVerificationResult(false, "Enter a valid six-digit authenticator code.");
            await using var transaction = await BeginTransactionIfNeededAsync();
            var credential = await _db.TotpCredentials
                .FromSqlInterpolated($@"SELECT * FROM ""TotpCredentials"" WHERE ""UserId"" = {userId} FOR UPDATE")
                .FirstOrDefaultAsync();
            var now = DateTime.UtcNow;
            if (credential?.IsEnabled != true || string.IsNullOrWhiteSpace(credential.EncryptedSecret))
                return new TotpVerificationResult(false, "Authenticator is not enabled for this account.");
            if (credential.LockoutEnd.HasValue && credential.LockoutEnd.Value > now)
                return new TotpVerificationResult(false, "Authenticator verification is temporarily locked. Try again later.");

            var encryptedSecret = credential.EncryptedSecret;
            var secret = _protector.Unprotect(encryptedSecret, userId);
            var step = FindMatchingTimeStep(secret, code, now);
            var needsReprotection = _protector.IsProtectionConfigured && !_protector.IsUsingActiveKey(encryptedSecret);
            if (step == null || (credential.LastAcceptedTimeStep.HasValue && step.Value <= credential.LastAcceptedTimeStep.Value))
            {
                if (needsReprotection)
                    credential.EncryptedSecret = _protector.Protect(secret, userId);

                RegisterFailedAttempt(credential, now);
                await _db.SaveChangesAsync();
                if (transaction != null) await transaction.CommitAsync();
                return new TotpVerificationResult(false,
                    credential.LockoutEnd.HasValue && credential.LockoutEnd.Value > now
                        ? "Too many incorrect codes. Authenticator verification is temporarily locked."
                        : "The authenticator code is invalid or has already been used.");
            }

            if (needsReprotection)
                credential.EncryptedSecret = _protector.Protect(secret, userId);

            credential.LastAcceptedTimeStep = step.Value;
            credential.FailedAttemptCount = 0;
            credential.FailedAttemptWindowStartedAt = null;
            credential.LockoutEnd = null;
            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();
            return new TotpVerificationResult(true, "Authenticator code verified.");
        }

        public async Task<bool> ConsumeRecoveryCodeAsync(Guid userId, string code)
        {
            var normalized = NormalizeCode(code);
            if (normalized.Length < 20) return false;
            await using var transaction = await BeginTransactionIfNeededAsync();
            var hash = HashCode(normalized);
            var record = await _db.MfaRecoveryCodes
                .FromSqlInterpolated($@"SELECT * FROM ""MfaRecoveryCodes""
                    WHERE ""UserId"" = {userId} AND ""CodeHash"" = {hash}
                    AND ""UsedAt"" IS NULL AND ""InvalidatedAt"" IS NULL FOR UPDATE")
                .FirstOrDefaultAsync();
            if (record == null) return false;
            record.UsedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();
            return true;
        }

        public async Task DisableAsync(Guid userId)
        {
            await using var transaction = await BeginTransactionIfNeededAsync();
            var lockKey = "totp:" + userId.ToString("N");
            await _db.Database.ExecuteSqlInterpolatedAsync($"SELECT pg_advisory_xact_lock(hashtext({lockKey}))");
            var credential = await _db.TotpCredentials
                .FromSqlInterpolated($@"SELECT * FROM ""TotpCredentials"" WHERE ""UserId"" = {userId} FOR UPDATE")
                .FirstOrDefaultAsync();
            if (credential == null || !credential.IsEnabled)
                throw new InvalidOperationException("Authenticator is not enabled.");

            var now = DateTime.UtcNow;
            credential.IsEnabled = false;
            credential.EncryptedSecret = null;
            credential.PendingEncryptedSecret = null;
            credential.PendingEnrollmentExpiresAt = null;
            credential.DisabledAt = now;
            credential.LastAcceptedTimeStep = null;
            credential.FailedAttemptCount = 0;
            credential.FailedAttemptWindowStartedAt = null;
            credential.LockoutEnd = null;
            var settings = await _db.UserSecuritySettings.FirstOrDefaultAsync(x => x.UserId == userId);
            if (settings != null) settings.MfaEnabled = false;
            var codes = await _db.MfaRecoveryCodes
                .Where(x => x.UserId == userId && x.UsedAt == null && x.InvalidatedAt == null).ToListAsync();
            foreach (var item in codes) item.InvalidatedAt = now;
            await _db.SaveChangesAsync();
            if (transaction != null) await transaction.CommitAsync();
        }

        private async Task<List<string>> ReplaceRecoveryCodesAsync(Guid userId, DateTime now)
        {
            var active = await _db.MfaRecoveryCodes
                .Where(x => x.UserId == userId && x.UsedAt == null && x.InvalidatedAt == null).ToListAsync();
            foreach (var item in active) item.InvalidatedAt = now;
            var batch = Guid.NewGuid();
            var result = new List<string>(10);
            for (var i = 0; i < 10; i++)
            {
                var code = FormatCode(Base32Encode(RandomNumberGenerator.GetBytes(16)));
                result.Add(code);
                _db.MfaRecoveryCodes.Add(new MfaRecoveryCode
                {
                    UserId = userId, BatchId = batch, CodeHash = HashCode(NormalizeCode(code))
                });
            }
            return result;
        }

        private static void RegisterFailedAttempt(TotpCredential credential, DateTime now)
        {
            if (credential.FailedAttemptWindowStartedAt == null ||
                credential.FailedAttemptWindowStartedAt.Value.Add(FailedWindow) <= now)
            {
                credential.FailedAttemptWindowStartedAt = now;
                credential.FailedAttemptCount = 0;
                credential.LockoutEnd = null;
            }
            credential.FailedAttemptCount++;
            if (credential.FailedAttemptCount >= MaxFailedAttempts) credential.LockoutEnd = now.Add(LockoutDuration);
        }

        private static bool IsSixDigitCode(string? value)
            => value is { Length: 6 } && value.All(c => c is >= '0' and <= '9');

        private static long? FindMatchingTimeStep(string secret, string code, DateTime now)
        {
            var current = new DateTimeOffset(DateTime.SpecifyKind(now, DateTimeKind.Utc)).ToUnixTimeSeconds() / PeriodSeconds;
            for (var step = current - 1; step <= current + 1; step++)
            {
                if (step < 0) continue;
                var expected = GenerateCode(secret, step);
                if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(code)))
                    return step;
            }
            return null;
        }

        private static string GenerateCode(string secret, long step)
        {
            var counter = BitConverter.GetBytes(step);
            if (BitConverter.IsLittleEndian) Array.Reverse(counter);
            using var hmac = new HMACSHA1(Base32Decode(secret));
            var hash = hmac.ComputeHash(counter);
            var offset = hash[^1] & 0x0F;
            var binary = ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset + 1] & 0xff) << 16) |
                         ((hash[offset + 2] & 0xff) << 8) |
                         (hash[offset + 3] & 0xff);
            return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
        }

        private static string Base32Encode(byte[] data)
        {
            var builder = new StringBuilder((data.Length * 8 + 4) / 5);
            var buffer = 0;
            var bits = 0;
            foreach (var value in data)
            {
                buffer = (buffer << 8) | value;
                bits += 8;
                while (bits >= 5)
                {
                    builder.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                    bits -= 5;
                }
            }
            if (bits > 0) builder.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
            return builder.ToString();
        }

        private static byte[] Base32Decode(string value)
        {
            var result = new List<byte>();
            var buffer = 0;
            var bits = 0;
            foreach (var character in value.TrimEnd('=').ToUpperInvariant())
            {
                var index = Array.IndexOf(Base32Alphabet, character);
                if (index < 0) throw new FormatException("Invalid Base32 secret.");
                buffer = (buffer << 5) | index;
                bits += 5;
                if (bits >= 8)
                {
                    result.Add((byte)((buffer >> (bits - 8)) & 0xff));
                    bits -= 8;
                }
            }
            return result.ToArray();
        }

        private static string NormalizeCode(string? input)
            => new((input ?? string.Empty).Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
        private static string FormatCode(string value)
            => string.Join("-", Enumerable.Range(0, (value.Length + 3) / 4).Select(i => value.Substring(i * 4, Math.Min(4, value.Length - i * 4))));
        private static string HashCode(string value)
            => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        private async Task<IDbContextTransaction?> BeginTransactionIfNeededAsync()
            => _db.Database.CurrentTransaction == null ? await _db.Database.BeginTransactionAsync() : null;
    }
}
