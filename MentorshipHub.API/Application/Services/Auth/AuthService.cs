using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Commom;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using MentorshipHub.API.Infrastructure.EntityModels.Profile;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.ComponentModel.DataAnnotations;

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

        public AuthService(AppDbContext db, IJwtTokenService jwt, IPasswordHasher hasher,
                            IUserSessionService sessions, IOtpService otp, IPublicIdService publicIdService)
        {
            _db = db;
            _jwt = jwt;
            _hasher = hasher;
            _sessions = sessions;
            _otp = otp;
            _publicIdService = publicIdService;
        }

        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
                return new LoginResponse { IsSuccess = false, Message = "Email and password are required." };

            var email = request.Email.Trim().ToLowerInvariant();

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

            if (user == null || user.PasswordHash == null || !_hasher.Verify(user.PasswordHash, request.Password))
                return new LoginResponse { IsSuccess = false, Message = "Invalid email or password." };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = "Account is inactive." };

            var relatedRecordsError = await EnsureUserRelatedRecordsAsync(user);
            if (relatedRecordsError != null)
                return new LoginResponse { IsSuccess = false, Message = relatedRecordsError };

            // EMAIL VERIFICATION
            if (!user.IsEmailConfirmed)
            {
                var otpResponse = await _otp.GenerateEmailVerificationOtp(user.Username, user.Email);

                return new LoginResponse
                {
                    IsSuccess = otpResponse.IsSuccess,
                    RequiresEmailVerification = true,
                    Email = user.Email,
                    Message = otpResponse.Message
                };
            }

            // MFA
            if (user.SecuritySetting?.MfaEnabled == true)
            {
                var otpResponse = await _otp.GenerateMfaOtp(user.Id);

                return new LoginResponse
                {
                    IsSuccess = otpResponse.IsSuccess,
                    RequiresMfa = otpResponse.IsSuccess,
                    UserId = user.Id,
                    Email = user.Email,
                    Message = otpResponse.Message
                };
            }

            return await CreateSession(user, request);
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
                PasswordHash = _hasher.Hash(request.Password),
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
            var email = request.Email.Trim().ToLowerInvariant();

            // 1️⃣ Check if this external provider is already linked
            var externalLogin = await _db.ExternalLogins
                .Include(x => x.User)
                .ThenInclude(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x =>
                    x.Provider == request.Provider &&
                    x.ProviderUserId == request.ProviderId);

            User? user;

            if (externalLogin != null)
            {
                // External account already linked
                user = externalLogin.User;
            }
            else
            {
                // 2️⃣ Check if a user already exists with this email
                 user = await _db.Users
                    .Include(x => x.SecuritySetting)
                    .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

                if (user == null)
                {
                    var memberRole = await _db.Roles.FirstOrDefaultAsync(x => x.Code == "MEMBER");
                    if (memberRole == null)
                    {
                        return new LoginResponse { IsSuccess = false, Message = "The default Member role is not configured. Please contact support." };
                    }

                    try
                    {
                        user = await CreateNewUserAsync(request, email, memberRole);
                    }
                    catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
                    {
                        // Another OAuth callback may have created this email just before this request.
                        _db.ChangeTracker.Clear();
                        user = await _db.Users
                            .Include(x => x.SecuritySetting)
                            .FirstOrDefaultAsync(x => x.Email.ToLower() == email);

                        if (user == null)
                            throw;
                    }
                }

                // 3️⃣ Link the external provider
                var newExternalLogin = new ExternalLogin
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Provider = request.Provider,
                    ProviderUserId = request.ProviderId,
                    CreatedAt = DateTime.UtcNow
                };

                await _db.ExternalLogins.AddAsync(newExternalLogin);
                try
                {
                    await _db.SaveChangesAsync();
                }
                catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
                {
                    // A second OAuth callback may have inserted the provider link concurrently.
                    _db.ChangeTracker.Clear();
                    externalLogin = await _db.ExternalLogins
                        .Include(x => x.User)
                        .ThenInclude(x => x.SecuritySetting)
                        .FirstOrDefaultAsync(x => x.Provider == request.Provider && x.ProviderUserId == request.ProviderId);

                    if (externalLogin == null)
                        throw;

                    user = externalLogin.User;
                }
            }

            // 4️⃣ Prevent login if account inactive
            if (!user.IsActive)
            {
                return new LoginResponse
                {
                    IsSuccess = false,
                    Message = "Account is inactive"
                };
            }

            var relatedRecordsError = await EnsureUserRelatedRecordsAsync(user);
            if (relatedRecordsError != null)
                return new LoginResponse { IsSuccess = false, Message = relatedRecordsError };

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                var response = await _otp.GenerateMfaOtp(user.Id);

                return new LoginResponse
                {
                    RequiresMfa = response.IsSuccess,
                    UserId = user.Id,
                    Email = user.Email,
                    IsSuccess = response.IsSuccess,
                    Message = response.Message
                };
            }

            // 5️⃣ Create session
            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId,
                DeviceName = request.DeviceName
            };

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

        public async Task<MfaOtpResponse> MfaOtpAsync(MfaOtpRequest request)
        {
            if (request == null || request.Id == Guid.Empty)
                return new MfaOtpResponse { IsSuccess = false, Message = "A valid MFA session is required." };

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Id == request.Id);

            if (user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true)
            {
                return new MfaOtpResponse { IsSuccess = false, Message = "MFA is not enabled for this account." };
            }

            return await _otp.GenerateMfaOtp(user.Id);
        }

        public async Task<LoginResponse> VerifyRegisterEmailOtp(VerifyEmailOtpRequest request)
        {
            var email = request.Email?.Trim().ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(request.OtpCode))
                return new LoginResponse { IsSuccess = false, Message = "Email and verification code are required." };

            var now = DateTime.UtcNow;
            var otp = await _db.EmailVerificationOtps.FirstOrDefaultAsync(x => x.Email.ToLower() == email);

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

            if (user.IsEmailConfirmed)
                return new LoginResponse { IsSuccess = false, Message = "Email is already verified. Please sign in." };

            otp.IsUsed = true;
            user.IsEmailConfirmed = true;
            await _db.SaveChangesAsync();

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                var mfaResponse = await _otp.GenerateMfaOtp(user.Id);
                return new LoginResponse
                {
                    IsSuccess = mfaResponse.IsSuccess,
                    RequiresMfa = mfaResponse.IsSuccess,
                    UserId = user.Id,
                    Email = user.Email,
                    Message = mfaResponse.Message
                };
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

            otp.IsUsed = true;
            user.IsEmailConfirmed = true;
            await _db.SaveChangesAsync();

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                var mfaResponse = await _otp.GenerateMfaOtp(user.Id);
                return new LoginResponse
                {
                    IsSuccess = mfaResponse.IsSuccess,
                    RequiresMfa = mfaResponse.IsSuccess,
                    UserId = user.Id,
                    Email = user.Email,
                    Message = mfaResponse.Message
                };
            }

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId ?? string.Empty,
                DeviceName = request.DeviceName
            };

            return await CreateSession(user, loginRequest);
        }

        public async Task<LoginResponse> VerifyMfaOtpAsync(VerifyMfaOtpRequest request)
        {
            if (request.UserId == Guid.Empty || string.IsNullOrWhiteSpace(request.Code))
                return new LoginResponse { IsSuccess = false, Message = "User and verification code are required." };

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Id == request.UserId);

            if (user == null || !user.IsActive || !user.IsEmailConfirmed ||
                user.SecuritySetting?.MfaEnabled != true)
            {
                return new LoginResponse { IsSuccess = false, Message = "MFA is not enabled for this account." };
            }

            var now = DateTime.UtcNow;
            var otp = await _db.MfaOtps
                .Where(x => x.UserId == request.UserId && !x.IsUsed)
                .OrderByDescending(x => x.CreatedAt)
                .FirstOrDefaultAsync();

            if (otp == null)
                return new LoginResponse { IsSuccess = false, Message = "OTP not found or already used. Request a new verification code." };

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

            if (!_hasher.Verify(otp.CodeHash, request.Code))
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

            otp.IsUsed = true;
            await _db.SaveChangesAsync();

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId ?? string.Empty,
                DeviceName = request.DeviceName
            };

            return await CreateSession(user, loginRequest);
        }

        public async Task<(RefreshTokenResponse response, string refreshToken)> RefreshAsync(string refreshToken)
        {
            if(string.IsNullOrEmpty(refreshToken))
                return (new RefreshTokenResponse { Message = "Refresh token missing" }, default!);

            var session = await _sessions.GetByTokenAsync(refreshToken);

            if (session == null || session.IsRevoked || session.ExpiresAt < DateTime.UtcNow)
                return (new RefreshTokenResponse { Message = "Login expired" }, default!);

            var user = await _db.Users.FindAsync(session.UserId);

            if(user == null || !user.IsActive)
                return (new RefreshTokenResponse { Message = "Account is inactive" }, default!);

            var roles = await GetRoles(user.Id);
            var permissions = await GetPermissions(user.Id);

            var newRefresh = _jwt.GenerateRefreshToken();

            await _sessions.RotateAsync(session, newRefresh);

            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions);

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

        private static string? ValidateRegistrationRequest(RegisterRequest request)
        {
            if (request == null)
                return "Registration details are required.";

            if (string.IsNullOrWhiteSpace(request.FullName))
                return "Full name is required.";

            if (request.FullName.Trim().Length > 25)
                return "Full name must be 25 characters or fewer.";

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

            var accessToken = _jwt.GenerateAccessToken(user, roles, permissions);
            var refreshToken = _jwt.GenerateRefreshToken();

            await _sessions.HandleLoginSessionAsync(user.Id, request, refreshToken);

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
