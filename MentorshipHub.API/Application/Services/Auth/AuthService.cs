using MentorshipHub.API.Application.DTO.Auth;
using MentorshipHub.API.Application.Interfaces.Auth;
using MentorshipHub.API.Application.Interfaces.Commom;
using MentorshipHub.API.Enities;
using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using MentorshipHub.API.Infrastructure.EntityModels.Profile;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;

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
            var email = request.Email.ToLower().Trim();

            var user = await _db.Users
                .Include(x => x.SecuritySetting)
                .FirstOrDefaultAsync(x => x.Email == email);

            if (user == null || user.PasswordHash == null || !_hasher.Verify(user.PasswordHash, request.Password))
                return new LoginResponse { IsSuccess = false, Message = "Invalid email or password." };

            if (!user.IsActive)
                return new LoginResponse { IsSuccess = false, Message = "Account is inactive." };

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
                    RequiresMfa = true,
                    Email = user.Email,
                    Message = otpResponse.Message
                };
            }

            return await CreateSession(user, request);
        }


        public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
        {
            var email = request.Email.ToLower().Trim();

            var existingUser = await _db.Users
                .FirstOrDefaultAsync(x => x.Email == email);

            if (existingUser != null)
            {
                return new RegisterResponse
                {
                    IsSuccess = false,
                    Message = "Email already registered"
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

            var role = await _db.Roles
                .FirstOrDefaultAsync(x => x.Name == "Member");

            if (role != null)
            {
                await _db.UserRoles.AddAsync(new UserRole
                {
                    UserId = user.Id,
                    RoleId = role.Id
                });
            }

            await _db.SaveChangesAsync();

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
            var email = request.Email.Trim().ToLower();

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
                    .FirstOrDefaultAsync(x => x.Email == email);

                if (user == null)
                {
                    user = await CreateNewUserAsync(request, email);
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
                await _db.SaveChangesAsync();
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

            if (user.SecuritySetting?.MfaEnabled == true)
            {
                var response = await _otp.GenerateMfaOtp(user.Id);

                return new LoginResponse
                {
                    RequiresMfa = true,
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
            var user = await _db.Users.FirstOrDefaultAsync(x => x.Email == request.Email);

            if (user == null)
            {
                return new EmailOtpResponse
                {
                    IsSuccess = true,
                    Message = "If the account exists, a verification code has been sent."
                };
            }

            var response = await _otp.GenerateEmailVerificationOtp(user.Username, request.Email, true);

            return response;

        }

        public async Task<MfaOtpResponse> MfaOtpAsync(MfaOtpRequest request)
        {
            var response = await _otp.GenerateMfaOtp(request.Id);

            return response;

        }

        public async Task<VerifyEmailOtpResponse> VerifyRegisterEmailOtp(VerifyEmailOtpRequest request)
        {
            var otp = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email == request.Email);

            if (otp == null)
                return new VerifyEmailOtpResponse { Message = "OTP not found" };

            // Handle lock
            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil > DateTime.UtcNow)
                    return new VerifyEmailOtpResponse { Message = "Account locked temporarily" };

                // lock expired
                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt < DateTime.UtcNow)
                return new VerifyEmailOtpResponse { Message = "OTP expired" };

            // Verify OTP
            if (!_hasher.Verify(request.OtpCode, otp.CodeHash))
            {
                otp.AttemptCount++;

                if (otp.AttemptCount >= otp.MaxAttempts)
                    otp.LockedUntil = DateTime.UtcNow.AddHours(24);

                await _db.SaveChangesAsync();

                return new VerifyEmailOtpResponse { Message = "Invalid OTP" };

            }

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Email == request.Email);

            if (user == null)
                return new VerifyEmailOtpResponse { Message = "User not found" };

            user.IsEmailConfirmed = true;

            await _db.SaveChangesAsync();

            return new VerifyEmailOtpResponse
            {
                IsSuccess = true,
                Message = "Email verified successfully"
            };

        }

        public async Task<LoginResponse> VerifyEmailOtp(VerifyEmailOtpRequest request)
        {
            var otp = await _db.EmailVerificationOtps
                .FirstOrDefaultAsync(x => x.Email == request.Email);

            if (otp == null)
                return new LoginResponse { Message = "OTP not found" };

            // Handle lock
            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil > DateTime.UtcNow)
                    return new LoginResponse { Message = "Account locked temporarily" };

                // lock expired
                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt < DateTime.UtcNow)
                return new LoginResponse { Message = "OTP expired" };

            // Verify OTP
            if (!_hasher.Verify(request.OtpCode, otp.CodeHash))
            {
                otp.AttemptCount++;

                if (otp.AttemptCount >= otp.MaxAttempts)
                    otp.LockedUntil = DateTime.UtcNow.AddHours(24);

                await _db.SaveChangesAsync();

                return new LoginResponse { Message = "Invalid OTP" };
            }

            var user = await _db.Users
                .FirstOrDefaultAsync(x => x.Email == request.Email);

            if (user == null)
                return new LoginResponse { Message = "User not found" };

            user.IsEmailConfirmed = true;

            await _db.SaveChangesAsync();

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId,
                DeviceName = request.DeviceName
            };

            return await CreateSession(user, loginRequest);
        }

        public async Task<LoginResponse> VerifyMfaOtpAsync(VerifyMfaOtpRequest request)
        {
            var otp = await _db.MfaOtps
                .FirstOrDefaultAsync(x => x.UserId == request.UserId);

            if (otp == null)
                return new LoginResponse { Message = "OTP not found" };

            // Handle lock
            if (otp.LockedUntil.HasValue)
            {
                if (otp.LockedUntil > DateTime.UtcNow)
                    return new LoginResponse { Message = "Account locked temporarily" };

                // lock expired
                otp.AttemptCount = 0;
                otp.LockedUntil = null;
            }

            if (otp.ExpiresAt < DateTime.UtcNow)
                return new LoginResponse { Message = "OTP expired" };

            // Verify OTP
            if (!_hasher.Verify(request.Code, otp.CodeHash))
            {
                otp.AttemptCount++;

                if (otp.AttemptCount >= otp.MaxAttempts)
                    otp.LockedUntil = DateTime.UtcNow.AddHours(24);

                await _db.SaveChangesAsync();

                return new LoginResponse { Message = "Invalid OTP" };
            }

            var user = await _db.Users
                .FirstOrDefaultAsync(x => x.Id == request.UserId);

            if (user == null)
                return new LoginResponse { Message = "User not found" };

            await _db.SaveChangesAsync();

            var loginRequest = new LoginRequest
            {
                DeviceId = request.DeviceId,
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

        private async Task<User> CreateNewUserAsync(ExternalLoginRequest request, string email)
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

            var role = await _db.Roles
                .FirstOrDefaultAsync(x => x.Code == "MEMBER");

            if (role != null)
            {
                await _db.UserRoles.AddAsync(new UserRole
                {
                    UserId = user.Id,
                    RoleId = role.Id
                });
            }

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
