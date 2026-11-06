using MentorshipHub.API.Infrastructure.EntityModels.Identity;
using MentorshipHub.API.Infrastructure.EntityModels.Profile;
using MentorshipHub.API.Infrastructure.EntityModels.Rbac;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Enities
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }


        public DbSet<User> Users { get; set; }
        public DbSet<UserProfile> UserProfiles { get; set; }

        public DbSet<UserSecuritySetting> UserSecuritySettings { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }

        public DbSet<TotpCredential> TotpCredentials { get; set; }
        public DbSet<MfaLoginChallenge> MfaLoginChallenges { get; set; }
        public DbSet<MfaRecoveryCode> MfaRecoveryCodes { get; set; }
        public DbSet<EmailVerificationOtp> EmailVerificationOtps { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        public DbSet<ExternalLogin> ExternalLogins { get; set; }

        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<RbacAuditLog> RbacAuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>(entity =>
            {
                entity.HasKey(x => x.Id);

                entity.Property(x => x.Email).IsRequired().HasMaxLength(256);
                entity.Property(x => x.Username).IsRequired().HasMaxLength(100);
                entity.Property(x => x.PasswordHash);

                entity.HasIndex(x => x.Email).IsUnique();

                entity.HasOne(x => x.Profile)
                      .WithOne(x => x.User)
                      .HasForeignKey<UserProfile>(x => x.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.HasOne(x => x.SecuritySetting)
                      .WithOne(x => x.User)
                      .HasForeignKey<UserSecuritySetting>(x => x.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(x => x.Sessions)
                      .WithOne(x => x.User)
                      .HasForeignKey(x => x.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<UserRole>(entity =>
            {
                entity.HasKey(x => new { x.UserId, x.RoleId });

                entity.HasOne(x => x.User)
                      .WithMany(x => x.UserRoles)
                      .HasForeignKey(x => x.UserId);

                entity.HasOne(x => x.Role)
                      .WithMany(x => x.UserRoles)
                      .HasForeignKey(x => x.RoleId);
            });


            builder.Entity<UserSecuritySetting>()
                .HasKey(x => x.UserId);


            builder.Entity<UserProfile>(entity =>
            {
                entity.HasKey(x => x.UserId);
                entity.Property(x => x.FirstName).IsRequired().HasMaxLength(200);
                entity.Property(x => x.LastName).IsRequired().HasMaxLength(200);
                entity.Property(x => x.PhoneNumber);
                entity.Property(x => x.Bio);
                entity.Property(x => x.ProfileImageUrl);
            });

            builder.Entity<EmailVerificationOtp>()
                .HasIndex(x => x.Email)
                .IsUnique()
                .HasDatabaseName("IX_EmailVerificationOtps_Email");

            builder.Entity<UserSession>()
                .HasKey(x => x.Id);



            builder.Entity<TotpCredential>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.Property(x => x.EncryptedSecret).HasMaxLength(2048);
                entity.Property(x => x.PendingEncryptedSecret).HasMaxLength(2048);
                entity.HasIndex(x => x.UserId)
                    .IsUnique()
                    .HasDatabaseName("IX_TotpCredentials_UserId");
                entity.HasOne(x => x.User)
                    .WithOne()
                    .HasForeignKey<TotpCredential>(x => x.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<MfaLoginChallenge>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.Property(x => x.TokenHash).IsRequired().HasMaxLength(128);
                entity.Property(x => x.Purpose).IsRequired().HasMaxLength(64);
                entity.Property(x => x.DeviceId).HasMaxLength(256);
                entity.Property(x => x.DeviceName).HasMaxLength(256);
                entity.Property(x => x.IpAddress).HasMaxLength(64);
                entity.Property(x => x.UserAgent).HasMaxLength(1024);
                entity.HasIndex(x => x.TokenHash)
                    .IsUnique()
                    .HasDatabaseName("IX_MfaLoginChallenges_TokenHash");
                entity.HasIndex(x => x.ExpiresAt)
                    .HasDatabaseName("IX_MfaLoginChallenges_ExpiresAt");
                entity.HasIndex(x => new { x.UserId, x.ExpiresAt })
                    .HasDatabaseName("IX_MfaLoginChallenges_UserId_ExpiresAt");
                entity.HasOne(x => x.User)
                    .WithMany()
                    .HasForeignKey(x => x.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<MfaRecoveryCode>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.Property(x => x.CodeHash).IsRequired().HasMaxLength(128);
                entity.HasIndex(x => x.CodeHash)
                    .IsUnique()
                    .HasDatabaseName("IX_MfaRecoveryCodes_CodeHash");
                entity.HasIndex(x => new { x.UserId, x.BatchId })
                    .HasDatabaseName("IX_MfaRecoveryCodes_UserId_BatchId");
                entity.HasOne(x => x.User)
                    .WithMany()
                    .HasForeignKey(x => x.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<PasswordResetToken>()
                .HasKey(x => x.Id);

            builder.Entity<PasswordResetToken>()
                .HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<ExternalLogin>()
                .HasKey(x => x.Id);

            builder.Entity<ExternalLogin>()
                .HasIndex(x => new { x.Provider, x.ProviderUserId })
                .IsUnique();

            builder.Entity<ExternalLogin>()
                .HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<Role>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.HasIndex(x => x.Code).IsUnique();
            });

            builder.Entity<Permission>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.HasIndex(x => x.Code).IsUnique();
            });


            builder.Entity<RbacAuditLog>(entity =>
            {
                entity.HasKey(x => x.Id);

                entity.Property(x => x.ActionCode)
                    .IsRequired()
                    .HasMaxLength(100);

                entity.Property(x => x.TargetType)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(x => x.BeforeData)
                    .HasColumnType("jsonb");

                entity.Property(x => x.AfterData)
                    .HasColumnType("jsonb");

                entity.Property(x => x.IpAddress).HasMaxLength(64);
                entity.Property(x => x.UserAgent).HasMaxLength(1024);
                entity.Property(x => x.CorrelationId).HasMaxLength(128);

                entity.HasIndex(x => x.CreatedAt)
                    .HasDatabaseName("IX_RbacAuditLogs_CreatedAt");

                entity.HasIndex(x => x.ActorUserId)
                    .HasDatabaseName("IX_RbacAuditLogs_ActorUserId");

                entity.HasIndex(x => x.TargetUserId)
                    .HasDatabaseName("IX_RbacAuditLogs_TargetUserId");

                entity.HasIndex(x => x.TargetRoleId)
                    .HasDatabaseName("IX_RbacAuditLogs_TargetRoleId");

                entity.HasIndex(x => x.ActionCode)
                    .HasDatabaseName("IX_RbacAuditLogs_ActionCode");

                entity.HasOne<User>()
                    .WithMany()
                    .HasForeignKey(x => x.ActorUserId)
                    .OnDelete(DeleteBehavior.SetNull);

                entity.HasOne<User>()
                    .WithMany()
                    .HasForeignKey(x => x.TargetUserId)
                    .OnDelete(DeleteBehavior.SetNull);

                entity.HasOne<Role>()
                    .WithMany()
                    .HasForeignKey(x => x.TargetRoleId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            builder.Entity<RolePermission>(entity =>
            {
                entity.HasKey(x => new { x.RoleId, x.PermissionId });

                entity.HasOne(x => x.Role)
                      .WithMany(x => x.RolePermissions)
                      .HasForeignKey(x => x.RoleId);

                entity.HasOne(x => x.Permission)
                      .WithMany(x => x.RolePermissions)
                      .HasForeignKey(x => x.PermissionId);
            });
        }
    }
}