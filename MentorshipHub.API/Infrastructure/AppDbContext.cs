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

        public DbSet<MfaOtp> MfaOtps { get; set; }
        public DbSet<EmailVerificationOtp> EmailVerificationOtps { get; set; }
        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }

        public DbSet<ExternalLogin> ExternalLogins { get; set; }

        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }

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

            builder.Entity<UserSession>()
                .HasKey(x => x.Id);

            builder.Entity<MfaOtp>()
                .HasKey(x => x.Id);

            builder.Entity<MfaOtp>()
                .HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);


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