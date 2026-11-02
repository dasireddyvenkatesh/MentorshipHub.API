using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    public partial class RemoveLegacyMfaAndResetSessions : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Do not silently downgrade any user whose active TOTP secret still
            // uses the retired Data Protection format. Stop before changing data.
            migrationBuilder.Sql("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM "TotpCredentials"
                        WHERE "IsEnabled" = TRUE
                          AND (
                              "EncryptedSecret" IS NULL
                              OR "EncryptedSecret" NOT LIKE 'xqare:aesgcm:v1:%'
                          )
                    ) THEN
                        RAISE EXCEPTION 'Legacy TOTP secrets remain. Resolve these credentials before applying the authentication cutover.';
                    END IF;
                    IF EXISTS (
                        SELECT 1
                        FROM "UserSecuritySettings" s
                        WHERE s."MfaEnabled" = TRUE
                          AND NOT EXISTS (
                              SELECT 1
                              FROM "TotpCredentials" t
                              WHERE t."UserId" = s."UserId"
                                AND t."IsEnabled" = TRUE
                          )
                    ) THEN
                        RAISE EXCEPTION 'MFA-enabled accounts without an active TOTP credential remain. Resolve these accounts before applying the authentication cutover.';
                    END IF;
                END $;
                """);

            // Global sign-out: all users must authenticate again after deployment.
            migrationBuilder.Sql("""
                UPDATE "UserSessions"
                SET "IsRevoked" = TRUE,
                    "RevokedAt" = COALESCE("RevokedAt", CURRENT_TIMESTAMP)
                WHERE "IsRevoked" = FALSE OR "RevokedAt" IS NULL;
                """);

            migrationBuilder.Sql("""
                UPDATE "MfaLoginChallenges"
                SET "ConsumedAt" = COALESCE("ConsumedAt", CURRENT_TIMESTAMP)
                WHERE "ConsumedAt" IS NULL;
                """);

            // Incomplete enrollments restart after the user signs in again.
            migrationBuilder.Sql("""
                UPDATE "TotpCredentials"
                SET "PendingEncryptedSecret" = NULL,
                    "PendingEnrollmentExpiresAt" = NULL
                WHERE "PendingEncryptedSecret" IS NOT NULL
                   OR "PendingEnrollmentExpiresAt" IS NOT NULL;
                """);

            migrationBuilder.Sql("""
                UPDATE "TotpCredentials"
                SET "EncryptedSecret" = NULL
                WHERE "IsEnabled" = FALSE AND "EncryptedSecret" IS NOT NULL;
                """);

            // Remove the table used only by email-as-login-MFA.
            migrationBuilder.DropTable(name: "MfaOtps");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Recreates an empty legacy table only. Revoked sessions and consumed
            // challenges intentionally remain revoked if the migration is rolled back.
            migrationBuilder.CreateTable(
                name: "MfaOtps",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CodeHash = table.Column<string>(type: "text", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    MaxAttempts = table.Column<int>(type: "integer", nullable: false),
                    LockedUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaOtps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MfaOtps_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_MfaOtps_UserId_Active",
                table: "MfaOtps",
                column: "UserId",
                unique: true,
                filter: "\"IsUsed\" = FALSE");
        }
    }
}