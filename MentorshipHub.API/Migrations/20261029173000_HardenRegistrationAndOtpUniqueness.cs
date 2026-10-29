using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    public partial class HardenRegistrationAndOtpUniqueness : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Do not silently delete preserved accounts if historical email casing created duplicates.
            migrationBuilder.Sql(@"
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ""Users""
        GROUP BY lower(btrim(""Email""))
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'Cannot normalize user email addresses: duplicate emails exist ignoring case or surrounding spaces. Resolve duplicate Users rows before rerunning this migration.';
    END IF;
END $$;

UPDATE ""Users""
SET ""Email"" = lower(btrim(""Email""))
WHERE ""Email"" <> lower(btrim(""Email""));

CREATE UNIQUE INDEX ""IX_Users_Email_Normalized""
ON ""Users"" (lower(""Email""));");

            // OTP rows are short-lived security data. Keep only the newest row per email before
            // adding uniqueness; this invalidates any older duplicate OTPs safely.
            migrationBuilder.Sql(@"
DELETE FROM ""EmailVerificationOtps"" AS old
USING ""EmailVerificationOtps"" AS newer
WHERE lower(btrim(old.""Email"")) = lower(btrim(newer.""Email""))
  AND (
      newer.""CreatedAt"" > old.""CreatedAt""
      OR (newer.""CreatedAt"" = old.""CreatedAt"" AND newer.""Id"" > old.""Id"")
  );

UPDATE ""EmailVerificationOtps""
SET ""Email"" = lower(btrim(""Email""))
WHERE ""Email"" <> lower(btrim(""Email""));");

            migrationBuilder.CreateIndex(
                name: "IX_EmailVerificationOtps_Email",
                table: "EmailVerificationOtps",
                column: "Email",
                unique: true);

            // Retain only the newest unused MFA OTP per user before enforcing one active OTP.
            migrationBuilder.Sql(@"
WITH ranked AS (
    SELECT ""Id"",
           row_number() OVER (PARTITION BY ""UserId"" ORDER BY ""CreatedAt"" DESC, ""Id"" DESC) AS rn
    FROM ""MfaOtps""
    WHERE ""IsUsed"" = FALSE
)
UPDATE ""MfaOtps"" AS otp
SET ""IsUsed"" = TRUE
FROM ranked
WHERE ranked.""Id"" = otp.""Id""
  AND ranked.rn > 1;");

            migrationBuilder.CreateIndex(
                name: "IX_MfaOtps_UserId_Active",
                table: "MfaOtps",
                column: "UserId",
                unique: true,
                filter: "\"IsUsed\" = FALSE");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_MfaOtps_UserId_Active",
                table: "MfaOtps");

            migrationBuilder.DropIndex(
                name: "IX_EmailVerificationOtps_Email",
                table: "EmailVerificationOtps");

            migrationBuilder.Sql(@"DROP INDEX IF EXISTS ""IX_Users_Email_Normalized"";");
        }
    }
}
