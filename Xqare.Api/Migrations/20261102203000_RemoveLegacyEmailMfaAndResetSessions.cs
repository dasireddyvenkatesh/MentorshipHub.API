using Xqare.Api.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Xqare.Api.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261102203000_RemoveLegacyEmailMfaAndResetSessions")]
    public partial class RemoveLegacyEmailMfaAndResetSessions : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
UPDATE ""UserSessions""
SET ""IsRevoked"" = TRUE,
    ""RevokedAt"" = COALESCE(""RevokedAt"", NOW()),
    ""LastActivityAt"" = NOW()
WHERE ""IsRevoked"" = FALSE OR ""RevokedAt"" IS NULL;

UPDATE ""MfaLoginChallenges""
SET ""ConsumedAt"" = NOW()
WHERE ""ConsumedAt"" IS NULL;

UPDATE ""TotpCredentials""
SET ""EncryptedSecret"" = CASE
        WHEN ""EncryptedSecret"" IS NOT NULL
         AND ""EncryptedSecret"" NOT LIKE 'xqare:aesgcm:%' THEN NULL
        ELSE ""EncryptedSecret""
    END,
    ""PendingEncryptedSecret"" = CASE
        WHEN ""PendingEncryptedSecret"" IS NOT NULL
         AND ""PendingEncryptedSecret"" NOT LIKE 'xqare:aesgcm:%' THEN NULL
        ELSE ""PendingEncryptedSecret""
    END,
    ""PendingEnrollmentExpiresAt"" = CASE
        WHEN ""PendingEncryptedSecret"" IS NOT NULL
         AND ""PendingEncryptedSecret"" NOT LIKE 'xqare:aesgcm:%' THEN NULL
        ELSE ""PendingEnrollmentExpiresAt""
    END;
");

            migrationBuilder.DropTable(name: "MfaOtps");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
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
