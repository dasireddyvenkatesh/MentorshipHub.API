using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    public partial class BackfillMissingUserDefaults : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // A cleaned development database may retain Users and Roles while child tables
            // have been cleared. Restore only missing defaults; never replace existing roles.
            migrationBuilder.Sql(@"
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ""Users"" AS u
        WHERE NOT EXISTS (
            SELECT 1 FROM ""UserRoles"" AS ur WHERE ur.""UserId"" = u.""Id""
        )
    ) AND NOT EXISTS (
        SELECT 1 FROM ""Roles"" WHERE ""Code"" = 'MEMBER'
    ) THEN
        RAISE EXCEPTION 'Cannot backfill role-less users because the MEMBER role is missing. Seed the standard roles and rerun the migration.';
    END IF;
END $$;

INSERT INTO ""UserProfiles""
    (""UserId"", ""FirstName"", ""LastName"", ""PhoneNumber"", ""ProfileImageUrl"", ""Bio"")
SELECT u.""Id"", '', '', NULL, NULL, NULL
FROM ""Users"" AS u
WHERE NOT EXISTS (
    SELECT 1 FROM ""UserProfiles"" AS p WHERE p.""UserId"" = u.""Id""
)
ON CONFLICT (""UserId"") DO NOTHING;

INSERT INTO ""UserSecuritySettings""
    (""UserId"", ""MfaEnabled"", ""AccessFailedCount"", ""LockoutEnd"")
SELECT u.""Id"", FALSE, 0, NULL
FROM ""Users"" AS u
WHERE NOT EXISTS (
    SELECT 1 FROM ""UserSecuritySettings"" AS settings WHERE settings.""UserId"" = u.""Id""
)
ON CONFLICT (""UserId"") DO NOTHING;

INSERT INTO ""UserRoles"" (""UserId"", ""RoleId"")
SELECT u.""Id"", member.""Id""
FROM ""Users"" AS u
CROSS JOIN ""Roles"" AS member
WHERE member.""Code"" = 'MEMBER'
  AND NOT EXISTS (
      SELECT 1 FROM ""UserRoles"" AS ur WHERE ur.""UserId"" = u.""Id""
  )
ON CONFLICT (""UserId"", ""RoleId"") DO NOTHING;");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Intentionally no-op: removing these defaults during rollback could break existing users.
        }
    }
}
