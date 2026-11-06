using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261106150000_AddPermissionDescriptions")]
    public partial class AddPermissionDescriptions : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Permissions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.Sql("""
                UPDATE "Permissions"
                SET "Description" = CASE "Code"
                    WHEN 'ADMIN_OVERVIEW_VIEW' THEN 'Allows an administrator to view the Admin Overview dashboard, including the administrative summary and high-level platform metrics. It does not grant access to manage users or roles.'
                    WHEN 'ADMIN_USERS_VIEW' THEN 'Allows an administrator to view the user directory, search and filter users, and open individual user details. It is read-only and does not allow enabling or disabling accounts.'
                    WHEN 'ADMIN_USERS_MANAGE' THEN 'Allows an administrator to change a user account''s active or disabled status. The API prevents an administrator from disabling their own account and protects the last Super Admin. It does not grant access to edit profile details or credentials.'
                    WHEN 'RBAC_ROLES_VIEW' THEN 'Allows an administrator to view the role catalogue and role-level summary information, including whether a role is system-defined and its assignment and permission counts. It does not allow role changes.'
                    WHEN 'RBAC_ROLES_MANAGE' THEN 'Allows an administrator to create custom roles, rename custom roles, and delete eligible custom roles. System roles and SUPERADMIN are protected. A role cannot be deleted while users are assigned to it. This permission does not itself grant permission assignment or user-role assignment.'
                    WHEN 'RBAC_PERMISSIONS_VIEW' THEN 'Allows an administrator to view the permission catalogue and inspect the permissions currently assigned to a role. It is read-only and does not allow changing role permissions.'
                    WHEN 'RBAC_PERMISSIONS_MANAGE' THEN 'Allows an administrator to replace the permission set assigned to an eligible custom role. System role permissions are protected, and requested permission codes must exist in the permission catalogue. This does not create or edit permission definitions.'
                    WHEN 'RBAC_ASSIGNMENTS_MANAGE' THEN 'Allows an administrator to assign an eligible role to a user or remove a role assignment. Disabled users cannot receive a role, duplicate assignments are rejected, and SUPERADMIN assignments are protected from these endpoints.'
                    ELSE 'Allows the application capability identified by this permission code. Refer to the permission code and module when reviewing its scope.'
                END;
                """);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Description",
                table: "Permissions");
        }
    }
}