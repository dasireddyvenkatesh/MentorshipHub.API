using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261106140000_SeedRbacPermissionCatalogue")]
    public partial class SeedRbacPermissionCatalogue : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                INSERT INTO "Permissions" ("Id", "Name", "Code", "Module", "CreatedAt")
                VALUES
                    ('a1d4b1f0-0001-4000-8000-000000000001', 'View administration overview', 'ADMIN_OVERVIEW_VIEW', 'ADMIN', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000002', 'View users', 'ADMIN_USERS_VIEW', 'ADMIN', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000003', 'Manage users', 'ADMIN_USERS_MANAGE', 'ADMIN', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000004', 'View roles', 'RBAC_ROLES_VIEW', 'RBAC', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000005', 'Manage roles', 'RBAC_ROLES_MANAGE', 'RBAC', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000006', 'View permissions', 'RBAC_PERMISSIONS_VIEW', 'RBAC', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000007', 'Manage role permissions', 'RBAC_PERMISSIONS_MANAGE', 'RBAC', TIMESTAMPTZ '2026-11-06 08:30:00+00'),
                    ('a1d4b1f0-0001-4000-8000-000000000008', 'Manage user role assignments', 'RBAC_ASSIGNMENTS_MANAGE', 'RBAC', TIMESTAMPTZ '2026-11-06 08:30:00+00')
                ON CONFLICT ("Code") DO NOTHING;
                """);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DELETE FROM "Permissions"
                WHERE "Id" IN (
                    'a1d4b1f0-0001-4000-8000-000000000001',
                    'a1d4b1f0-0001-4000-8000-000000000002',
                    'a1d4b1f0-0001-4000-8000-000000000003',
                    'a1d4b1f0-0001-4000-8000-000000000004',
                    'a1d4b1f0-0001-4000-8000-000000000005',
                    'a1d4b1f0-0001-4000-8000-000000000006',
                    'a1d4b1f0-0001-4000-8000-000000000007',
                    'a1d4b1f0-0001-4000-8000-000000000008'
                );
                """);
        }
    }
}
