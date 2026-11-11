using Xqare.Api.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Xqare.Api.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261106120000_AddRbacAuditLogs")]
    public partial class AddRbacAuditLogs : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RbacAuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ActorUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    ActionCode = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    TargetType = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetRoleId = table.Column<Guid>(type: "uuid", nullable: true),
                    BeforeData = table.Column<string>(type: "jsonb", nullable: true),
                    AfterData = table.Column<string>(type: "jsonb", nullable: true),
                    IpAddress = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RbacAuditLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RbacAuditLogs_Roles_TargetRoleId",
                        column: x => x.TargetRoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RbacAuditLogs_Users_ActorUserId",
                        column: x => x.ActorUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_RbacAuditLogs_Users_TargetUserId",
                        column: x => x.TargetUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RbacAuditLogs_ActionCode",
                table: "RbacAuditLogs",
                column: "ActionCode");

            migrationBuilder.CreateIndex(
                name: "IX_RbacAuditLogs_ActorUserId",
                table: "RbacAuditLogs",
                column: "ActorUserId");

            migrationBuilder.CreateIndex(
                name: "IX_RbacAuditLogs_CreatedAt",
                table: "RbacAuditLogs",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_RbacAuditLogs_TargetRoleId",
                table: "RbacAuditLogs",
                column: "TargetRoleId");

            migrationBuilder.CreateIndex(
                name: "IX_RbacAuditLogs_TargetUserId",
                table: "RbacAuditLogs",
                column: "TargetUserId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "RbacAuditLogs");
        }
    }
}