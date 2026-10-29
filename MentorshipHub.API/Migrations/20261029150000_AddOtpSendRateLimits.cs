using System;
using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MentorshipHub.API.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20261029150000_AddOtpSendRateLimits")]
    public partial class AddOtpSendRateLimits : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "HourlySendCount",
                table: "EmailVerificationOtps",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "HourlyWindowStartedAt",
                table: "EmailVerificationOtps",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DailySendCount",
                table: "EmailVerificationOtps",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "DailyWindowStartedAt",
                table: "EmailVerificationOtps",
                type: "timestamp with time zone",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "HourlySendCount", table: "EmailVerificationOtps");
            migrationBuilder.DropColumn(name: "HourlyWindowStartedAt", table: "EmailVerificationOtps");
            migrationBuilder.DropColumn(name: "DailySendCount", table: "EmailVerificationOtps");
            migrationBuilder.DropColumn(name: "DailyWindowStartedAt", table: "EmailVerificationOtps");
        }
    }
}
