using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AdAudit.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "cfg");

            migrationBuilder.CreateTable(
                name: "AuditLogEntries",
                schema: "cfg",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Timestamp = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Actor = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Action = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    TargetDomain = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    Detail = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Targets",
                schema: "cfg",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Domain = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Server = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Trusted = table.Column<bool>(type: "bit", nullable: false),
                    Note = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Targets", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DomainCredentials",
                schema: "cfg",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TargetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    EncryptedPassword = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DomainCredentials", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DomainCredentials_Targets_TargetId",
                        column: x => x.TargetId,
                        principalSchema: "cfg",
                        principalTable: "Targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TargetExtraServers",
                schema: "cfg",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TargetId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ServerName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetExtraServers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetExtraServers_Targets_TargetId",
                        column: x => x.TargetId,
                        principalSchema: "cfg",
                        principalTable: "Targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogEntries_Timestamp",
                schema: "cfg",
                table: "AuditLogEntries",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_DomainCredentials_TargetId",
                schema: "cfg",
                table: "DomainCredentials",
                column: "TargetId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TargetExtraServers_TargetId",
                schema: "cfg",
                table: "TargetExtraServers",
                column: "TargetId");

            migrationBuilder.CreateIndex(
                name: "IX_Targets_Domain",
                schema: "cfg",
                table: "Targets",
                column: "Domain",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogEntries",
                schema: "cfg");

            migrationBuilder.DropTable(
                name: "DomainCredentials",
                schema: "cfg");

            migrationBuilder.DropTable(
                name: "TargetExtraServers",
                schema: "cfg");

            migrationBuilder.DropTable(
                name: "Targets",
                schema: "cfg");
        }
    }
}
