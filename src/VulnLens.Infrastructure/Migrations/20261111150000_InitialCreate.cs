using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnLens.Infrastructure.Migrations;

/// <inheritdoc />
public partial class InitialCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "scans",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                ArtifactName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                Scanner = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                ScannedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                ImportedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_scans", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "findings",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                ScanId = table.Column<Guid>(type: "uuid", nullable: false),
                VulnerabilityId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                PackageName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                InstalledVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                FixedVersion = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                Severity = table.Column<int>(type: "integer", nullable: false),
                Title = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                Fingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_findings", x => x.Id);
                table.ForeignKey(
                    name: "FK_findings_scans_ScanId",
                    column: x => x.ScanId,
                    principalTable: "scans",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(
            name: "IX_findings_Fingerprint",
            table: "findings",
            column: "Fingerprint");

        migrationBuilder.CreateIndex(
            name: "IX_findings_ScanId_Fingerprint",
            table: "findings",
            columns: new[] { "ScanId", "Fingerprint" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_findings_Severity",
            table: "findings",
            column: "Severity");

        migrationBuilder.CreateIndex(
            name: "IX_findings_VulnerabilityId",
            table: "findings",
            column: "VulnerabilityId");

        migrationBuilder.CreateIndex(
            name: "IX_scans_ArtifactName_ScannedAt",
            table: "scans",
            columns: new[] { "ArtifactName", "ScannedAt" });
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "findings");

        migrationBuilder.DropTable(
            name: "scans");
    }
}
