using Microsoft.EntityFrameworkCore;
using VulnLens.Core.Domain;

namespace VulnLens.Infrastructure.Persistence;

public sealed class VulnLensDbContext(DbContextOptions<VulnLensDbContext> options) : DbContext(options)
{
    public DbSet<Scan> Scans => Set<Scan>();

    public DbSet<Finding> Findings => Set<Finding>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Scan>(scan =>
        {
            scan.ToTable("scans");
            scan.HasKey(s => s.Id);
            scan.Property(s => s.ArtifactName).HasMaxLength(512).IsRequired();
            scan.Property(s => s.Scanner).HasMaxLength(64).IsRequired();
            scan.HasIndex(s => new { s.ArtifactName, s.ScannedAt });
            scan.HasMany(s => s.Findings)
                .WithOne()
                .HasForeignKey(f => f.ScanId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Finding>(finding =>
        {
            finding.ToTable("findings");
            finding.HasKey(f => f.Id);
            finding.Property(f => f.VulnerabilityId).HasMaxLength(128).IsRequired();
            finding.Property(f => f.PackageName).HasMaxLength(256).IsRequired();
            finding.Property(f => f.InstalledVersion).HasMaxLength(128).IsRequired();
            finding.Property(f => f.FixedVersion).HasMaxLength(256);
            finding.Property(f => f.Title).HasMaxLength(1024);
            finding.Property(f => f.Fingerprint).HasMaxLength(64).IsRequired();
            // Stored as int on purpose: "minSeverity" filters use >= and must compare by rank, not alphabetically.
            finding.Property(f => f.Severity);
            finding.HasIndex(f => f.Severity);

            // De-duplication guarantee at DB level: one fingerprint per scan.
            finding.HasIndex(f => new { f.ScanId, f.Fingerprint }).IsUnique();
            finding.HasIndex(f => f.VulnerabilityId);
            finding.HasIndex(f => f.Fingerprint);
        });
    }
}
