namespace VulnLens.Core.Domain;

/// <summary>One imported scanner report for one artifact (e.g. a Docker image).</summary>
public sealed class Scan
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    /// <summary>What was scanned, e.g. "ghcr.io/me/vulnlens-api:sha-abc123".</summary>
    public required string ArtifactName { get; init; }

    /// <summary>Scanner that produced the report, e.g. "trivy".</summary>
    public required string Scanner { get; init; }

    /// <summary>When the scanner ran (from the report). Falls back to import time.</summary>
    public DateTimeOffset ScannedAt { get; init; }

    public DateTimeOffset ImportedAt { get; init; } = DateTimeOffset.UtcNow;

    public List<Finding> Findings { get; init; } = [];
}
