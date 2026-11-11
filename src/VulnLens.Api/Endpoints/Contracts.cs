namespace VulnLens.Api.Endpoints;

public sealed record SeverityCounts(int Critical, int High, int Medium, int Low, int Unknown);

public sealed record ScanSummary(
    Guid Id,
    string ArtifactName,
    string Scanner,
    DateTimeOffset ScannedAt,
    DateTimeOffset ImportedAt,
    int TotalFindings,
    SeverityCounts Counts);

public sealed record FindingDto(
    Guid Id,
    Guid ScanId,
    string ArtifactName,
    string VulnerabilityId,
    string PackageName,
    string InstalledVersion,
    string? FixedVersion,
    string Severity,
    string? Title);

/// <summary>What changed between the two most recent scans of an artifact.</summary>
public sealed record ScanDiff(
    string ArtifactName,
    Guid? PreviousScanId,
    Guid LatestScanId,
    IReadOnlyList<FindingDto> NewFindings,
    IReadOnlyList<FindingDto> FixedFindings,
    int UnchangedCount);
