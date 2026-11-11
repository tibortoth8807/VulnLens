using System.Text.Json;
using System.Text.Json.Serialization;
using VulnLens.Core.Domain;

namespace VulnLens.Core.Parsing;

/// <summary>
/// Parses Trivy JSON output (SchemaVersion 2), e.g.
/// <c>trivy image --format json --output trivy-results.json my-image:tag</c>.
/// </summary>
public sealed class TrivyReportParser : IScanReportParser
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public string Scanner => "trivy";

    public async Task<Scan> ParseAsync(Stream report, CancellationToken cancellationToken = default)
    {
        TrivyReport? trivy;
        try
        {
            trivy = await JsonSerializer.DeserializeAsync<TrivyReport>(report, JsonOptions, cancellationToken);
        }
        catch (JsonException ex)
        {
            throw new ScanReportFormatException("The report is not valid Trivy JSON.", ex);
        }

        if (trivy is null || string.IsNullOrWhiteSpace(trivy.ArtifactName))
        {
            throw new ScanReportFormatException("The Trivy report has no ArtifactName.");
        }

        var scan = new Scan
        {
            ArtifactName = trivy.ArtifactName,
            Scanner = Scanner,
            // PostgreSQL timestamptz needs UTC offsets (Npgsql rejects e.g. +01:00).
            ScannedAt = trivy.CreatedAt?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
        };

        // Trivy can report the same CVE/package for several targets (layers, lock files).
        // We keep one finding per fingerprint.
        var findings = (trivy.Results ?? [])
            .SelectMany(result => result.Vulnerabilities ?? [])
            .Where(v => !string.IsNullOrWhiteSpace(v.VulnerabilityId) && !string.IsNullOrWhiteSpace(v.PkgName))
            .Select(v => new Finding
            {
                ScanId = scan.Id,
                VulnerabilityId = v.VulnerabilityId!,
                PackageName = v.PkgName!,
                InstalledVersion = v.InstalledVersion ?? string.Empty,
                FixedVersion = string.IsNullOrWhiteSpace(v.FixedVersion) ? null : v.FixedVersion,
                Severity = SeverityParser.Parse(v.Severity),
                Title = v.Title,
                Fingerprint = Finding.CreateFingerprint(
                    scan.ArtifactName, v.VulnerabilityId!, v.PkgName!, v.InstalledVersion ?? string.Empty),
            })
            .DistinctBy(f => f.Fingerprint);

        scan.Findings.AddRange(findings);
        return scan;
    }

    // --- Trivy JSON contract (only the fields we use) ---

    private sealed record TrivyReport(
        int SchemaVersion,
        DateTimeOffset? CreatedAt,
        string? ArtifactName,
        string? ArtifactType,
        List<TrivyResult>? Results);

    private sealed record TrivyResult(
        string? Target,
        string? Class,
        string? Type,
        List<TrivyVulnerability>? Vulnerabilities);

    private sealed record TrivyVulnerability(
        [property: JsonPropertyName("VulnerabilityID")] string? VulnerabilityId,
        string? PkgName,
        string? InstalledVersion,
        string? FixedVersion,
        string? Severity,
        string? Title);
}
