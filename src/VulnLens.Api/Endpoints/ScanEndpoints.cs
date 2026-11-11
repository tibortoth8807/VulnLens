using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnLens.Core.Domain;
using VulnLens.Core.Parsing;
using VulnLens.Infrastructure.Persistence;

namespace VulnLens.Api.Endpoints;

public static class ScanEndpoints
{
    private const string ApiKeyHeader = "X-Api-Key";

    public static IEndpointRouteBuilder MapScanEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api").WithTags("Scans");

        // Upload a raw scanner report, e.g.:
        // curl -X POST --data-binary @trivy-results.json -H "Content-Type: application/json" http://localhost:8080/api/scans/trivy
        api.MapPost("/scans/{scanner}", ImportScan).WithName("ImportScan");
        api.MapGet("/scans", ListScans).WithName("ListScans");
        api.MapGet("/scans/{id:guid}/findings", GetScanFindings).WithName("GetScanFindings");
        api.MapGet("/findings", GetLatestFindings).WithName("GetLatestFindings");
        api.MapGet("/diff", GetDiff).WithName("GetDiff");

        return app;
    }

    private static async Task<IResult> ImportScan(
        string scanner,
        HttpRequest request,
        [FromServices] IEnumerable<IScanReportParser> parsers,
        [FromServices] VulnLensDbContext db,
        [FromServices] IConfiguration configuration,
        CancellationToken ct)
    {
        if (!IsAuthorized(request, configuration))
        {
            return Results.Unauthorized();
        }

        var parser = parsers.FirstOrDefault(p => string.Equals(p.Scanner, scanner, StringComparison.OrdinalIgnoreCase));
        if (parser is null)
        {
            return Results.Problem($"Unsupported scanner '{scanner}'.", statusCode: StatusCodes.Status400BadRequest);
        }

        Scan scan;
        try
        {
            scan = await parser.ParseAsync(request.Body, ct);
        }
        catch (ScanReportFormatException ex)
        {
            return Results.Problem(ex.Message, statusCode: StatusCodes.Status400BadRequest);
        }

        db.Scans.Add(scan);
        await db.SaveChangesAsync(ct);

        return Results.Created($"/api/scans/{scan.Id}/findings", ToSummary(scan));
    }

    private static async Task<IResult> ListScans([FromServices] VulnLensDbContext db, CancellationToken ct)
    {
        var scans = await db.Scans
            .AsNoTracking()
            .Include(s => s.Findings)
            .OrderByDescending(s => s.ScannedAt)
            .Take(100)
            .ToListAsync(ct);

        return Results.Ok(scans.Select(ToSummary));
    }

    private static async Task<IResult> GetScanFindings(Guid id, [FromServices] VulnLensDbContext db, CancellationToken ct)
    {
        var scan = await db.Scans.AsNoTracking().Include(s => s.Findings).FirstOrDefaultAsync(s => s.Id == id, ct);
        return scan is null
            ? Results.NotFound()
            : Results.Ok(scan.Findings.OrderByDescending(f => f.Severity).Select(f => ToDto(f, scan.ArtifactName)));
    }

    /// <summary>Findings of the latest scan of every artifact (or of one artifact), optionally filtered by minimum severity.</summary>
    private static async Task<IResult> GetLatestFindings(
        [FromQuery] string? artifact,
        [FromQuery] string? minSeverity,
        [FromServices] VulnLensDbContext db,
        CancellationToken ct)
    {
        // Small table, so picking "latest per artifact" in memory keeps the query simple and portable.
        var scanHeaders = await db.Scans
            .AsNoTracking()
            .Where(s => artifact == null || s.ArtifactName == artifact)
            .Select(s => new { s.Id, s.ArtifactName, s.ScannedAt })
            .ToListAsync(ct);

        var latest = scanHeaders
            .GroupBy(s => s.ArtifactName)
            .Select(g => g.MaxBy(s => s.ScannedAt)!)
            .ToDictionary(s => s.Id, s => s.ArtifactName);

        var latestIds = latest.Keys.ToList();
        var min = SeverityParser.Parse(minSeverity);

        var findings = await db.Findings
            .AsNoTracking()
            .Where(f => latestIds.Contains(f.ScanId) && f.Severity >= min)
            .ToListAsync(ct);

        return Results.Ok(findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.PackageName)
            .Select(f => ToDto(f, latest[f.ScanId])));
    }

    /// <summary>"What got better since last time?" New vs. fixed findings between the last two scans of an artifact.</summary>
    private static async Task<IResult> GetDiff([FromQuery] string artifact, [FromServices] VulnLensDbContext db, CancellationToken ct)
    {
        var lastTwo = await db.Scans
            .AsNoTracking()
            .Include(s => s.Findings)
            .Where(s => s.ArtifactName == artifact)
            .OrderByDescending(s => s.ScannedAt)
            .Take(2)
            .ToListAsync(ct);

        if (lastTwo.Count == 0)
        {
            return Results.NotFound();
        }

        var latest = lastTwo[0];
        var previous = lastTwo.ElementAtOrDefault(1);
        var previousFindings = previous?.Findings ?? [];

        var previousPrints = previousFindings.Select(f => f.Fingerprint).ToHashSet();
        var latestPrints = latest.Findings.Select(f => f.Fingerprint).ToHashSet();

        var diff = new ScanDiff(
            artifact,
            previous?.Id,
            latest.Id,
            NewFindings: latest.Findings.Where(f => !previousPrints.Contains(f.Fingerprint)).Select(f => ToDto(f, artifact)).ToList(),
            FixedFindings: previousFindings.Where(f => !latestPrints.Contains(f.Fingerprint)).Select(f => ToDto(f, artifact)).ToList(),
            UnchangedCount: latest.Findings.Count(f => previousPrints.Contains(f.Fingerprint)));

        return Results.Ok(diff);
    }

    /// <summary>If Ingest:ApiKey is configured, uploads must send it in the X-Api-Key header (used by CI).</summary>
    private static bool IsAuthorized(HttpRequest request, IConfiguration configuration)
    {
        var expected = configuration["Ingest:ApiKey"];
        if (string.IsNullOrEmpty(expected))
        {
            return true;
        }

        var provided = request.Headers[ApiKeyHeader].ToString();
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(provided), Encoding.UTF8.GetBytes(expected));
    }

    private static ScanSummary ToSummary(Scan scan) => new(
        scan.Id,
        scan.ArtifactName,
        scan.Scanner,
        scan.ScannedAt,
        scan.ImportedAt,
        scan.Findings.Count,
        new SeverityCounts(
            scan.Findings.Count(f => f.Severity == Severity.Critical),
            scan.Findings.Count(f => f.Severity == Severity.High),
            scan.Findings.Count(f => f.Severity == Severity.Medium),
            scan.Findings.Count(f => f.Severity == Severity.Low),
            scan.Findings.Count(f => f.Severity == Severity.Unknown)));

    private static FindingDto ToDto(Finding f, string artifactName) => new(
        f.Id, f.ScanId, artifactName, f.VulnerabilityId, f.PackageName, f.InstalledVersion, f.FixedVersion, f.Severity.ToString(), f.Title);
}
