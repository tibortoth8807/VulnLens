using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using VulnLens.Api.Endpoints;
using VulnLens.Core.Domain;

namespace VulnLens.Tests;

public sealed class FindingsEndpointTests : IClassFixture<VulnLensApiFactory>, IAsyncLifetime
{
    private readonly VulnLensApiFactory _factory;
    private readonly HttpClient _client;

    public FindingsEndpointTests(VulnLensApiFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    public async Task InitializeAsync()
    {
        await _factory.ResetDatabaseAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task GetFindings_WhenDatabaseIsEmpty_ReturnsOkWithEmptyList()
    {
        var response = await _client.GetAsync("/api/findings");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var findings = await response.Content.ReadFromJsonAsync<List<FindingDto>>();
        Assert.NotNull(findings);
        Assert.Empty(findings);
    }

    [Fact]
    public async Task GetFindings_ReturnsOnlyFindingsFromLatestScan_PerArtifact()
    {
        const string artifact = "ghcr.io/org/api:v1";

        // Older scan (yesterday)
        var olderScan = new Scan
        {
            ArtifactName = artifact,
            Scanner = "trivy",
            ScannedAt = DateTimeOffset.UtcNow.AddDays(-2),
            ImportedAt = DateTimeOffset.UtcNow.AddDays(-2),
        };
        olderScan.Findings.Add(new Finding
        {
            ScanId = olderScan.Id,
            VulnerabilityId = "CVE-2024-OLD",
            PackageName = "old-pkg",
            InstalledVersion = "1.0.0",
            Severity = Severity.High,
            Fingerprint = Finding.CreateFingerprint(artifact, "CVE-2024-OLD", "old-pkg", "1.0.0"),
        });

        // Latest scan (today)
        var latestScan = new Scan
        {
            ArtifactName = artifact,
            Scanner = "trivy",
            ScannedAt = DateTimeOffset.UtcNow,
            ImportedAt = DateTimeOffset.UtcNow,
        };
        latestScan.Findings.Add(new Finding
        {
            ScanId = latestScan.Id,
            VulnerabilityId = "CVE-2024-NEW",
            PackageName = "new-pkg",
            InstalledVersion = "2.0.0",
            Severity = Severity.Critical,
            Fingerprint = Finding.CreateFingerprint(artifact, "CVE-2024-NEW", "new-pkg", "2.0.0"),
        });

        await _factory.SeedAsync(db =>
        {
            db.Scans.AddRange(olderScan, latestScan);
            return Task.CompletedTask;
        });

        var response = await _client.GetAsync($"/api/findings?artifact={Uri.EscapeDataString(artifact)}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var findings = await response.Content.ReadFromJsonAsync<List<FindingDto>>();
        Assert.NotNull(findings);

        // Must only contain findings from the latest scan
        var single = Assert.Single(findings);
        Assert.Equal("CVE-2024-NEW", single.VulnerabilityId);
        Assert.Equal("new-pkg", single.PackageName);
        Assert.Equal("Critical", single.Severity);
    }

    [Fact]
    public async Task GetFindings_WhenFilteredByArtifact_ReturnsOnlyFindingsForThatArtifact()
    {
        const string frontendArtifact = "app-frontend:1.0";
        const string backendArtifact = "app-backend:1.0";

        var frontendScan = new Scan
        {
            ArtifactName = frontendArtifact,
            Scanner = "trivy",
            ScannedAt = DateTimeOffset.UtcNow,
        };
        frontendScan.Findings.Add(new Finding
        {
            ScanId = frontendScan.Id,
            VulnerabilityId = "CVE-FRONTEND-1",
            PackageName = "vue",
            InstalledVersion = "3.4.0",
            Severity = Severity.High,
            Fingerprint = Finding.CreateFingerprint(frontendArtifact, "CVE-FRONTEND-1", "vue", "3.4.0"),
        });

        var backendScan = new Scan
        {
            ArtifactName = backendArtifact,
            Scanner = "trivy",
            ScannedAt = DateTimeOffset.UtcNow,
        };
        backendScan.Findings.Add(new Finding
        {
            ScanId = backendScan.Id,
            VulnerabilityId = "CVE-BACKEND-1",
            PackageName = "Npgsql",
            InstalledVersion = "8.0.0",
            Severity = Severity.High,
            Fingerprint = Finding.CreateFingerprint(backendArtifact, "CVE-BACKEND-1", "Npgsql", "8.0.0"),
        });

        await _factory.SeedAsync(db =>
        {
            db.Scans.AddRange(frontendScan, backendScan);
            return Task.CompletedTask;
        });

        var response = await _client.GetAsync($"/api/findings?artifact={Uri.EscapeDataString(frontendArtifact)}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var findings = await response.Content.ReadFromJsonAsync<List<FindingDto>>();
        Assert.NotNull(findings);
        var item = Assert.Single(findings);
        Assert.Equal("CVE-FRONTEND-1", item.VulnerabilityId);
        Assert.Equal(frontendArtifact, item.ArtifactName);
    }

    [Fact]
    public async Task GetFindings_WhenFilteredByMinSeverity_FiltersOutLowerSeverities()
    {
        const string artifact = "multi-severity-app:1.0";

        var scan = new Scan
        {
            ArtifactName = artifact,
            Scanner = "trivy",
            ScannedAt = DateTimeOffset.UtcNow,
        };

        scan.Findings.AddRange([
            new Finding
            {
                ScanId = scan.Id,
                VulnerabilityId = "CVE-CRIT",
                PackageName = "pkg-a",
                InstalledVersion = "1.0",
                Severity = Severity.Critical,
                Fingerprint = Finding.CreateFingerprint(artifact, "CVE-CRIT", "pkg-a", "1.0"),
            },
            new Finding
            {
                ScanId = scan.Id,
                VulnerabilityId = "CVE-HIGH",
                PackageName = "pkg-b",
                InstalledVersion = "1.0",
                Severity = Severity.High,
                Fingerprint = Finding.CreateFingerprint(artifact, "CVE-HIGH", "pkg-b", "1.0"),
            },
            new Finding
            {
                ScanId = scan.Id,
                VulnerabilityId = "CVE-MED",
                PackageName = "pkg-c",
                InstalledVersion = "1.0",
                Severity = Severity.Medium,
                Fingerprint = Finding.CreateFingerprint(artifact, "CVE-MED", "pkg-c", "1.0"),
            },
            new Finding
            {
                ScanId = scan.Id,
                VulnerabilityId = "CVE-LOW",
                PackageName = "pkg-d",
                InstalledVersion = "1.0",
                Severity = Severity.Low,
                Fingerprint = Finding.CreateFingerprint(artifact, "CVE-LOW", "pkg-d", "1.0"),
            },
        ]);

        await _factory.SeedAsync(db =>
        {
            db.Scans.Add(scan);
            return Task.CompletedTask;
        });

        var response = await _client.GetAsync($"/api/findings?artifact={Uri.EscapeDataString(artifact)}&minSeverity=High");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var findings = await response.Content.ReadFromJsonAsync<List<FindingDto>>();
        Assert.NotNull(findings);

        Assert.Equal(2, findings.Count);
        Assert.Equal("CVE-CRIT", findings[0].VulnerabilityId);
        Assert.Equal("Critical", findings[0].Severity);
        Assert.Equal("CVE-HIGH", findings[1].VulnerabilityId);
        Assert.Equal("High", findings[1].Severity);
    }

    [Fact]
    public async Task GetFindings_EndToEnd_AfterTrivyReportUpload_ReturnsParsedFindings()
    {
        var samplePath = Path.Combine(AppContext.BaseDirectory, "TestData", "trivy-sample.json");
        await using var fileStream = File.OpenRead(samplePath);
        using var content = new StreamContent(fileStream);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var uploadResponse = await _client.PostAsync("/api/scans/trivy", content);
        Assert.Equal(HttpStatusCode.Created, uploadResponse.StatusCode);

        var findingsResponse = await _client.GetAsync("/api/findings?artifact=vulnlens-demo:latest");
        Assert.Equal(HttpStatusCode.OK, findingsResponse.StatusCode);

        var findings = await findingsResponse.Content.ReadFromJsonAsync<List<FindingDto>>();
        Assert.NotNull(findings);
        Assert.Equal(3, findings.Count);

        Assert.Contains(findings, f => f.VulnerabilityId == "CVE-2024-0001" && f.Severity == "Critical");
        Assert.Contains(findings, f => f.VulnerabilityId == "CVE-2024-0003" && f.Severity == "High");
        Assert.Contains(findings, f => f.VulnerabilityId == "CVE-2024-0002" && f.Severity == "Medium");
    }
}
