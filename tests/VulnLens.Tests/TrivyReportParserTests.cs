using System.Text;
using VulnLens.Core.Domain;
using VulnLens.Core.Parsing;

namespace VulnLens.Tests;

public sealed class TrivyReportParserTests
{
    private readonly TrivyReportParser _parser = new();

    [Fact]
    public async Task Parses_sample_report_and_removes_duplicates()
    {
        await using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "trivy-sample.json"));

        var scan = await _parser.ParseAsync(stream);

        Assert.Equal("vulnlens-demo:latest", scan.ArtifactName);
        Assert.Equal("trivy", scan.Scanner);
        Assert.Equal(3, scan.Findings.Count); // 4 entries in the file, 1 duplicate
        Assert.All(scan.Findings, f => Assert.Equal(scan.Id, f.ScanId));
    }

    [Fact]
    public async Task Maps_severity_and_empty_fixed_version()
    {
        await using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "trivy-sample.json"));

        var scan = await _parser.ParseAsync(stream);

        var critical = Assert.Single(scan.Findings, f => f.VulnerabilityId == "CVE-2024-0001");
        Assert.Equal(Severity.Critical, critical.Severity);
        Assert.Equal("3.0.15-1~deb12u1", critical.FixedVersion);

        var noFix = Assert.Single(scan.Findings, f => f.VulnerabilityId == "CVE-2024-0002");
        Assert.Null(noFix.FixedVersion);
    }

    [Fact]
    public async Task Converts_scan_time_to_utc()
    {
        await using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "trivy-sample.json"));

        var scan = await _parser.ParseAsync(stream);

        Assert.Equal(TimeSpan.Zero, scan.ScannedAt.Offset);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 8, 15, 0, TimeSpan.Zero), scan.ScannedAt);
    }

    [Fact]
    public async Task Report_without_vulnerabilities_gives_empty_scan()
    {
        const string json = """{ "SchemaVersion": 2, "ArtifactName": "clean:1.0", "Results": [ { "Target": "x" } ] }""";

        var scan = await _parser.ParseAsync(new MemoryStream(Encoding.UTF8.GetBytes(json)));

        Assert.Empty(scan.Findings);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("""{ "SchemaVersion": 2 }""")]
    public async Task Invalid_report_throws_format_exception(string json)
    {
        await Assert.ThrowsAsync<ScanReportFormatException>(
            () => _parser.ParseAsync(new MemoryStream(Encoding.UTF8.GetBytes(json))));
    }
}

public sealed class FingerprintTests
{
    [Fact]
    public void Fingerprint_is_stable_and_case_insensitive()
    {
        var a = Finding.CreateFingerprint("img:1", "CVE-1", "libssl3", "1.0");
        var b = Finding.CreateFingerprint("IMG:1", "cve-1", "LIBSSL3", "1.0");

        Assert.Equal(a, b);
        Assert.Equal(64, a.Length);
    }

    [Fact]
    public void Different_package_version_gives_different_fingerprint()
    {
        Assert.NotEqual(
            Finding.CreateFingerprint("img:1", "CVE-1", "libssl3", "1.0"),
            Finding.CreateFingerprint("img:1", "CVE-1", "libssl3", "1.1"));
    }
}
