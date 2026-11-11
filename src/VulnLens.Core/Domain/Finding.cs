using System.Security.Cryptography;
using System.Text;

namespace VulnLens.Core.Domain;

/// <summary>A single vulnerability in a single package version, within one scan.</summary>
public sealed class Finding
{
    public Guid Id { get; init; } = Guid.CreateVersion7();

    public Guid ScanId { get; init; }

    public required string VulnerabilityId { get; init; }

    public required string PackageName { get; init; }

    public required string InstalledVersion { get; init; }

    public string? FixedVersion { get; init; }

    public Severity Severity { get; init; }

    public string? Title { get; init; }

    /// <summary>
    /// Stable identity of "this CVE in this package version of this artifact".
    /// Used to de-duplicate inside a scan and to compare scans over time (new / fixed findings).
    /// </summary>
    public required string Fingerprint { get; init; }

    public static string CreateFingerprint(string artifactName, string vulnerabilityId, string packageName, string installedVersion)
    {
        var raw = string.Join('|', artifactName, vulnerabilityId, packageName, installedVersion).ToUpperInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }
}
