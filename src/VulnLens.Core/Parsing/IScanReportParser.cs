using VulnLens.Core.Domain;

namespace VulnLens.Core.Parsing;

/// <summary>Turns a scanner-specific report into the VulnLens domain model.</summary>
public interface IScanReportParser
{
    /// <summary>Scanner name this parser handles, e.g. "trivy". Matched case-insensitively.</summary>
    string Scanner { get; }

    Task<Scan> ParseAsync(Stream report, CancellationToken cancellationToken = default);
}

public sealed class ScanReportFormatException(string message, Exception? inner = null) : Exception(message, inner);
