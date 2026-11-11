namespace VulnLens.Core.Domain;

public enum Severity
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public static class SeverityParser
{
    public static Severity Parse(string? value) =>
        Enum.TryParse<Severity>(value, ignoreCase: true, out var severity) && Enum.IsDefined(severity)
            ? severity
            : Severity.Unknown;
}
