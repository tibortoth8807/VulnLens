using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VulnLens.Infrastructure.Persistence;

namespace VulnLens.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.AddDbContext<VulnLensDbContext>(options => options.UseNpgsql(connectionString));
        return services;
    }

    /// <summary>
    /// Applies pending EF Core migrations to ensure the database schema is up-to-date.
    /// </summary>
    public static async Task InitializeDatabaseAsync(this IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<VulnLensDbContext>();

        await db.Database.MigrateAsync(cancellationToken);
    }
}
