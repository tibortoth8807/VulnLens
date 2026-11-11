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
    /// Applies EF migrations if there are any; otherwise creates the schema directly.
    /// The fallback keeps the skeleton runnable before the first migration is generated.
    /// </summary>
    public static async Task InitializeDatabaseAsync(this IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<VulnLensDbContext>();

        if (db.Database.GetMigrations().Any())
        {
            await db.Database.MigrateAsync(cancellationToken);
        }
        else
        {
            await db.Database.EnsureCreatedAsync(cancellationToken);
        }
    }
}
