using DotNet.Testcontainers.Builders;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;
using VulnLens.Infrastructure.Persistence;

namespace VulnLens.Tests;

public sealed class VulnLensApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly PostgreSqlContainer _dbContainer = new PostgreSqlBuilder()
        .WithImage("postgres:17-alpine")
        .Build();

    public async Task InitializeAsync()
    {
        await _dbContainer.StartAsync();
    }

    public new async Task DisposeAsync()
    {
        await _dbContainer.StopAsync();
        await _dbContainer.DisposeAsync();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ConnectionStrings:VulnLens", _dbContainer.GetConnectionString());
    }

    public async Task ResetDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VulnLensDbContext>();
        db.Findings.RemoveRange(db.Findings);
        db.Scans.RemoveRange(db.Scans);
        await db.SaveChangesAsync();
    }

    public async Task SeedAsync(Func<VulnLensDbContext, Task> seedAction)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VulnLensDbContext>();
        await seedAction(db);
        await db.SaveChangesAsync();
    }
}
