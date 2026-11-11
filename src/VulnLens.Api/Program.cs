using VulnLens.Api.Endpoints;
using VulnLens.Core.Parsing;
using VulnLens.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("VulnLens")
    ?? throw new InvalidOperationException("Connection string 'VulnLens' is missing.");

builder.Services.AddInfrastructure(connectionString);
builder.Services.AddSingleton<IScanReportParser, TrivyReportParser>();
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();

var app = builder.Build();

await app.Services.InitializeDatabaseAsync();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi(); // /openapi/v1.json
}

app.MapHealthChecks("/health");
app.MapScanEndpoints();

await app.RunAsync();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program;
