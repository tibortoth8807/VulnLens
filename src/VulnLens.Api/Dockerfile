# Build from the repository root:
#   docker build -f src/VulnLens.Api/Dockerfile -t vulnlens-api .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first (cached layer as long as project files don't change)
COPY Directory.Build.props Directory.Packages.props ./
COPY src/VulnLens.Core/VulnLens.Core.csproj src/VulnLens.Core/
COPY src/VulnLens.Infrastructure/VulnLens.Infrastructure.csproj src/VulnLens.Infrastructure/
COPY src/VulnLens.Api/VulnLens.Api.csproj src/VulnLens.Api/
RUN dotnet restore src/VulnLens.Api/VulnLens.Api.csproj

COPY src/ src/
RUN dotnet publish src/VulnLens.Api/VulnLens.Api.csproj -c Release --no-restore -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
# Non-root user shipped with the official .NET images
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "VulnLens.Api.dll"]
