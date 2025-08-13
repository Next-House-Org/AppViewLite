# -------------------------
# Build Stage
# -------------------------
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build

WORKDIR /src

# Copy solution and project files
COPY src/AppViewLite.sln ./
COPY src/AppViewLite/*.csproj ./AppViewLite/
COPY src/AppViewLite.Web/*.csproj ./AppViewLite.Web/

# Restore dependencies
RUN dotnet restore AppViewLite.sln

# Copy all source code
COPY src/. .

# Publish the application (Release mode)
RUN dotnet publish AppViewLite.sln -c Release -o /app/publish

# -------------------------
# Runtime Stage
# -------------------------
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime

# Install git so your app can fetch git commit info
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy published files from build stage
COPY --from=build /app/publish .

# Expose the HTTP port only
EXPOSE 61749

# Force HTTP only (ALB handles SSL)
ENV DOTNET_URLS=http://+:61749
ENV ASPNETCORE_URLS=http://+:61749

# Optional: allow creating new database if not present
ENV ALLOW_NEW_DB=1

# Start the application
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll", "--allow-new-database", "1"]

