# =========================
# 1. Build stage
# =========================
#FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /src

# Copy solution file
COPY src/AppViewLite.sln ./

# Copy project files (for layer caching during restore)
COPY src/AppViewLite/*.csproj ./AppViewLite/
COPY src/AppViewLite.Web/*.csproj ./AppViewLite.Web/

# Restore dependencies
RUN dotnet restore AppViewLite.sln

# Copy the rest of the source code
COPY src/ ./ 

# Build and publish the application
RUN dotnet publish AppViewLite.Web/AppViewLite.Web.csproj -c Release -o /app/publish

# =========================
# 2. Runtime stage
# =========================
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Copy published output from build stage
COPY --from=build /app/publish .

# Expose the application port (adjust if your app uses a different one)
EXPOSE 61749

# Environment variables (adjust if needed)
ENV DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false

# Start the app
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll"]

