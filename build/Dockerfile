# =========================
# BUILD STAGE
# =========================
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

# Publish the application
RUN dotnet publish AppViewLite.sln -c Release -o /app/publish


# =========================
# RUNTIME STAGE
# =========================
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime

# Install git if commit info is needed
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy published files from build stage
COPY --from=build /app/publish .

# Expose the port your app listens on
EXPOSE 61749

# Environment variable to allow new database creation
ENV ALLOW_NEW_DB=1

# Start the app with optional flag to create DB if missing
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll", "--allow-new-database", "1"]

