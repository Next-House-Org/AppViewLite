# Use .NET 9.0 SDK image for build stage
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

# Use .NET 9.0 ASP.NET runtime image for runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime

WORKDIR /app

# Copy published files from build stage
COPY --from=build /app/publish .

# Expose the port your app listens on (adjust if needed)
EXPOSE 61749

# Start the app
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll"]

