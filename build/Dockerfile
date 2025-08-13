# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and projects
COPY src/AppViewLite.sln ./
COPY src/AppViewLite/*.csproj ./AppViewLite/
COPY src/AppViewLite.Web/*.csproj ./AppViewLite.Web/

# Restore dependencies
RUN dotnet restore AppViewLite.sln

# Copy all source code
COPY src/. .

# Publish the app
RUN dotnet publish AppViewLite.sln -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app

# Copy published files
COPY --from=build /app/publish .

# Set environment variables to disable HTTPS
ENV DOTNET_URLS=http://+:61749
ENV DOTNET_RUNNING_IN_CONTAINER=true
ENV DOTNET_DEVELOPER_CERTS=false
ENV ASPNETCORE_ENVIRONMENT=Production

# Expose only HTTP port
EXPOSE 61749

# Start the app
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll"]

