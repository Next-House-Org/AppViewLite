# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files first (better caching for restore)
COPY AppViewLite.sln ./
COPY src/AppViewLite.Web/AppViewLite.Web.csproj src/AppViewLite.Web/
# Copy any other project files that AppViewLite.Web references
COPY src/AppViewLite/AppViewLite.csproj src/AppViewLite/

# Restore dependencies
RUN dotnet restore AppViewLite.sln

# Copy the rest of the source
COPY . .

# Publish (Release build)
RUN dotnet publish src/AppViewLite.Web/AppViewLite.Web.csproj -c Release -o /app/publish

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 61749

# Set environment for ASP.NET Core
ENV ASPNETCORE_URLS=http://+:61749

ENTRYPOINT ["dotnet", "AppViewLite.Web.dll"]

