# =========================
# Stage 1: Build
# =========================
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build

WORKDIR /src

# Copy solution and project files first for restore caching
COPY ./src/*.sln ./
COPY ./src/AppViewLite/*.csproj ./AppViewLite/
COPY ./src/AppViewLite.Web/*.csproj ./AppViewLite.Web/

# Restore dependencies
RUN dotnet restore

# Copy all source code
COPY ./src/. .

# Publish the Web project
RUN dotnet publish ./AppViewLite.Web/AppViewLite.Web.csproj \
    -c Release \
    -o /publish

# =========================
# Stage 2: Runtime
# =========================
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime

WORKDIR /app

# Install required tools
RUN apt-get update && \
    apt-get install -y git curl unzip && \
    rm -rf /var/lib/apt/lists/*

# Copy published artifacts from build stage
COPY --from=build /publish/ /app/

# Expose port
EXPOSE 61749

# Environment variables
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ALLOW_NEW_DB=1
ENV DOTNET_URLS=http://+:61749    # <-- force HTTP only
ENV DOTNET_HTTPS_PORT=0           # <-- disables HTTPS
ENV SKIP_GIT_LOG=1

# Persistent volume for DB/checkpoints
VOLUME /root/BskyAppViewLiteData

# Entry point
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll", "--allow-new-database", "1"]

