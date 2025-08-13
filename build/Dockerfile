# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy all source code
COPY . .

# Install additional tools
RUN apt-get update && \
    apt-get install -y git curl unzip && \
    rm -rf /var/lib/apt/lists/*

# Restore and publish
RUN dotnet restore
RUN dotnet publish -c Release -o /app

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app

# Copy published app
COPY --from=build /app /app

# Environment variables
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ALLOW_NEW_DB=1
ENV DOTNET_URLS=http://+:61749
ENV SKIP_GIT_LOG=1

# Expose port
EXPOSE 61749

# Persistent volume for checkpoints/data
VOLUME /root/BskyAppViewLiteData

# Entry point
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll", "--allow-new-database", "1"]

