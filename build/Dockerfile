# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy all source code
COPY . .

# Optional: include .git if you want git log to work
# COPY .git /src/.git

# Restore and publish
RUN dotnet restore
RUN dotnet publish -c Release -o /app

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app

# Copy published app
COPY --from=build /app ./

# Environment variables
ENV DOTNET_URLS=http://+:61749
ENV SKIP_GIT_LOG=1
ENV ASPNETCORE_ENVIRONMENT=Production

# Expose HTTP port
EXPOSE 61749

# Persistent data volume
VOLUME /root/BskyAppViewLiteData

# Run the app
ENTRYPOINT ["dotnet", "AppViewLite.Web.dll", "--allow-new-database", "1"]

