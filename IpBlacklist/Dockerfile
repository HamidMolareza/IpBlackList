FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base

# Create data folder before dropping privileges
USER root

# Drop to the application user
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["IpBlacklist/IpBlacklist.csproj", "IpBlacklist/"]
RUN dotnet restore "IpBlacklist/IpBlacklist.csproj"
COPY . .
WORKDIR "/src/IpBlacklist"
RUN dotnet build "./IpBlacklist.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./IpBlacklist.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "IpBlacklist.dll"]
