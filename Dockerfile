# Use the official .NET 8 runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80

# Use the official .NET 8 SDK image for building
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["app/gdvcsharp.csproj", "."]
RUN dotnet restore "./gdvcsharp.csproj"
COPY app/ .
WORKDIR "/src/."
RUN dotnet build "gdvcsharp.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "gdvcsharp.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Create some sample files for path traversal testing
RUN mkdir -p /app/uploads
RUN echo "This is a sample file for testing." > /app/uploads/sample.txt
RUN echo '{"database": {"password": "secret123"}, "api_key": "hidden_key"}' > /app/uploads/config.json
RUN echo "admin:x:0:0:root:/root:/bin/bash" > /etc/passwd.sample

# Add a warning label
LABEL description="Deliberately vulnerable web application for educational purposes"
LABEL warning="DO NOT USE IN PRODUCTION - CONTAINS INTENTIONAL SECURITY VULNERABILITIES"

ENTRYPOINT ["dotnet", "gdvcsharp.dll"]
