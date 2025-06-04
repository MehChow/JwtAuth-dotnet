# Use the official .NET SDK image
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /app

# Copy the solution and project files
COPY JwtAuth.sln .
COPY JwtAuth.csproj .
RUN dotnet restore

# Copy the rest of the source code and build
COPY . .
RUN dotnet publish JwtAuth.csproj -c Release -o out

# Use the same SDK image for runtime
FROM mcr.microsoft.com/dotnet/sdk:9.0
WORKDIR /app

# Install PostgreSQL client tools
RUN apt-get update && \
    apt-get install -y postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Install EF Core tools
RUN dotnet tool install --global dotnet-ef
ENV PATH="${PATH}:/root/.dotnet/tools"

# Copy the entire source code
COPY . .

# Copy the published app
COPY --from=build /app/out .

# Create migrations directory if it doesn't exist
RUN mkdir -p Migrations

# Expose the port the app runs on
EXPOSE 8080

ENTRYPOINT ["dotnet", "JwtAuth.dll"]