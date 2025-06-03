using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text;
using JwtAuth.Data;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();

// Add CORS services
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowNextjsApp", policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>()
            ?? new[] { "http://localhost:3000" };

        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddDbContext<UserDbContext>(options =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
    if (string.IsNullOrEmpty(connectionString))
    {
        throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
    }
    options.UseSqlServer(connectionString);
});

builder.Services.AddLogging();
builder.Services.AddHttpContextAccessor();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    var token = builder.Configuration["AppSettings:Token"];
    var issuer = builder.Configuration["AppSettings:Issuer"];
    var audience = builder.Configuration["AppSettings:Audience"];

    if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(audience))
    {
        throw new InvalidOperationException("JWT configuration is missing. Please check your environment variables.");
    }

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(token)),
        ClockSkew = TimeSpan.Zero
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var accessToken = context.Request.Cookies["accessToken"];
            if (!string.IsNullOrEmpty(accessToken))
            {
                context.Token = accessToken;
            }
            return Task.CompletedTask;
        },

        OnTokenValidated = async context =>
        {
            var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (!string.IsNullOrEmpty(jti))
            {
                var dbContext = context.HttpContext.RequestServices.GetRequiredService<UserDbContext>();
                var isBlacklisted = await dbContext.BlacklistedTokens
                    .AnyAsync(t => t.Jti == jti && t.ExpiryDate > DateTime.UtcNow);
                if (isBlacklisted)
                {
                    context.Fail("Token has been invalidated.");
                }
            }
        },

        OnChallenge = async context =>
        {
            // Prevent the default 401 response
            context.HandleResponse();

            // Set the response status code and content type
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";

            // Create a ServiceResult response
            string errorMessage = "Authentication failed: Invalid or missing access token.";
            if (context.AuthenticateFailure != null)
            {
                errorMessage = context.AuthenticateFailure switch
                {
                    SecurityTokenExpiredException => "Unauthorized: Token expired.",
                    SecurityTokenInvalidSignatureException => "Unauthorized: Invalid token signature.",
                    _ => string.IsNullOrEmpty(context.Request.Cookies["accessToken"])
                        ? "Unauthorized: Missing token."
                        : "Unauthorized: Invalid token."
                };
            }

            // Write the response
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(errorMessage));
        }
    };
});

// Dependency Injection
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ICookieService, CookieService>();

// Add HttpClient for Google Auth
builder.Services.AddHttpClient(); // This registers IHttpClientFactory
builder.Services.AddScoped<IOAuthService, OAuthService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
} else
{
    app.UseHttpsRedirection();
}

// Enable CORS middleware
app.UseCors("AllowNextjsApp");

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
