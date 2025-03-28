using System.Text;
using JwtAuth.Data;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add CORS services
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowNextjsApp", policy =>
    {
        policy.WithOrigins("http://localhost:3000") // Your Next.js app URL
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("UserDatabase")));
builder.Services.AddLogging();
builder.Services.AddHttpContextAccessor();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["AppSettings:Issuer"],
        ValidAudience = builder.Configuration["AppSettings:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["AppSettings:Token"]!)),
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
                if (context.AuthenticateFailure is SecurityTokenExpiredException)
                {
                    errorMessage = "Authentication failed: Access token has expired.";
                }
                else if (context.AuthenticateFailure is SecurityTokenInvalidSignatureException)
                {
                    errorMessage = "Authentication failed: Invalid token signature.";
                }
                else if (string.IsNullOrEmpty(context.Request.Cookies["accessToken"]))
                {
                    errorMessage = "Authentication failed: Access token is missing.";
                }
            }

            // Write the response
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(errorMessage));
        }
    };
});

// Dependency Injection
builder.Services.AddScoped<IAuthService, AuthService>();

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
