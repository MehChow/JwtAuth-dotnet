using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Constants;
using JwtAuth.Exceptions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Google.Apis.Auth;

namespace JwtAuth.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration, ILogger<AuthService> logger, IHttpContextAccessor httpContextAccessor) : IAuthService
    {
        // REGISTER
        public async Task<ServiceResult<AuthInternalResponse>> RegisterAsync(RegisterDto request)
        {
            try
            {
                // Check if the email is already in used
                if (await context.Users.AnyAsync(u => u.Email == request.Email))
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.EMAIL_ALREADY_INUSED };
                }

                var user = new User
                {
                    Email = request.Email,
                    Username = ExtractUsernameFromEmail(request.Email),
                    PasswordHash = new PasswordHasher<User>().HashPassword(null!, request.Password)
                };

                context.Users.Add(user);
                await context.SaveChangesAsync();

                // Proceed to generate the tokens
                var accessToken = CreateToken(user);
                var refreshToken = await GenerateAndSaveRefreshTokenAsync(user);

                return new ServiceResult<AuthInternalResponse> { IsSuccess = true,
                    Data = new AuthInternalResponse
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        User = user
                    }
                };
            }
            catch (DbUpdateException ex)
            {
                logger.LogError(ex, "Failed to register user {Username} due to database update error.", request.Email);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Registration failed due to a server error. Please try again later." };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while registering user {Username}.", request.Email);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Registration failed due to an unexpected error. Please try again later." };
            }
        }

        // LOGIN
        public async Task<ServiceResult<AuthInternalResponse>> LoginAsync(LoginDto request)
        {
            try
            {
                // User not exist
                var user = await context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
                if (user == null)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.INVALID_CREDENTIALS };
                }

                // Password not match
                if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, request.Password) == PasswordVerificationResult.Failed)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.INVALID_CREDENTIALS };
                }

                //// For invalidate all existing refresh tokens for the user, uncomment when needed
                //var existingTokens = await context.RefreshTokens
                //    .Where(t => t.UserId == user.Id && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
                //    .ToListAsync();
                //foreach (var token in existingTokens)
                //{
                //    token.IsRevoked = true;
                //}
                //await context.SaveChangesAsync();

                // Proceed to generate the tokens
                var accessToken = CreateToken(user);
                var refreshToken = await GenerateAndSaveRefreshTokenAsync(user);

                return new ServiceResult<AuthInternalResponse> { IsSuccess = true,
                    Data = new AuthInternalResponse
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        User = user
                    }
                };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while logging in email {Email}.", request.Email);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Login failed due to an unexpected error. Please try again later." };
            }
        }

        // GET USER INFO
        public async Task<ServiceResult<User>> GetUserInfoAsync()
        {
            try
            {
                var userId = httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId) || !Guid.TryParse(userId, out var userIdGuid))
                {
                    return new ServiceResult<User> { IsSuccess = false, Message = AuthMessages.INVALID_USER_ID_FORMAT };
                }

                var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userIdGuid);
                if (user == null)
                {
                    return new ServiceResult<User> { IsSuccess = false, Message = AuthMessages.USER_NOT_FOUND };
                }

                return new ServiceResult<User> { IsSuccess = true, Data = user };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while retrieving user info for user ID {UserId}.", httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                return new ServiceResult<User> { IsSuccess = false, Message = "Failed to retrieve user info due to an unexpected error." };
            }
        }

        // LOGOUT
        public async Task<ServiceResult> LogoutAsync(string? refreshToken, string? accessToken)
        {
            try
            {
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    var hashedToken = HashToken(refreshToken);
                    var tokenRecord = await context.RefreshTokens
                        .FirstOrDefaultAsync(t => t.TokenHash == hashedToken && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);
                    if (tokenRecord != null)
                    {
                        tokenRecord.IsRevoked = true;
                        await context.SaveChangesAsync();
                    }
                }

                if (!string.IsNullOrEmpty(accessToken))
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var jwtToken = tokenHandler.ReadJwtToken(accessToken);
                    var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
                    if (!string.IsNullOrEmpty(jti))
                    {
                        context.BlacklistedTokens.Add(new BlacklistedToken
                        {
                            Jti = jti,
                            ExpiryDate = DateTime.UtcNow.AddMinutes(15)
                        });
                        await context.SaveChangesAsync();
                    }
                }

                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LOGOUT_SUCCESS };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while logging out.");
                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LOGOUT_SUCCESS };
            }
        }

        // REFRESH TOKEN
        public async Task<ServiceResult<AuthInternalResponse>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                var hashedToken = HashToken(refreshToken);
                var tokenRecord = await context.RefreshTokens
                    .FirstOrDefaultAsync(t => t.TokenHash == hashedToken && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);
                if (tokenRecord == null)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.INVALID_REFRESH_TOKEN };
                }

                // Mark old token as revoked
                tokenRecord.IsRevoked = true;
                await context.SaveChangesAsync();

                // Get user
                var user = await context.Users.FindAsync(tokenRecord.UserId);
                if (user == null)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.USER_NOT_FOUND };
                }

                // Generate new tokens
                var accessToken = CreateToken(user);
                var newRefreshToken = await GenerateAndSaveRefreshTokenAsync(user);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = true, Data = new AuthInternalResponse { AccessToken = accessToken, RefreshToken = newRefreshToken } };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while refreshing token.");
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Token refresh failed due to an unexpected error." };
            }
        }

        // GOOGLE OAUTH
        public async Task<ServiceResult<AuthInternalResponse>> GoogleLoginAsync(string idToken)
        {
            try
            {
                // Validate ID token
                var payload = await ValidateGoogleIdTokenAsync(idToken);

                // Find or create user
                var user = await FindOrCreateGoogleUserAsync(payload);

                // Generate tokens
                var accessToken = CreateToken(user);
                var refreshToken = await GenerateAndSaveRefreshTokenAsync(user);

                return new ServiceResult<AuthInternalResponse>
                {
                    IsSuccess = true,
                    Data = new AuthInternalResponse
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        User = user
                    }
                };
            }
            catch (InvalidJwtException ex)
            {
                logger.LogError(ex, "Invalid Google ID token");
                return new ServiceResult<AuthInternalResponse>
                {
                    IsSuccess = false,
                    Message = AuthMessages.INVALID_GOOGLE_CRED
                };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during Google login");
                return new ServiceResult<AuthInternalResponse>
                {
                    IsSuccess = false,
                    Message = AuthMessages.GOOGLE_LOGIN_FAILED
                };
            }
        }

        public async Task<GoogleJsonWebSignature.Payload> ValidateGoogleIdTokenAsync(string idToken)
        {
            return await GoogleJsonWebSignature.ValidateAsync(idToken, new()
            {
                Audience = [configuration["Authentication:Google:ClientId"]
                ?? throw new ConfigMissingException("Google:ClientId")],
                IssuedAtClockTolerance = TimeSpan.FromMinutes(5),
            });
        }

        public async Task<User> FindOrCreateGoogleUserAsync(GoogleJsonWebSignature.Payload payload)
        {
            if (string.IsNullOrEmpty(payload.Email))
                throw new AuthException("Google ID token missing email");

            // Try to find by Google ID first
            var user = await context.Users
                .FirstOrDefaultAsync(u => u.Provider == "Google" && u.ProviderId == payload.Subject);

            if (user == null)
            {
                // Then try by email
                user = await context.Users
                    .FirstOrDefaultAsync(u => u.Email == payload.Email);

                if (user != null)
                {
                    // Link existing account with Google
                    user.Provider = "Google";
                    user.ProviderId = payload.Subject;
                    await context.SaveChangesAsync();
                }
            }

            if (user == null)
            {
                // Create new user
                user = new User
                {
                    Username = payload.Name,
                    Email = payload.Email,
                    Provider = "Google",
                    ProviderId = payload.Subject,
                    PasswordHash = null // No password for Google users
                };

                context.Users.Add(user);
                await context.SaveChangesAsync();
            }

            return user;
        }

        // HELPER METHODS BELOW
        public async Task<User?> GetUserByRefreshTokenAsync(string refreshToken)
        {
            return await ValidateRefreshTokenAsync(refreshToken);
        }

        private async Task<User?> ValidateRefreshTokenAsync(string refreshToken)
        {
            try
            {
                var hashedToken = HashToken(refreshToken);
                var tokenRecord = await context.RefreshTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == hashedToken
                                    && !t.IsRevoked
                                    && t.ExpiresAt > DateTime.UtcNow);
                return tokenRecord?.User;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while validating refresh token.");
                return null;
            }
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            try
            {
                var refreshToken = GenerateRefreshToken();
                var tokenRecord = new RefreshToken
                {
                    UserId = user.Id,
                    TokenHash = HashToken(refreshToken),
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    IsRevoked = false
                };
                context.RefreshTokens.Add(tokenRecord);
                await context.SaveChangesAsync();
                return refreshToken;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while generating and saving refresh token for user {UserId}.", user.Id);
                throw;
            }
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Role, user.Role),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Add jti for blacklisting
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        private static string HashToken(string token)
        {
            var bytes = Encoding.UTF8.GetBytes(token);
            var hash = SHA256.HashData(bytes);
            return Convert.ToBase64String(hash);
        }

        private static string ExtractUsernameFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("Email cannot be null or empty.", nameof(email));
            var atIndex = email.IndexOf('@');
            return atIndex > 0 ? email[..atIndex] : email;
        }
    }
}
