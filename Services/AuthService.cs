using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration, ILogger<AuthService> logger, IHttpContextAccessor httpContextAccessor) : IAuthService
    {
        // REGISTER
        public async Task<ServiceResult<AuthInternalResponse>> RegisterAsync(RegisterDto request)
        {
            try
            {
                // Check if the username already exists
                if (await context.Users.AnyAsync(u => u.Username == request.Username))
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.UsernameAlreadyExists };
                }

                var user = new User
                {
                    Username = request.Username,
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
                logger.LogError(ex, "Failed to register user {Username} due to database update error.", request.Username);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Registration failed due to a server error. Please try again later." };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while registering user {Username}.", request.Username);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Registration failed due to an unexpected error. Please try again later." };
            }
        }

        // LOGIN
        public async Task<ServiceResult<AuthInternalResponse>> LoginAsync(LoginDto request)
        {
            try
            {
                // User not exist
                var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
                if (user == null)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.InvalidCredentials };
                }

                // Password not match
                if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, request.Password) == PasswordVerificationResult.Failed)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.InvalidCredentials };
                }

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
                logger.LogError(ex, "Unexpected error while logging in user {Username}.", request.Username);
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
                    return new ServiceResult<User> { IsSuccess = false, Message = AuthMessages.InvalidUserIdFormat };
                }

                var user = await context.Users.FirstOrDefaultAsync(u => u.Id == userIdGuid);
                if (user == null)
                {
                    return new ServiceResult<User> { IsSuccess = false, Message = AuthMessages.UserNotFound };
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

                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LogoutSuccess };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while logging out.");
                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LogoutSuccess };
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
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.InvalidRefreshToken };
                }

                // Mark old token as revoked
                tokenRecord.IsRevoked = true;
                await context.SaveChangesAsync();

                // Get user
                var user = await context.Users.FindAsync(tokenRecord.UserId);
                if (user == null)
                {
                    return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = AuthMessages.InvalidRefreshToken };
                }

                // Generate new tokens
                var accessToken = CreateToken(user);
                var newRefreshToken = await GenerateAndSaveRefreshTokenAsync(user);
                return new ServiceResult<AuthInternalResponse> { IsSuccess = true, Data = { AccessToken = accessToken, RefreshToken = newRefreshToken } };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while refreshing token.");
                return new ServiceResult<AuthInternalResponse> { IsSuccess = false, Message = "Token refresh failed due to an unexpected error." };
            }
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
    }
}
