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
    public class AuthService(UserDbContext context, IConfiguration configuration, ILogger<AuthService> logger) : IAuthService
    {
        // REGISTER
        public async Task<ServiceResult<User>> RegisterAsync(RegisterDto request)
        {
            try
            {
                // Check if the username already exists
                if (await context.Users.AnyAsync(u => u.Username == request.Username))
                {
                    return new ServiceResult<User> { IsSuccess = false, Message = AuthMessages.UsernameAlreadyExists };
                }

                // Proceed to create the user
                var user = new User();
                var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

                user.Username = request.Username;
                user.PasswordHash = hashedPassword;

                context.Users.Add(user);
                await context.SaveChangesAsync();

                return new ServiceResult<User> { IsSuccess = true, Data = user };
            }
            catch (DbUpdateException ex)
            {
                logger.LogError(ex, "Failed to register user {Username} due to database update error.", request.Username);
                return new ServiceResult<User> { IsSuccess = false, Message = "Registration failed due to a server error. Please try again later." };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while registering user {Username}.", request.Username);
                return new ServiceResult<User> { IsSuccess = false, Message = "Registration failed due to an unexpected error. Please try again later." };
            }
        }

        // LOGIN
        public async Task<ServiceResult<(TokenResponseDto TokenResponse, string RefreshToken)>> LoginAsync(LoginDto request)
        {
            try
            {
                // Check if the user exists
                var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
                if (user == null)
                {
                    return new ServiceResult<(TokenResponseDto, string)> { IsSuccess = false, Message = AuthMessages.InvalidCredentials };
                }


                if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
                {
                    return new ServiceResult<(TokenResponseDto, string)> { IsSuccess = false, Message = AuthMessages.InvalidCredentials };
                }

                // Proceed to generate the tokens
                var tokenResponse = CreateTokenResponse(user);
                var refreshToken = await GenerateAndSaveRefreshTokenAsync(user);

                return new ServiceResult<(TokenResponseDto, string)> { IsSuccess = true, Data = (tokenResponse, refreshToken) };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while logging in user {Username}.", request.Username);
                return new ServiceResult<(TokenResponseDto, string)> { IsSuccess = false, Message = "Login failed due to an unexpected error. Please try again later." };
            }
        }

        // REFRESH TOKEN
        public async Task<ServiceResult<TokenResponseDto>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // Check if the refresh token is valid
                var user = await ValidateRefreshTokenAsync(refreshToken);
                if (user == null)
                {
                    return new ServiceResult<TokenResponseDto> { IsSuccess = false, Message = AuthMessages.InvalidRefreshToken };
                }

                // Proceed to generate the new access token
                var tokenResponse = CreateTokenResponse(user);
                return new ServiceResult<TokenResponseDto> { IsSuccess = true, Data = tokenResponse };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while refreshing token for refreshToken {RefreshToken}.", refreshToken);
                return new ServiceResult<TokenResponseDto> { IsSuccess = false, Message = "Token refresh failed due to an unexpected error. Please try again later." };
            }
        }

        // LOGOUT
        public async Task<ServiceResult> LogoutAsync(string? refreshToken)
        {
            try
            {
                var user = await context.Users
                .FirstOrDefaultAsync(u => u.RefreshToken == refreshToken && u.RefreshTokenExpiryTime >= DateTime.UtcNow);

                if (user != null)
                {
                    // Token is valid, so invalidate it
                    user.RefreshToken = null;
                    user.RefreshTokenExpiryTime = null;
                    await context.SaveChangesAsync();
                }

                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LogoutSuccess };
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while logging out with refreshToken {RefreshToken}.", refreshToken);
                // Still return success, as the client session is terminated via cookie deletion
                return new ServiceResult { IsSuccess = true, Message = AuthMessages.LogoutSuccess };
            }
        }

        // HELPER METHODS BELOW
        private TokenResponseDto CreateTokenResponse(User user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user)
            };
        }

        public async Task<User?> GetUserByRefreshTokenAsync(string refreshToken)
        {
            return await ValidateRefreshTokenAsync(refreshToken);
        }

        private async Task<User?> ValidateRefreshTokenAsync(string refreshToken)
        {
            try
            {
                return await context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken
                                && u.RefreshTokenExpiryTime > DateTime.UtcNow);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while validating refresh token {RefreshToken}.", refreshToken);
                return null; // Return null to indicate failure
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
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
                await context.SaveChangesAsync();
                return refreshToken;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Unexpected error while generating and saving refresh token for user {UserId}.", user.Id);
                throw; // Rethrow to be handled by the caller (e.g., LoginAsync)
            }
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Role, user.Role)
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
    }
}
