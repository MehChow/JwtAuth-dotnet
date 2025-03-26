using JwtAuth.Entities;
using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<(TokenResponseDto? TokenResponse, string? RefreshToken)> LoginAsync(UserDto request);
        Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken);
        Task<User?> GetUserByRefreshTokenAsync(string refreshToken);
        Task<string> GenerateAndSaveRefreshTokenAsync(User user);
        Task<bool> LogoutAsync(string refreshToken);
    }
}
