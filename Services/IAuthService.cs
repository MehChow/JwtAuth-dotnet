using JwtAuth.Entities;
using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<ServiceResult<(TokenResponseDto TokenResponse, string RefreshToken, User User)>> RegisterAsync(RegisterDto request);
        Task<ServiceResult<(TokenResponseDto TokenResponse, string RefreshToken, User User)>> LoginAsync(LoginDto request);
        Task<ServiceResult<User>> GetUserInfoAsync();
        Task<ServiceResult<TokenResponseDto>> RefreshTokenAsync(string refreshToken);
        Task<ServiceResult> LogoutAsync(string? refreshToken);
        Task<User?> GetUserByRefreshTokenAsync(string refreshToken);
        Task<string> GenerateAndSaveRefreshTokenAsync(User user);
    }
}
