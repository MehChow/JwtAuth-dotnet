using JwtAuth.Entities;
using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<ServiceResult<AuthInternalResponse>> RegisterAsync(RegisterDto request);
        Task<ServiceResult<AuthInternalResponse>> LoginAsync(LoginDto request);
        Task<ServiceResult<User>> GetUserInfoAsync();
        Task<ServiceResult<AuthInternalResponse>> RefreshTokenAsync(string refreshToken);
        Task<ServiceResult> LogoutAsync(string? refreshToken, string? accessToken);
        Task<User?> GetUserByRefreshTokenAsync(string refreshToken);
        Task<string> GenerateAndSaveRefreshTokenAsync(User user);
    }
}
