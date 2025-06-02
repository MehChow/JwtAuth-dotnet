using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IOAuthService
    {
        Task<GoogleTokenResponse> ExchangeCodeForTokensAsync(string authorizationCode);
    }
}
