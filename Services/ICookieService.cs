using Microsoft.AspNetCore.Http;

namespace JwtAuth.Services
{
    public interface ICookieService
    {
        void SetAuthCookies(HttpResponse response, string accessToken, string refreshToken, bool isProduction);
        void ClearAuthCookies(HttpResponse response, bool isProduction);
    }
} 