using Microsoft.AspNetCore.Http;

namespace JwtAuth.Services
{
    public class CookieService : ICookieService
    {
        public void SetAuthCookies(HttpResponse response, string accessToken, string refreshToken, bool isProduction)
        {
            response.Cookies.Append("accessToken", accessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15),
            });
            response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),
            });
        }

        public void ClearAuthCookies(HttpResponse response, bool isProduction)
        {
            response.Cookies.Delete("accessToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction,
                SameSite = SameSiteMode.Strict,
            });
            response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction,
                SameSite = SameSiteMode.Strict,
            });
        }
    }
} 