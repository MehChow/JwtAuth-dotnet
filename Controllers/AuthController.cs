using Microsoft.AspNetCore.Mvc;
using JwtAuth.Entities;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService, IConfiguration configuration) : ControllerBase
    {
        private readonly bool isProduction = configuration.GetValue<bool>("AppSettings:IsProduction");

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(RegisterDto request)
        {
            var result = await authService.RegisterAsync(request);
            if (!result.IsSuccess)
            {
                // User already exists
                return BadRequest(result.Message);
            }

            // Return the newly created user
            return Ok(result.Data);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(LoginDto request)
        {
            var result = await authService.LoginAsync(request);
            if (!result.IsSuccess)
            {
                // Invalid credentials
                return BadRequest(result.Message);
            }

            // Set the accessToken and refreshToken as HTTP-only cookies
            var (tokenResponse, refreshToken) = result.Data;
            Response.Cookies.Append("accessToken", tokenResponse.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Return the access token
            return Ok(tokenResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                // No refresh token provided
                return BadRequest(AuthMessages.NoRefreshTokenProvided);
            }

            var result = await authService.RefreshTokenAsync(refreshToken);
            if (!result.IsSuccess)
            {
                // Invalid refresh token
                return Unauthorized(result.Message);
            }

            var user = await authService.GetUserByRefreshTokenAsync(refreshToken);
            var newRefreshToken = await authService.GenerateAndSaveRefreshTokenAsync(user!);

            // Set the accessToken and refreshToken as HTTP-only cookies
            Response.Cookies.Append("accessToken", result.Data.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15)
            });

            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            // Return the new access token
            return Ok(result.Data);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            // Call the service even if refreshToken is null/empty, as it will handle it gracefully
            var result = await authService.LogoutAsync(refreshToken);

            // Clear cookies regardless of token state
            Response.Cookies.Delete("accessToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict
            });
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict
            });

            return Ok(result.Message);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticationOnlyEndpoint()
        {
            return Ok("You are authenticated!!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin!!");
        }
    }
}
