using Microsoft.AspNetCore.Mvc;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuth.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService, IConfiguration configuration, ILogger<AuthController> _logger) : ControllerBase
    {
        private readonly bool isProduction = configuration.GetValue<bool>("AppSettings:IsProduction");

        [HttpPost("register")]
        public async Task<ActionResult<UserResponseDto>> Register(RegisterDto request)
        {
            var result = await authService.RegisterAsync(request);
            if (!result.IsSuccess)
            {
                // Username already exists
                if (result.Message == AuthMessages.USERNAME_ALREADY_EXISTS)
                {
                    return Conflict(result.Message);
                }

                // Db or server error
                return StatusCode(500, result.Message);
            }

            // Set the accessToken and refreshToken as HTTP-only cookies
            var requestResponse = result.Data;
            Response.Cookies.Append("accessToken", requestResponse.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15),
            });
            Response.Cookies.Append("refreshToken", requestResponse.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),
            });

            // Only return the neccessary info
            var userResponse = new UserResponseDto
            {
                Id = requestResponse.User.Id,
                Username = requestResponse.User.Username,
                Role = requestResponse.User.Role
            };

            // Return the access token and the user
            return Ok(userResponse);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserResponseDto>> Login(LoginDto request)
        {
            var result = await authService.LoginAsync(request);
            if (!result.IsSuccess)
            {
                // Invalid credentials
                if (result.Message == AuthMessages.INVALID_CREDENTIALS)
                {
                    return Unauthorized(result.Message);
                }

                // Server error
                return StatusCode(500, result.Message);
            }

            // Set the accessToken and refreshToken as HTTP-only cookies
            var loginResponse  = result.Data!;

            Response.Cookies.Append("accessToken", loginResponse.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15),
            });
            Response.Cookies.Append("refreshToken", loginResponse.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),
            });

            // Only return the neccessary info
            var userResponse = new UserResponseDto
            {
                Id = loginResponse.User.Id,
                Username = loginResponse.User.Username,
                Role = loginResponse.User.Role
            };

            // Return the access token and the user
            return Ok(userResponse);
        }

        [Authorize]
        [HttpGet("get-userinfo")]
        public async Task<ActionResult<UserResponseDto>> GetUserInfo()
        {
            var result = await authService.GetUserInfoAsync();
            if (!result.IsSuccess)
            {
                if (result.Message == AuthMessages.INVALID_USER_ID_FORMAT)
                {
                    return Unauthorized(result.Message);
                }
                if (result.Message == AuthMessages.USER_NOT_FOUND)
                {
                    return NotFound(result.Message);
                }
                return StatusCode(500, result.Message);
            }

            var user = result.Data!;

            // Only return necessary info
            var userResponse = new UserResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                Role = user.Role
            };

            return Ok(userResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                // No refresh token provided
                return BadRequest(AuthMessages.NO_REFRESH_TOKEN_PROVIDED);
            }

            var result = await authService.RefreshTokenAsync(refreshToken);
            if (!result.IsSuccess)
            {
                // Invalid refresh token
                if (result.Message == AuthMessages.INVALID_REFRESH_TOKEN)
                {
                    return Unauthorized(result.Message);
                }

                // Server error
                return StatusCode(500, result.Message);
            }

            var response = result.Data!;

            // Set the accessToken and refreshToken as HTTP-only cookies
            Response.Cookies.Append("accessToken", response.AccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(15),
            });

            Response.Cookies.Append("refreshToken", response.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(7),
            });

            // Return the new access token
            _logger.LogInformation("Set-Cookie headers: {Headers}", string.Join(", ", Response.Headers["Set-Cookie"].ToArray()));
            return Ok();
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var accessToken = Request.Cookies["accessToken"];

            var result = await authService.LogoutAsync(refreshToken, accessToken);

            // Clear cookies regardless of token state
            Response.Cookies.Delete("accessToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
            });
            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = isProduction, // Use true in production with HTTPS
                SameSite = SameSiteMode.Strict,
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
